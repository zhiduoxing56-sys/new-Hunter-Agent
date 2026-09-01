"""Translate Kong's preserved outputs into Protocol v1 result components.

The Kong CLI is treated as a fixed professional backend. This module is the
Hunter-side reverse-result ingress:

``Kong analysis.json -> decode/normalize -> schema check -> semantic extraction
-> Evidence/Finding proposal -> categorized diagnostics -> AgentResult``

Rules:

- only deterministic decoding/normalization and provenance are added; nothing is
  guessed (no benchmark function names, no backdoor conclusions, no fabricated
  names);
- every per-record parse problem is categorized (not a single ``errors`` total);
- non-critical records are skipped with a diagnostic; critical problems (e.g. a
  malformed function array) degrade the result so the adapter reports
  PARTIAL/BLOCKED instead of silently succeeding;
- every Finding carries provenance back to the Kong analysis artifact.
"""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pentestgpt_agent.protocol import Evidence, Finding

SUPPORTED_RECORD_KINDS = frozenset({"function", "symbol", ""})
MAX_DIAGNOSTIC_SAMPLES = 3


def load_analysis(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError("Kong analysis.json must contain a JSON object")
    for key in ("binary", "stats", "functions"):
        if key not in value:
            raise ValueError(f"Kong analysis.json is missing {key!r}")
    if not isinstance(value["binary"], dict) or not isinstance(value["stats"], dict):
        raise ValueError("Kong binary and stats sections must be JSON objects")
    if not isinstance(value["functions"], list):
        raise ValueError("Kong functions section must be a JSON array")
    return value


def analysis_evidence(artifact_id: str) -> Evidence:
    return Evidence(
        evidence_id="kong-analysis-evidence",
        type="backend_analysis",
        source="kong",
        description="Kong's original structured reverse-engineering output.",
        artifact_ref=artifact_id,
    )


def parse_info_output(output: str) -> dict[str, str | int]:
    parsed: dict[str, str | int] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        normalized = key.lower().replace(" ", "_")
        if normalized in {"functions", "word_size"}:
            digits = "".join(character for character in value if character.isdigit())
            parsed[normalized] = int(digits) if digits else value
        elif normalized in {"binary", "path", "arch", "format", "endianness", "compiler"}:
            parsed[normalized] = value
    if "binary" not in parsed or "functions" not in parsed:
        raise ValueError("Kong info output is missing required binary metadata")
    return parsed


@dataclass
class ReverseDiagnostics:
    """Categorized per-record parse diagnostics (not a single errors total)."""

    total_records: int = 0
    parsed_records: int = 0
    named_records: int = 0
    skipped_records: int = 0
    error_categories: dict[str, int] = field(default_factory=dict)
    error_samples: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def record_error(self, category: str, sample: dict[str, Any]) -> None:
        self.error_categories[category] = self.error_categories.get(category, 0) + 1
        samples = self.error_samples.setdefault(category, [])
        if len(samples) < MAX_DIAGNOSTIC_SAMPLES:
            samples.append(sample)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_records": self.total_records,
            "parsed_records": self.parsed_records,
            "named_records": self.named_records,
            "skipped_records": self.skipped_records,
            "error_categories": dict(sorted(self.error_categories.items())),
            "error_samples": {
                category: list(samples)
                for category, samples in sorted(self.error_samples.items())
            },
        }


@dataclass(frozen=True)
class ReverseAnalysisResult:
    """Structured, provenance-carrying extraction of one Kong analysis."""

    stats: dict[str, Any]
    findings: tuple[Finding, ...]
    diagnostics: ReverseDiagnostics
    semantic_adequate: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "stats": dict(self.stats),
            "finding_count": len(self.findings),
            "diagnostics": self.diagnostics.to_dict(),
            "semantic_adequate": self.semantic_adequate,
        }


def findings_from_analysis(
    value: dict[str, Any],
    *,
    evidence_id: str,
    artifact_sha256: str | None = None,
) -> tuple[Finding, ...]:
    """Extract provenance-carrying Findings, keeping the legacy signature."""
    return parse_reverse_analysis(
        value,
        evidence_id=evidence_id,
        artifact_sha256=artifact_sha256,
    ).findings


def parse_reverse_analysis(
    value: dict[str, Any],
    *,
    evidence_id: str,
    artifact_sha256: str | None = None,
) -> ReverseAnalysisResult:
    """Decode one Kong analysis object into findings + categorized diagnostics.

    Per-record problems are categorized and sampled. Ignorable records
    (malformed items, duplicates, unsupported kinds) are skipped with a
    diagnostic; records that still carry a usable address or original name are
    kept as unnamed-symbol evidence with a diagnostic, never fabricated.
    """
    load_analysis_from_value(value)
    stats = dict(value.get("stats", {}))
    diagnostics = ReverseDiagnostics()
    seen_addresses: Counter = Counter()
    findings: list[Finding] = []
    functions = value.get("functions", [])
    diagnostics.total_records = len(functions)
    for index, item in enumerate(functions):
        finding = _extract_record(
            item,
            index=index,
            evidence_id=evidence_id,
            artifact_sha256=artifact_sha256,
            seen_addresses=seen_addresses,
            diagnostics=diagnostics,
        )
        if finding is not None:
            findings.append(finding)
            diagnostics.parsed_records += 1
            if finding.metadata.get("named"):
                diagnostics.named_records += 1
        else:
            diagnostics.skipped_records += 1
    named = int(stats.get("named", 0) or 0)
    semantic_adequate = named > 0 or diagnostics.named_records > 0
    return ReverseAnalysisResult(
        stats=stats,
        findings=tuple(findings),
        diagnostics=diagnostics,
        semantic_adequate=semantic_adequate,
    )


def _extract_record(
    item: Any,
    *,
    index: int,
    evidence_id: str,
    artifact_sha256: str | None,
    seen_addresses: Counter,
    diagnostics: ReverseDiagnostics,
) -> Finding | None:
    if not isinstance(item, dict):
        diagnostics.record_error("malformed_item", {"record_index": index})
        return None
    kind = str(item.get("kind") or "")
    if kind not in SUPPORTED_RECORD_KINDS:
        diagnostics.record_error(
            "unsupported_record",
            {"record_index": index, "kind": kind, "address": item.get("address")},
        )
        return None
    address_value = item.get("address")
    address = _parse_address(address_value)
    if address_value is not None and address is None:
        diagnostics.record_error(
            "invalid_address",
            {"record_index": index, "address": address_value, "original_name": item.get("original_name")},
        )
    original_name = _safe_str(item.get("original_name"))
    name = _safe_str(item.get("name"))
    if not name and not original_name:
        diagnostics.record_error(
            "missing_name",
            {"record_index": index, "address": address_value},
        )
        original_name = original_name or f"record-{index}"
    if address is not None:
        seen_addresses[address] += 1
        if seen_addresses[address] > 1:
            diagnostics.record_error(
                "duplicate_record",
                {"record_index": index, "address": address_value, "original_name": original_name},
            )
            return None
    confidence = _safe_int(item.get("confidence"))
    if confidence is not None and not 0 <= confidence <= 100:
        diagnostics.record_error(
            "invalid_confidence",
            {"record_index": index, "address": address_value, "confidence": item.get("confidence")},
        )
    display_name = name or original_name
    display_address = _format_address(address, address_value)
    title = f"{display_name} ({display_address})"
    comments = _safe_str(item.get("comments"))
    reasoning = _safe_str(item.get("reasoning"))
    description = comments or reasoning or f"Kong analyzed function {display_name} at {display_address}."
    metadata = {
        "address": display_address,
        "original_name": original_name,
        "name": name,
        "signature": _safe_str(item.get("signature")),
        "confidence": confidence if confidence is not None else 0,
        "classification": _safe_str(item.get("classification")),
        "obfuscation_techniques": item.get("obfuscation_techniques", []),
        "source": "kong_analysis",
        "record_index": index,
        "artifact_sha256": artifact_sha256 or "",
        "named": bool(name),
    }
    return Finding(
        finding_id=f"kong-function-{index + 1}",
        type="reverse_engineered_function",
        title=title,
        description=description,
        evidence_refs=(evidence_id,),
        metadata=metadata,
    )


def _parse_address(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        text = value.strip()
        if text.lower().startswith("0x"):
            text = text[2:]
        try:
            return int(text, 16)
        except ValueError:
            try:
                return int(value)
            except ValueError:
                return None
    return None


def _format_address(address: int | None, raw: Any) -> str:
    if address is not None:
        return f"0x{address:08x}"
    if isinstance(raw, str) and raw.strip():
        return raw.strip()
    return "unknown"


def _safe_str(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return str(value)


def _safe_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


def analysis_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_analysis_from_value(value: dict[str, Any]) -> None:
    for key in ("binary", "stats", "functions"):
        if key not in value:
            raise ValueError(f"Kong analysis.json is missing {key!r}")
    if not isinstance(value["binary"], dict) or not isinstance(value["stats"], dict):
        raise ValueError("Kong binary and stats sections must be JSON objects")
    if not isinstance(value["functions"], list):
        raise ValueError("Kong functions section must be a JSON array")

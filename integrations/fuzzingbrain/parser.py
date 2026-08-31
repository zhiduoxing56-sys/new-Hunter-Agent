"""Convert FuzzingBrain filesystem output into the frozen Hunter protocol."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from pentestgpt_agent.protocol import ErrorCategory, ExecutionStatus


@dataclass(frozen=True)
class ParsedOutcome:
    status: ExecutionStatus
    summary: str
    error_category: ErrorCategory | None = None
    error_code: str | None = None
    retryable: bool = False
    task_document: dict[str, Any] | None = None
    pov_documents: tuple[dict[str, Any], ...] = ()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def iter_result_files(results: Path) -> Iterable[tuple[str, Path]]:
    """Yield supported evidence without following links outside results."""
    root = results.resolve()
    if not root.is_dir():
        return
    for path in sorted(root.rglob("*")):
        resolved = path.resolve()
        if path.is_symlink() or not resolved.is_relative_to(root) or not resolved.is_file():
            continue
        relative = resolved.relative_to(root).as_posix().lower()
        if "/povs/" in f"/{relative}" or relative.startswith("povs/"):
            yield "trigger_sample", resolved
        elif "/crashes/" in f"/{relative}" or relative.startswith("crashes/"):
            yield "crash_bundle", resolved
        elif "/patches/" in f"/{relative}" or relative.startswith("patches/"):
            yield "patch", resolved
        elif relative.endswith(("report.json", "summary.json")):
            yield "vulnerability_bundle", resolved
        elif relative.endswith((".log", ".txt")):
            yield "backend_log", resolved


def parse_outcome(
    *, returncode: int, stderr: str, report: dict[str, Any] | None = None,
    task_document: dict[str, Any] | None = None,
    pov_documents: Iterable[dict[str, Any]] = (), cancelled: bool = False,
) -> ParsedOutcome:
    text = stderr.lower()
    backend_status = str((task_document or report or {}).get("status", "")).lower()
    povs = tuple(pov_documents)
    successful_povs = [item for item in povs if item.get("is_successful", True)]
    if cancelled or backend_status == "cancelled":
        return ParsedOutcome(ExecutionStatus.CANCELLED, "FuzzingBrain was cancelled by the user.", task_document=task_document, pov_documents=povs)
    mappings = (
        (("deepseek", "api key", "authentication", "rate limit", "429"), ErrorCategory.BACKEND_ERROR, "FUZZINGBRAIN_LLM_FAILURE", True),
        (("docker", "daemon"), ErrorCategory.ENVIRONMENT_ERROR, "FUZZINGBRAIN_DOCKER_FAILURE", True),
        (("mongodb", "mongo", "redis"), ErrorCategory.ENVIRONMENT_ERROR, "FUZZINGBRAIN_SERVICE_FAILURE", True),
        (("build failed", "compilation", "compiler error"), ErrorCategory.TOOL_ERROR, "FUZZINGBRAIN_BUILD_FAILURE", False),
        (("timeout", "timed out"), ErrorCategory.TIMEOUT, "FUZZINGBRAIN_FUZZER_TIMEOUT", True),
    )
    if returncode != 0 or backend_status in {"failed", "error"}:
        for needles, category, code, retryable in mappings:
            if any(needle in text for needle in needles):
                return ParsedOutcome(ExecutionStatus.FAILED, "FuzzingBrain failed during backend execution.", category, code, retryable, task_document, povs)
        return ParsedOutcome(ExecutionStatus.FAILED, "FuzzingBrain failed during backend execution.", ErrorCategory.BACKEND_ERROR, "FUZZINGBRAIN_BACKEND_FAILURE", False, task_document, povs)
    if successful_povs:
        return ParsedOutcome(ExecutionStatus.SUCCESS, f"FuzzingBrain produced {len(successful_povs)} reproducible vulnerability trigger(s).", task_document=task_document, pov_documents=povs)
    if backend_status in {"partial", "running"}:
        return ParsedOutcome(ExecutionStatus.PARTIAL, "FuzzingBrain produced partial results without a verified trigger.", task_document=task_document, pov_documents=povs)
    return ParsedOutcome(ExecutionStatus.SUCCESS, "FuzzingBrain completed without finding a reproducible vulnerability.", task_document=task_document, pov_documents=povs)


def safe_identifier(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-.")
    return value[:96] or "artifact"

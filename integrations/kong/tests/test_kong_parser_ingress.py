"""Reverse result ingress tests (Phase 3D-B).

The Kong CLI is a fixed professional backend. Hunter's parser must:

- consume Kong's real analysis.json deterministically;
- categorize every per-record parse error (never a single ``errors`` total);
- skip+diagnose ignorable records and degrade honestly on critical problems;
- never fabricate names or backdoor conclusions;
- carry provenance (source artifact SHA, address, record index) on every finding;
- report PARTIAL when Kong's process succeeded but semantic output is
  insufficient, and FAILED when the process failed;
- never let a parser error become a global success (completion truth still gates).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from integrations.kong.parser import (
    parse_reverse_analysis,
)
from pentestgpt_agent.protocol import (
    ExecutionStatus,
    RunLayout,
    TaskSpec,
)
from integrations.kong.adapter import KongAdapter

FIXTURES = Path(__file__).resolve().parent / "fixtures"


def _analysis(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _result(value: dict, *, sha: str = "a" * 64) -> dict:
    parsed = parse_reverse_analysis(value, evidence_id="kong-analysis-evidence", artifact_sha256=sha)
    return {
        "stats": parsed.stats,
        "findings": parsed.findings,
        "diagnostics": parsed.diagnostics,
        "adequate": parsed.semantic_adequate,
    }


def _named_item(name: str = "add_values", address: str = "0x00401000") -> dict:
    return {
        "address": address,
        "original_name": "FUN_00401000",
        "name": name,
        "signature": "int add_values(int, int)",
        "confidence": 90,
        "classification": "math",
        "comments": "Adds two values.",
    }


def _base_stats(**overrides: int) -> dict:
    stats = {
        "total_functions": 478,
        "analyzed": 2,
        "named": 0,
        "renamed": 0,
        "confirmed": 0,
        "errors": 445,
        "skipped": 31,
        "llm_calls": 2,
    }
    stats.update(overrides)
    return stats


# ---------------------------------------------------------------------------
# frozen fixture replay
# ---------------------------------------------------------------------------


def test_frozen_liblzma_errors445_named0_replay_is_partial_and_categorized() -> None:
    value = _analysis(FIXTURES / "phase3d_b_liblzma_analysis.json")
    assert value["stats"]["errors"] == 445
    assert value["stats"]["named"] == 0

    parsed = parse_reverse_analysis(value, evidence_id="kong-analysis-evidence")

    assert parsed.semantic_adequate is False
    assert len(parsed.findings) == 2
    # both frozen records are unnamed but carry their original symbols
    assert {f.metadata["original_name"] for f in parsed.findings} >= {
        "FUN_0010ea50",
        "lzma_index_hash_decode",
    }
    # no name is fabricated
    assert all(not f.metadata["named"] for f in parsed.findings)
    # the frozen names (which are empty) are never replaced by a guessed backdoor
    assert not any("backdoor" in f.title.lower() or "cve" in f.title.lower() for f in parsed.findings)
    # provenance on every finding
    assert all(f.metadata["source"] == "kong_analysis" for f in parsed.findings)
    assert all(f.metadata["record_index"] in {0, 1} for f in parsed.findings)


def test_frozen_fixture_never_presents_parser_state_as_success() -> None:
    value = _analysis(FIXTURES / "phase3d_b_liblzma_analysis.json")
    parsed = parse_reverse_analysis(value, evidence_id="kong-analysis-evidence")
    assert parsed.semantic_adequate is False
    # stats still expose the real aggregate; nothing is hidden
    assert parsed.stats["errors"] == 445
    assert parsed.stats["named"] == 0


# ---------------------------------------------------------------------------
# named vs unnamed records
# ---------------------------------------------------------------------------


def test_named_function_output_is_adequate() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(named=1, analyzed=1, errors=0),
        "functions": [_named_item()],
    }
    result = _result(value)
    assert result["adequate"] is True
    assert len(result["findings"]) == 1
    assert result["findings"][0].title == "add_values (0x00401000)"
    assert result["findings"][0].metadata["named"] is True


def test_unnamed_symbol_is_kept_with_diagnostic() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(named=0, analyzed=1, errors=0),
        "functions": [
            {
                "address": "0x001158d0",
                "original_name": "lzma_index_hash_decode",
                "name": "",
                "confidence": 0,
            }
        ],
    }
    result = _result(value)
    assert len(result["findings"]) == 1
    assert result["findings"][0].metadata["named"] is False
    assert result["findings"][0].metadata["original_name"] == "lzma_index_hash_decode"
    assert result["adequate"] is False


# ---------------------------------------------------------------------------
# categorized per-record errors
# ---------------------------------------------------------------------------


def test_malformed_single_record_is_skipped_and_categorized() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(),
        "functions": [_named_item(), "this is not a dict", _named_item("b", "0x00402000")],
    }
    result = _result(value)
    assert result["diagnostics"].error_categories == {"malformed_item": 1}
    assert result["diagnostics"].parsed_records == 2
    assert len(result["findings"]) == 2


def test_duplicate_conflicting_records_dedupe_and_categorize() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(),
        "functions": [_named_item("a", "0x00401000"), _named_item("b", "0x00401000")],
    }
    result = _result(value)
    assert result["diagnostics"].error_categories == {"duplicate_record": 1}
    assert len(result["findings"]) == 1
    assert result["findings"][0].title == "a (0x00401000)"


def test_unsupported_optional_record_is_skipped_with_diagnostic() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(),
        "functions": [_named_item(), {"kind": "data_symbol", "address": "0x00403000", "name": "g"}],
    }
    result = _result(value)
    assert result["diagnostics"].error_categories == {"unsupported_record": 1}
    assert len(result["findings"]) == 1


def test_invalid_address_and_invalid_confidence_are_categorized() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(),
        "functions": [
            {"address": "not-an-address", "original_name": "FUN_X", "name": "", "confidence": 999},
        ],
    }
    result = _result(value)
    categories = result["diagnostics"].error_categories
    assert categories.get("invalid_address", 0) == 1
    assert categories.get("invalid_confidence", 0) == 1
    assert len(result["findings"]) == 1


def test_missing_name_record_keeps_address_with_diagnostic() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(),
        "functions": [{"address": "0x00401000"}],
    }
    result = _result(value)
    assert result["diagnostics"].error_categories.get("missing_name", 0) == 1
    assert len(result["findings"]) == 1
    assert "0x00401000" in result["findings"][0].title


def test_many_valid_with_few_bad_records_keeps_majority() -> None:
    functions = [_named_item(f"fn_{i}", f"0x0040{i:04x}") for i in range(100)]
    functions.insert(20, "junk")
    functions.append({"kind": "unknown_kind"})
    value = {"binary": {"name": "benign"}, "stats": _base_stats(named=99), "functions": functions}
    result = _result(value)
    assert len(result["findings"]) == 100
    assert result["diagnostics"].error_categories == {
        "malformed_item": 1,
        "unsupported_record": 1,
    }


# ---------------------------------------------------------------------------
# degenerate / empty / malformed outputs
# ---------------------------------------------------------------------------


def test_empty_kong_result_is_not_success() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(named=0, errors=0, analyzed=0, total_functions=0),
        "functions": [],
    }
    result = _result(value)
    assert result["adequate"] is False
    assert result["findings"] == ()
    assert result["diagnostics"].total_records == 0


def test_completely_malformed_functions_array_raises() -> None:
    value = {"binary": {"name": "benign"}, "stats": {}, "functions": "not-a-list"}
    with pytest.raises(ValueError, match="functions section"):
        parse_reverse_analysis(value, evidence_id="kong-analysis-evidence")


# ---------------------------------------------------------------------------
# provenance
# ---------------------------------------------------------------------------


def test_findings_carry_artifact_sha_and_record_provenance() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(named=1),
        "functions": [_named_item()],
    }
    result = _result(value, sha="f" * 64)
    metadata = result["findings"][0].metadata
    assert metadata["artifact_sha256"] == "f" * 64
    assert metadata["source"] == "kong_analysis"
    assert metadata["record_index"] == 0
    assert metadata["address"] == "0x00401000"


def test_parser_never_hardcodes_benchmark_targets() -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(named=1),
        "functions": [_named_item("ordinary_helper")],
    }
    result = _result(value)
    title = result["findings"][0].title.lower()
    for needle in ("backdoor", "cve-2024-3094", "init_rsa", "chacha20", "liblzma"):
        assert needle not in title


# ---------------------------------------------------------------------------
# adapter status mapping (honest PARTIAL / FAILED / SUCCESS)
# ---------------------------------------------------------------------------


def _prepared_adapter(tmp_path: Path, analysis: dict, *, returncode: int = 0) -> tuple[KongAdapter, object, object]:
    task = TaskSpec(
        task_id="kong-parser-status",
        domain="reverse",
        target=str(tmp_path / "sample.so"),
        goal="Analyze a binary.",
    )
    layout = RunLayout.ensure(tmp_path / "runs", task)
    kong_dir = layout.artifacts / "kong"
    kong_dir.mkdir(parents=True, exist_ok=True)
    (kong_dir / "analysis.json").write_text(json.dumps(analysis), encoding="utf-8")
    adapter = KongAdapter(kong_config_dir=tmp_path / "config")
    class _Process:
        started_at = "2026-09-01T00:00:00+00:00"
        started_monotonic = 1.0
        stdout_path = layout.logs / "kong.stdout.log"
        stderr_path = layout.logs / "kong.stderr.log"
    process = _Process()
    layout.logs.mkdir(parents=True, exist_ok=True)
    (layout.logs / "kong.stdout.log").touch()
    (layout.logs / "kong.stderr.log").touch()
    from pentestgpt_agent.protocol import PreparedTask
    prepared = PreparedTask(task, layout, {"mode": "analyze"})
    return adapter, prepared, process


@pytest.mark.asyncio
async def test_adapter_process_success_but_semantic_insufficient_is_partial(tmp_path: Path) -> None:
    value = _analysis(FIXTURES / "phase3d_b_liblzma_analysis.json")
    adapter, prepared, process = _prepared_adapter(tmp_path, value)
    result = adapter._collect_analysis(prepared, process, returncode=0, stdout="", stderr="", elapsed=1.0)

    assert result.status is ExecutionStatus.PARTIAL
    assert result.error is not None
    assert result.error.code == "KONG_SEMANTIC_OUTPUT_INSUFFICIENT"
    assert result.metrics["process_success"] is True
    assert result.metrics["semantic_adequate"] is False
    assert result.metrics["parse_diagnostics"]["parsed_records"] == 2
    assert result.metrics["errors"] == 445


@pytest.mark.asyncio
async def test_adapter_named_output_is_success(tmp_path: Path) -> None:
    value = {
        "binary": {"name": "benign"},
        "stats": _base_stats(named=1, errors=0, analyzed=1),
        "functions": [_named_item()],
    }
    adapter, prepared, process = _prepared_adapter(tmp_path, value)
    result = adapter._collect_analysis(prepared, process, returncode=0, stdout="", stderr="", elapsed=1.0)

    assert result.status is ExecutionStatus.SUCCESS
    assert result.error is None
    assert result.metrics["semantic_adequate"] is True
    assert result.findings[0].metadata["named"] is True


@pytest.mark.asyncio
async def test_adapter_process_failure_is_failed(tmp_path: Path) -> None:
    adapter, prepared, process = _prepared_adapter(tmp_path, _analysis(FIXTURES / "phase3d_b_liblzma_analysis.json"))
    result = adapter._collect_analysis(prepared, process, returncode=1, stdout="", stderr="boom", elapsed=1.0)

    assert result.status is ExecutionStatus.FAILED
    assert result.error is not None
    assert result.error.code == "KONG_PROCESS_FAILED"


@pytest.mark.asyncio
async def test_parser_error_never_becomes_global_success() -> None:
    from hunter_brain.completion_truth import KongReverseOracle
    from hunter_brain.state import ArtifactRecord, EvidenceRecord, HunterWorldState

    analysis_path = FIXTURES / "phase3d_b_liblzma_analysis.json"
    task = TaskSpec(
        task_id="reverse-truth",
        domain="reverse",
        target="liblzma.so.5.6.1",
        goal="Identify backdoor functions.",
        success_conditions=("Backdoor functions identified.",),
    )
    state = HunterWorldState.from_task(task)
    state.register_child_task("child-reverse")
    import hashlib

    state.add_artifact(
        ArtifactRecord(
            artifact_id="kong-analysis",
            artifact_type="reverse_analysis",
            path=str(analysis_path.resolve()),
            sha256=hashlib.sha256(analysis_path.read_bytes()).hexdigest(),
            size=analysis_path.stat().st_size,
            producer_agent="kong",
            source_task_id="child-reverse",
        )
    )
    state.add_evidence(EvidenceRecord("kong-analysis-evidence", "backend_analysis", "kong", "analysis", artifact_ref="kong-analysis"))

    verdict = await KongReverseOracle().assess(task=task, state=state)

    assert verdict.verdict.value == "not_verified"
    assert verdict.reason == "backend_tool_failure"

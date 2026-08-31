from __future__ import annotations

import json
import asyncio
from pathlib import Path

import pytest

from integrations.fuzzingbrain import FuzzingBrainAdapter
from integrations.fuzzingbrain.parser import iter_result_files, parse_outcome
from pentestgpt_agent.protocol import AuthorizationScope, ErrorCategory, ExecutionStatus, RunLayout, TaskSpec


def _task(tmp_path: Path, source: Path) -> tuple[TaskSpec, RunLayout]:
    task_id = "fuzzingbrain-unit"
    runs = tmp_path / "runs"
    workspace = (runs / task_id).resolve()
    task = TaskSpec(
        task_id=task_id,
        domain="vulnerability_research",
        target=str(source.resolve()),
        goal="Find and reproduce a vulnerability in this authorized local source tree.",
        workspace=str(workspace),
        authorization=AuthorizationScope(
            allowed_targets=(str(source.resolve()),),
            allowed_read_paths=(str(source.resolve()),),
            workspace=str(workspace),
        ),
        timeout=120,
        model_budget=1.5,
    )
    return task, RunLayout.ensure(runs, task)


def test_prepare_copies_input_and_never_places_secret_in_protocol(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.mkdir()
    (source / "target.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
    task, layout = _task(tmp_path, source)
    adapter = FuzzingBrainAdapter(repo_root=Path(__file__).resolve().parents[3])

    prepared = asyncio.run(adapter.prepare(task, layout))

    assert (layout.artifacts / "fuzzingbrain-workspace/repo/target.c").is_file()
    serialized = json.dumps({"input": prepared.backend_input, "metadata": prepared.metadata})
    assert "DEEPSEEK_API_KEY" not in serialized
    assert "--budget" in prepared.backend_input["command"]


def test_prepare_rejects_source_outside_authorized_read_paths(tmp_path: Path) -> None:
    source = tmp_path / "source.c"
    source.write_text("x", encoding="utf-8")
    task, layout = _task(tmp_path, source)
    bad = TaskSpec.from_dict({**task.to_dict(), "authorization": {**task.authorization.to_dict(), "allowed_read_paths": [str(tmp_path / "elsewhere")]}})

    with pytest.raises(ValueError, match="outside allowed_read_paths"):
        asyncio.run(FuzzingBrainAdapter(repo_root=Path(__file__).resolve().parents[3]).prepare(bad, layout))


def test_parser_distinguishes_success_empty_partial_and_failures() -> None:
    found = parse_outcome(returncode=0, stderr="", pov_documents=({"is_successful": True},))
    empty = parse_outcome(returncode=0, stderr="", report={"status": "completed"})
    partial = parse_outcome(returncode=0, stderr="", report={"status": "partial"})
    llm = parse_outcome(returncode=1, stderr="DeepSeek HTTP 429 rate limit")
    build = parse_outcome(returncode=1, stderr="compiler error: build failed")
    timeout = parse_outcome(returncode=1, stderr="fuzzer timed out")
    assert found.status is ExecutionStatus.SUCCESS and "trigger" in found.summary
    assert empty.status is ExecutionStatus.SUCCESS and "without finding" in empty.summary
    assert partial.status is ExecutionStatus.PARTIAL
    assert llm.error_code == "FUZZINGBRAIN_LLM_FAILURE" and llm.retryable
    assert build.error_category is ErrorCategory.TOOL_ERROR
    assert timeout.error_category is ErrorCategory.TIMEOUT


def test_result_collection_rejects_symlinks_and_classifies_outputs(tmp_path: Path) -> None:
    results = tmp_path / "results"
    for directory in ("povs", "crashes", "patches"):
        (results / directory).mkdir(parents=True)
    (results / "povs/pov.bin").write_bytes(b"pov")
    (results / "crashes/crash.bin").write_bytes(b"crash")
    (results / "patches/fix.diff").write_text("diff", encoding="utf-8")
    outside = tmp_path / "outside"
    outside.write_text("secret", encoding="utf-8")
    (results / "povs/leak").symlink_to(outside)

    found = list(iter_result_files(results))

    assert [kind for kind, _ in found] == ["crash_bundle", "patch", "trigger_sample"]
    assert all(path.name != "leak" for _, path in found)


def test_default_composition_builds_real_fuzzingbrain_adapter(tmp_path: Path) -> None:
    from integrations.hunter_brain import build_hunter_brain_adapters

    adapters = build_hunter_brain_adapters(repo_root=Path(__file__).resolve().parents[3])
    assert isinstance(adapters.vulnerability_research, FuzzingBrainAdapter)
    assert adapters.registry().get("vulnerability_research") is adapters.vulnerability_research

"""TRUDI Full runtime/environment contract tests (Phase 3D-C).

The full healthcheck must classify each environment failure with a distinct,
auditable code and must never silently fall back to Lite. Runtime availability
is measured separately from capability/verification.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from integrations.trudi.adapter import TrudiAdapter
from pentestgpt_agent.protocol import (
    AuthorizationScope,
    InputObject,
    TargetObject,
    TaskSpec,
)

ROOT = Path(__file__).resolve().parents[3]


def _task(*, task_id: str = "trudi-runtime-contract", sha: str | None = "a" * 64) -> TaskSpec:
    evidence = ROOT / ".runtime" / "eval-artifacts" / "dfir" / "eicar.com"
    if not evidence.is_file():
        evidence = Path(__file__).resolve().parent / "fixtures" / "evidence.log"
    return TaskSpec(
        task_id=task_id,
        domain="dfir",
        target=str(evidence),
        goal="Investigate the supplied evidence.",
        metadata={"file_type": {"normalized_type": "evidence_file", "sha256": sha}},
        input_object=InputObject(
            "input", "file", str(evidence), path=str(evidence),
            source_name=evidence.name, sha256=sha or "0" * 64, size_bytes=evidence.stat().st_size,
        ),
        target_object=TargetObject("target", "evidence_file", str(evidence)),
        authorization=AuthorizationScope((str(evidence),)),
    )


async def _healthcheck(adapter: TrudiAdapter, task: TaskSpec):
    return await adapter.healthcheck(task)


@pytest.mark.asyncio
async def test_missing_claude_code_is_explicit_dependency_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("integrations.trudi.adapter._deepseek_key_ready", lambda: True)
    adapter = TrudiAdapter(mode="full")
    adapter.claude = tmp_path / "missing" / "claude"

    health = await _healthcheck(adapter, _task())

    assert health.available is False
    assert health.error is not None
    assert health.error.code == "TRUDI_FULL_RUNTIME"


@pytest.mark.asyncio
async def test_missing_node_is_explicit_dependency_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("integrations.trudi.adapter._deepseek_key_ready", lambda: True)
    adapter = TrudiAdapter(mode="full")
    adapter.node_bin = tmp_path / "missing-node-bin"

    health = await _healthcheck(adapter, _task())

    assert health.available is False
    assert health.error is not None
    assert health.error.code == "TRUDI_FULL_RUNTIME"


@pytest.mark.asyncio
async def test_node_below_22_is_explicit_unavailable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("integrations.trudi.adapter._deepseek_key_ready", lambda: True)
    node = tmp_path / "node"
    node.write_text("#!/bin/sh\necho v18.0.0\n", encoding="utf-8")
    node.chmod(0o755)
    adapter = TrudiAdapter(mode="full")
    adapter.node_bin = tmp_path
    if not adapter.claude.is_file():
        pytest.skip("real Claude Code runtime is not installed in this checkout")

    health = await _healthcheck(adapter, _task())

    assert health.available is False
    assert health.error is not None
    assert health.error.code == "TRUDI_NODE_RUNTIME"


@pytest.mark.asyncio
async def test_missing_layer1_sha_is_explicit_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("integrations.trudi.adapter._deepseek_key_ready", lambda: True)
    adapter = TrudiAdapter(mode="full")

    health = await _healthcheck(adapter, _task(sha=None))

    assert health.available is False
    assert health.error is not None
    assert health.error.code == "TRUDI_FULL_SHA256"


@pytest.mark.asyncio
async def test_missing_deepseek_key_is_explicit_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in ("HUNTER_TRUDI_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("integrations.trudi.adapter._deepseek_key_ready", lambda: False)
    adapter = TrudiAdapter(mode="full")

    health = await _healthcheck(adapter, _task())

    assert health.available is False
    assert health.error is not None
    assert health.error.code == "TRUDI_REASONING_UNAVAILABLE"


@pytest.mark.asyncio
async def test_full_mode_never_silently_falls_back_to_lite(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("HUNTER_TRUDI_DEEPSEEK_API_KEY", "DEEPSEEK_API_KEY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr("integrations.trudi.adapter._deepseek_key_ready", lambda: False)
    adapter = TrudiAdapter(mode="full")

    health = await _healthcheck(adapter, _task())

    assert health.error is not None
    assert health.error.code == "TRUDI_REASONING_UNAVAILABLE"
    assert adapter._mode_for(_task()) == "full"
    assert "lite" not in (health.details.get("scope") or "")


@pytest.mark.asyncio
async def test_valid_runtime_key_and_sha_is_available(monkeypatch: pytest.MonkeyPatch) -> None:
    adapter = TrudiAdapter(mode="full")
    if not adapter.claude.is_file() or not (adapter.node_bin / "node").is_file():
        pytest.skip("real Claude Code/Node runtime is not installed in this checkout")
    monkeypatch.setattr("integrations.trudi.adapter._deepseek_key_ready", lambda: True)

    health = await _healthcheck(adapter, _task())

    assert health.available is True
    assert health.details["mode"] == "full"
    assert health.details["lite_fallback"] is False
    assert health.details["available_tool_count"] >= 1


def test_bootstrap_report_never_leaks_secret(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("HUNTER_TRUDI_DEEPSEEK_API_KEY", "super-secret-value-not-for-output")
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import trudi_full_bootstrap as bootstrap
    finally:
        sys.path.remove(str(ROOT / "scripts"))
    bootstrap._installed_node_version = lambda: "22.23.2"  # type: ignore[assignment]
    bootstrap._installed_claude_version = lambda: "2.1.251"  # type: ignore[assignment]
    bootstrap.deepseek_reachable = lambda key: bool(key)  # type: ignore[assignment]

    text = json.dumps(bootstrap.report(evidence=None), ensure_ascii=False)

    assert "super-secret-value-not-for-output" not in text
    assert "secret-value" not in text

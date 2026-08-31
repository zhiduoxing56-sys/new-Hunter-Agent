"""Four-domain non-live preflight tests.

The preflight must reuse the real adapters' healthchecks, must never start a
backend analysis, and must produce a READY/BLOCKED verdict per domain.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hunter_brain.orchestrator import CapabilityAdapterRegistry
from integrations.hunter_brain import build_hunter_brain_adapters
from integrations.preflight import (
    DOMAIN_ORDER,
    DomainPreflight,
    PreflightStatus,
    preflight_task,
    run_preflight,
)
from pentestgpt_agent.protocol import (
    ErrorCategory,
    ErrorDetail,
    HealthcheckResult,
    TaskSpec,
)


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class _FakeAdapter:
    agent_id = "fake"

    def __init__(self, *, available: bool) -> None:
        self._available = available
        self.healthchecks: list[TaskSpec] = []

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        self.healthchecks.append(task_spec)
        if self._available:
            return HealthcheckResult(True, {"probe": "ok"})
        return HealthcheckResult(
            False,
            {"probe": "missing"},
            ErrorDetail(
                ErrorCategory.ENVIRONMENT_ERROR,
                "fake backend is not ready",
                code="FAKE_BLOCKED",
            ),
        )


def _registry(*, available: bool, include_all: bool = True) -> CapabilityAdapterRegistry:
    adapters = {domain: _FakeAdapter(available=available) for domain in DOMAIN_ORDER}
    if not include_all:
        adapters.pop("reverse")
    return CapabilityAdapterRegistry(adapters)


def test_preflight_tasks_are_valid_for_every_domain() -> None:
    for domain in DOMAIN_ORDER:
        task = preflight_task(domain, PROJECT_ROOT)
        task.validate()
        assert task.domain == domain


@pytest.mark.asyncio
async def test_preflight_reports_ready_when_all_healthchecks_pass() -> None:
    registry = _registry(available=True)
    results = await run_preflight(repo_root=PROJECT_ROOT, registry=registry)

    assert set(results) == set(DOMAIN_ORDER)
    assert all(item.status is PreflightStatus.READY for item in results.values())
    for domain in DOMAIN_ORDER:
        assert results[domain].details == {"probe": "ok"}


@pytest.mark.asyncio
async def test_preflight_reports_blocked_and_unregistered_adapters() -> None:
    registry = _registry(available=False, include_all=False)
    results = await run_preflight(repo_root=PROJECT_ROOT, registry=registry)

    for domain in ("pentest", "vulnerability_research", "dfir"):
        assert results[domain].status is PreflightStatus.BLOCKED
        assert results[domain].error_code == "FAKE_BLOCKED"
    assert results["reverse"].status is PreflightStatus.BLOCKED
    assert results["reverse"].error_code == "ADAPTER_UNREGISTERED"


@pytest.mark.asyncio
async def test_real_adapter_preflight_never_starts_analysis() -> None:
    adapters = build_hunter_brain_adapters(repo_root=PROJECT_ROOT)
    registry = adapters.registry()
    results = await run_preflight(repo_root=PROJECT_ROOT, registry=registry)

    assert set(results) == set(DOMAIN_ORDER)
    for item in results.values():
        assert isinstance(item, DomainPreflight)
        assert item.status in {PreflightStatus.READY, PreflightStatus.BLOCKED}
        assert isinstance(item.details, dict)
    # healthcheck-only: no backend subprocess or container was launched.
    assert adapters.pentest.last_pid is None
    assert adapters.vulnerability_research._processes == {}
    assert adapters.trudi._processes == {}
    assert adapters.kong._processes == {}

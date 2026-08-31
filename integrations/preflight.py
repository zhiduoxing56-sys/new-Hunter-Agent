"""Non-live four-domain environment preflight over the real adapters.

Reuses each adapter's ``healthcheck`` contract. It never runs a backend
analysis: no Docker containers, Ghidra headless jobs, TRUDI MCP sessions,
FuzzingBrain jobs, or model calls are started. The result is a per-domain
READY / BLOCKED summary a developer can read before starting live smoke tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any

from pentestgpt_agent.protocol import AuthorizationScope, TaskSpec

from .hunter_brain import build_hunter_brain_adapters


DOMAIN_ORDER = ("pentest", "vulnerability_research", "dfir", "reverse")


class PreflightStatus(StrEnum):
    READY = "READY"
    BLOCKED = "BLOCKED"


@dataclass(frozen=True)
class DomainPreflight:
    domain: str
    agent_id: str
    status: PreflightStatus
    details: dict[str, Any] = field(default_factory=dict)
    error_code: str | None = None
    message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "domain": self.domain,
            "agent_id": self.agent_id,
            "status": self.status.value,
            "details": self.details,
            "error_code": self.error_code,
            "message": self.message,
        }


def preflight_task(domain: str, repo_root: Path) -> TaskSpec:
    """Build a minimal healthcheck-compatible TaskSpec for one domain.

    Healthchecks validate the TaskSpec and only inspect the environment; no
    analysis is scheduled from these tasks.
    """
    if domain == "pentest":
        target = "http://127.0.0.1:8080/"
        return TaskSpec(
            task_id=f"preflight-{domain}",
            domain=domain,
            target=target,
            goal="Preflight environment check (no analysis).",
            authorization=AuthorizationScope((target,)),
        )
    if domain == "vulnerability_research":
        target_dir = repo_root.resolve()
        return TaskSpec(
            task_id=f"preflight-{domain}",
            domain=domain,
            target=str(target_dir),
            goal="Preflight environment check (no analysis).",
            authorization=AuthorizationScope(
                (str(target_dir),), allowed_read_paths=(str(target_dir),)
            ),
        )
    target_file = Path(__file__).resolve()
    return TaskSpec(
        task_id=f"preflight-{domain}",
        domain=domain,
        target=str(target_file),
        goal="Preflight environment check (no analysis).",
        metadata={"kong_mode": "info", "trudi_mode": "lite"},
        authorization=AuthorizationScope(
            (str(target_file),), allowed_read_paths=(str(target_file),)
        ),
    )


async def run_preflight(
    *,
    repo_root: Path,
    registry: Any = None,
) -> dict[str, DomainPreflight]:
    """Run each real adapter's healthcheck and summarize the environment.

    ``registry`` may be injected (e.g. mocks) for deterministic tests; by
    default the four real adapters from ``build_hunter_brain_adapters`` are
    used.
    """
    if registry is None:
        registry = build_hunter_brain_adapters(repo_root=repo_root).registry()
    tasks = {domain: preflight_task(domain, repo_root) for domain in DOMAIN_ORDER}
    results: dict[str, DomainPreflight] = {}
    for domain in DOMAIN_ORDER:
        adapter = registry.get(domain)
        if adapter is None:
            results[domain] = DomainPreflight(
                domain,
                "none",
                PreflightStatus.BLOCKED,
                {},
                "ADAPTER_UNREGISTERED",
                "No adapter is registered for this domain.",
            )
            continue
        try:
            health = await adapter.healthcheck(tasks[domain])
        except Exception as exc:  # pragma: no cover - defensive
            results[domain] = DomainPreflight(
                domain,
                adapter.agent_id,
                PreflightStatus.BLOCKED,
                {"exception": type(exc).__name__},
                "PREFLIGHT_ERROR",
                f"{type(exc).__name__}: {exc}",
            )
            continue
        results[domain] = DomainPreflight(
            domain,
            adapter.agent_id,
            PreflightStatus.READY if health.available else PreflightStatus.BLOCKED,
            dict(health.details),
            health.error.code if health.error is not None else None,
            health.error.message if health.error is not None else None,
        )
    return results

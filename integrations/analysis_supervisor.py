"""Minimal deterministic router for the frozen Analysis subsystem."""

from __future__ import annotations

from pathlib import Path
from collections.abc import Mapping

from pentestgpt_agent.protocol import (
    AdapterRunner,
    AgentAdapter,
    ErrorCategory,
    ErrorDetail,
    HealthcheckResult,
    PreparedTask,
    RunLayout,
    TaskSpec,
)


class AnalysisSupervisor:
    def __init__(
        self,
        *,
        kong_adapter: AgentAdapter,
        trudi_adapter: AgentAdapter,
        runs_root: Path,
        additional_adapters: Mapping[str, AgentAdapter] | None = None,
    ) -> None:
        self._routes = {"reverse": kong_adapter, "dfir": trudi_adapter}
        self._routes.update(additional_adapters or {})
        self.runs_root = runs_root

    async def execute(self, task_spec: TaskSpec):
        adapter = self._routes.get(
            task_spec.domain, _UnsupportedAnalysisAdapter(tuple(sorted(self._routes)))
        )
        return await AdapterRunner(adapter, runs_root=self.runs_root).execute(task_spec)


class _UnsupportedAnalysisAdapter(AgentAdapter):
    agent_id = "analysis-supervisor"

    def __init__(self, supported_domains: tuple[str, ...] = ("dfir", "reverse")) -> None:
        self.supported_domains = supported_domains

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        return HealthcheckResult(
            False,
            {"domain": task_spec.domain, "supported_domains": list(self.supported_domains)},
            ErrorDetail(
                ErrorCategory.INVALID_TASK,
                f"unsupported Analysis domain: {task_spec.domain}",
                code="ANALYSIS_DOMAIN_UNSUPPORTED",
                metadata={"supported_domains": list(self.supported_domains)},
            ),
        )

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        raise RuntimeError("unsupported adapter cannot prepare")

    async def run(self, prepared: PreparedTask):
        raise RuntimeError("unsupported adapter cannot run")

    async def collect(self, prepared: PreparedTask, handle):
        raise RuntimeError("unsupported adapter cannot collect")

    async def stop(self, prepared: PreparedTask | None, *, reason: str) -> None:
        return None

"""Composition roots for Hunter Brain's professional backends.

Professional implementations are imported here, outside ``hunter_brain``. The
brain receives only the frozen ``AgentAdapter`` interface through its registry.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from hunter_brain.capabilities import CapabilityCatalog, DEFAULT_CAPABILITIES
from hunter_brain.orchestrator import (
    CapabilityAdapterRegistry,
    HunterOrchestrator,
    OrchestrationStatus,
)
from hunter_brain.question_generator import CrossDomainQuestionGenerator
from hunter_brain.supervisor import (
    DeepSeekDecisionModel,
    DeepSeekSupervisorConfig,
    HunterSupervisor,
)
from hunter_brain.verifier import GlobalVerifier
from pentestgpt_agent.protocol import (
    AgentAdapter,
    AgentResult,
    ErrorCategory,
    ErrorDetail,
    ExecutionStatus,
    TaskSpec,
)

from autopenbench_adapter.protocol import AutoPenBenchProtocolAdapter
from .kong import KongAdapter
from .trudi import TrudiAdapter
from .fuzzingbrain import FuzzingBrainAdapter


@dataclass(frozen=True)
class AnalysisBrainAdapters:
    kong: AgentAdapter
    trudi: AgentAdapter

    def registry(self) -> CapabilityAdapterRegistry:
        return CapabilityAdapterRegistry(
            {
                "dfir": self.trudi,
                "reverse": self.kong,
            }
        )


@dataclass(frozen=True)
class HunterBrainAdapters:
    """All four phase-ten capability slots, composed outside the brain core."""

    kong: AgentAdapter
    trudi: AgentAdapter
    pentest: AgentAdapter
    vulnerability_research: AgentAdapter

    def registry(self) -> CapabilityAdapterRegistry:
        return CapabilityAdapterRegistry(
            {
                "dfir": self.trudi,
                "reverse": self.kong,
                "pentest": self.pentest,
                "vulnerability_research": self.vulnerability_research,
            }
        )


@dataclass(frozen=True)
class HunterBrainTaskExecutor:
    """Translate a global orchestration outcome to the frozen Web result shape."""

    orchestrator: HunterOrchestrator

    async def execute(self, task_spec: TaskSpec) -> AgentResult:
        started_at = datetime.now(UTC).isoformat()
        outcome = await self.orchestrator.run(task_spec)
        successful = outcome.status is OrchestrationStatus.COMPLETE
        partial = outcome.status in {
            OrchestrationStatus.BLOCKED,
            OrchestrationStatus.VERIFICATION_REQUIRED,
        }
        status = (
            ExecutionStatus.SUCCESS
            if successful
            else ExecutionStatus.PARTIAL
            if partial
            else ExecutionStatus.FAILED
        )
        terminal = outcome.terminal_decision
        summary = (
            getattr(terminal, "summary", None)
            or outcome.message
            or f"Hunter Brain finished with status {outcome.status.value}."
        )
        error = None
        if not successful:
            error = ErrorDetail(
                ErrorCategory.BACKEND_ERROR,
                outcome.message or summary,
                code=f"HUNTER_BRAIN_{outcome.status.value.upper()}",
                retryable=outcome.status is OrchestrationStatus.MODEL_ERROR,
            )
        return AgentResult(
            task_id=task_spec.task_id,
            agent_id="hunter-brain",
            domain=task_spec.domain,
            status=status,
            started_at=started_at,
            finished_at=datetime.now(UTC).isoformat(),
            summary=summary,
            error=error,
            metrics={
                "decisions_used": outcome.budget.decisions_used,
                "capability_calls_used": outcome.budget.capability_calls_used,
                "tool_calls_used": outcome.budget.tool_calls_used,
            },
            raw_output={
                "orchestration_status": outcome.status.value,
                "terminal_decision": terminal.to_dict() if terminal else None,
                "world_state": outcome.state.to_dict(),
            },
        )


def build_analysis_brain_adapters(
    *,
    repo_root: Path,
    trudi_mode: str = "lite",
    java_home: Path | None = None,
    ghidra_dir: Path | None = None,
    kong_config_dir: Path | None = None,
) -> AnalysisBrainAdapters:
    """Build only the mature DFIR/reverse pair used by phase-nine validation."""

    return AnalysisBrainAdapters(
        kong=KongAdapter(
            repo_root=repo_root,
            java_home=java_home,
            ghidra_dir=ghidra_dir,
            kong_config_dir=kong_config_dir,
        ),
        trudi=TrudiAdapter(repo_root=repo_root, mode=trudi_mode),
    )


def build_hunter_brain_adapters(
    *,
    repo_root: Path,
    vulnerability_research_adapter: AgentAdapter | None = None,
    pentest_adapter: AgentAdapter | None = None,
    trudi_mode: str = "lite",
    java_home: Path | None = None,
    ghidra_dir: Path | None = None,
    kong_config_dir: Path | None = None,
) -> HunterBrainAdapters:
    """Compose four domains without changing Hunter's supervision loop.

    AutoPenBench is the repository's existing penetration-testing adapter. The
    FuzzingBrain is the default vulnerability-research backend. Tests and
    deployments may still inject another protocol-compatible implementation.
    """

    analysis = build_analysis_brain_adapters(
        repo_root=repo_root,
        trudi_mode=trudi_mode,
        java_home=java_home,
        ghidra_dir=ghidra_dir,
        kong_config_dir=kong_config_dir,
    )
    return HunterBrainAdapters(
        kong=analysis.kong,
        trudi=analysis.trudi,
        pentest=pentest_adapter or AutoPenBenchProtocolAdapter(),
        vulnerability_research=vulnerability_research_adapter
        or FuzzingBrainAdapter(repo_root=repo_root),
    )


def build_analysis_brain_executor(
    *,
    repo_root: Path,
    runs_root: Path,
    config: DeepSeekSupervisorConfig | None = None,
) -> HunterBrainTaskExecutor:
    """Build the Web autonomous executor from currently mature real backends."""

    catalog = CapabilityCatalog(DEFAULT_CAPABILITIES[:2])
    adapters = build_analysis_brain_adapters(repo_root=repo_root)
    supervisor = HunterSupervisor(
        model=DeepSeekDecisionModel(config or DeepSeekSupervisorConfig.from_env()),
        catalog=catalog,
    )
    return HunterBrainTaskExecutor(
        HunterOrchestrator(
            supervisor=supervisor,
            adapters=adapters.registry(),
            runs_root=runs_root,
            question_generator=CrossDomainQuestionGenerator(catalog),
            verifier=GlobalVerifier(),
        )
    )

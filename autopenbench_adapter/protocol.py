"""Common AgentAdapter v1 bridge for the maintained real AutoPenBench runner."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import replace
from pathlib import Path
from typing import Any

from hunter_brain.handoffs import HandoffCarrier, HandoffDescriptor
from pentestgpt_agent.protocol.adapter import (
    AdapterExecutionError,
    HealthcheckResult,
    PreparedTask,
)
from pentestgpt_agent.protocol.contracts import (
    Artifact,
    ErrorCategory,
    ErrorDetail,
    Finding,
    TaskSpec,
)
from pentestgpt_agent.protocol.layout import RunLayout
from pentestgpt_agent.protocol.manifest import AgentManifest, ManifestMode
from pentestgpt_agent.protocol.subprocess_adapter import SubprocessAdapter

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
PENTEST_AGENT_ROOT = REPOSITORY_ROOT / "pentestgpt-core/pentestgpt_agent"
DEFAULT_BENCHMARK_ROOT = REPOSITORY_ROOT.parent / "AutoPenBench"


class AutoPenBenchProtocolAdapter(SubprocessAdapter):
    """Run one explicitly selected local benchmark case behind the common lifecycle."""

    def __init__(
        self,
        *,
        benchmark_root: Path = DEFAULT_BENCHMARK_ROOT,
        level: str = "in-vitro",
        category: str = "web_security",
        vm: int = 0,
        timeout: float = 3600.0,
        backend: str = "openai_compatible",
        model: str | None = None,
    ) -> None:
        self.benchmark_root = benchmark_root.resolve()
        self.level = level
        self.category = category
        self.vm = vm
        self.backend = backend
        self.model = model
        if backend not in {"openai_compatible", "codex", "claude"}:
            raise ValueError("unsupported PentestGPT backend")
        python = PENTEST_AGENT_ROOT / ".venv/bin/python"
        backend_id = "{task_id}-backend"
        start = [
            str(python),
            str(REPOSITORY_ROOT / "autopenbench_adapter/run_baseline.py"),
            "--benchmark-root",
            str(self.benchmark_root),
            "--level",
            level,
            "--category",
            category,
            "--vm",
            str(vm),
            "--backend",
            backend,
            "--run-id",
            backend_id,
            "--runs-root",
            "{artifacts}/backend-runs",
            "--workspace-root",
            "{artifacts}/backend-workspaces",
        ]
        if model is not None:
            start.extend(("--model", model))
        manifest = AgentManifest(
            name="pentestgpt-autopenbench",
            mode=ManifestMode.SUBPROCESS,
            workdir=str(REPOSITORY_ROOT),
            start=tuple(start),
            result=f"artifacts/backend-runs/{backend_id}/autopenbench-evaluation.json",
            timeout=timeout,
            environment={
                "PYTHONPATH": (
                    f"{REPOSITORY_ROOT}:{PENTEST_AGENT_ROOT / 'src'}"
                    + (f":{os.environ['PYTHONPATH']}" if os.environ.get("PYTHONPATH") else "")
                )
            },
            required_environment=(
                ("HUNTER_MODEL_NAME", "HUNTER_MODEL_BASE_URL", "HUNTER_MODEL_API_KEY")
                if backend == "openai_compatible"
                else ()
            ),
            metadata={
                "backend": "PentestGPT",
                "benchmark": "AutoPenBench",
                "authorization": "local Docker benchmark only",
                "model_backend": backend,
            },
        )
        super().__init__(manifest)

    def game(self) -> dict[str, Any]:
        games_path = self.benchmark_root / "data/games.json"
        value = json.loads(games_path.read_text(encoding="utf-8"))
        game = value[self.level][self.category][self.vm]
        if not isinstance(game, dict):
            raise ValueError("selected AutoPenBench game is malformed")
        return game

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        base = await super().healthcheck(task_spec)
        if not base.available:
            return base
        missing = [
            path
            for path in (
                self.benchmark_root / "data/games.json",
                self.benchmark_root / "benchmark/machines/docker-compose.yml",
                REPOSITORY_ROOT / "autopenbench_adapter/run_baseline.py",
            )
            if not path.is_file()
        ]
        if missing:
            return HealthcheckResult(
                False,
                {"missing_paths": [str(path) for path in missing]},
                ErrorDetail(
                    ErrorCategory.DEPENDENCY_ERROR,
                    "AutoPenBench resources are incomplete",
                    code="AUTOPENBENCH_RESOURCE_MISSING",
                ),
            )
        if shutil.which("docker") is None:
            return HealthcheckResult(
                False,
                {},
                ErrorDetail(
                    ErrorCategory.DEPENDENCY_ERROR,
                    "Docker CLI is unavailable",
                    code="DOCKER_NOT_FOUND",
                ),
            )
        if self.backend in {"codex", "claude"}:
            executable = shutil.which(self.backend)
            if executable is None:
                return HealthcheckResult(
                    False,
                    {},
                    ErrorDetail(
                        ErrorCategory.DEPENDENCY_ERROR,
                        f"{self.backend} CLI is unavailable",
                        code="MODEL_CLI_NOT_FOUND",
                    ),
                )
            if self.backend == "codex":
                auth = await asyncio.create_subprocess_exec(
                    executable,
                    "login",
                    "status",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                auth_output, _ = await auth.communicate()
                if auth.returncode != 0 or b"Logged in" not in auth_output:
                    return HealthcheckResult(
                        False,
                        {"model_cli": "codex", "authenticated": False},
                        ErrorDetail(
                            ErrorCategory.ENVIRONMENT_ERROR,
                            "Codex CLI is not authenticated",
                            code="MODEL_AUTH_UNAVAILABLE",
                        ),
                    )
        process = await asyncio.create_subprocess_exec(
            "docker",
            "info",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE,
        )
        _, stderr = await process.communicate()
        if process.returncode != 0:
            return HealthcheckResult(
                False,
                {"docker_error": stderr.decode(errors="replace")[-500:]},
                ErrorDetail(
                    ErrorCategory.ENVIRONMENT_ERROR,
                    "Docker daemon is unavailable to the adapter",
                    code="DOCKER_DAEMON_UNAVAILABLE",
                ),
            )
        return HealthcheckResult(
            True,
            {
                **base.details,
                "benchmark_root": str(self.benchmark_root),
                "case": f"{self.level}/{self.category}/vm{self.vm}",
                "docker_daemon": "available",
            },
        )

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        game = self.game()
        expected_target = str(game.get("target", ""))
        expected_goal = str(game.get("task", ""))
        allowed_targets = (
            task_spec.authorization.allowed_targets
            if task_spec.authorization is not None
            else tuple(str(item) for item in task_spec.scope.get("allowed_targets", []))
        )
        if task_spec.domain != "pentest" or task_spec.target != expected_target:
            raise AdapterExecutionError(
                ErrorCategory.INVALID_TASK,
                "TaskSpec does not match the selected authorized AutoPenBench case",
                code="AUTOPENBENCH_TASK_MISMATCH",
            )
        if task_spec.target not in allowed_targets or task_spec.goal != expected_goal:
            raise AdapterExecutionError(
                ErrorCategory.SCOPE_VIOLATION,
                "TaskSpec goal or authorization does not match the benchmark case",
                code="AUTOPENBENCH_SCOPE_MISMATCH",
            )
        return await super().prepare(task_spec, run_layout)

    async def collect(self, prepared: PreparedTask, handle: Any) -> Any:
        """Expose the real benchmark evaluation as a generic DFIR-consumable handoff."""
        result = await super().collect(prepared, handle)
        backend = next(
            (artifact for artifact in result.artifacts if artifact.artifact_id == "backend-result"),
            None,
        )
        evidence = next(
            (item for item in result.evidence if item.artifact_ref == "backend-result"),
            None,
        )
        if backend is None or evidence is None:
            return result
        descriptor = HandoffDescriptor(
            semantic_type="evidence_bundle",
            carrier=HandoffCarrier.FILE,
            values=(),
            source_task_id=prepared.task_spec.task_id,
            source_evidence_refs=(evidence.evidence_id,),
        )
        handoff = Artifact(
            "pentest-evidence-handoff",
            descriptor.semantic_type,
            backend.path,
            backend.sha256,
            backend.size,
            descriptor.to_metadata(),
            self.agent_id,
        )
        handoff.validate()
        finding = Finding(
            "pentest-evaluation",
            "target_proof",
            "PentestGPT AutoPenBench evaluation",
            result.summary,
            evidence_refs=(evidence.evidence_id,),
            metadata={"execution_status": result.status.value},
        )
        return replace(
            result,
            artifacts=(*result.artifacts, handoff),
            findings=(*result.findings, finding),
        )

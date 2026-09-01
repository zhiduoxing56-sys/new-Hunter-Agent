"""Protocol v1 AgentAdapter for Kong's official CLI."""

from __future__ import annotations

import asyncio
import os
import re
import signal
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from hunter_brain.handoffs import HandoffCarrier, HandoffDescriptor
from pentestgpt_agent.protocol import (
    AgentAdapter,
    AgentManifest,
    AgentResult,
    Artifact,
    ErrorCategory,
    ErrorDetail,
    Evidence,
    ExecutionHandle,
    ExecutionStatus,
    Finding,
    HealthcheckResult,
    PreparedTask,
    RunLayout,
    TaskSpec,
)
from pentestgpt_agent.protocol.contracts import utc_now

from .parser import (
    analysis_evidence,
    analysis_sha256,
    load_analysis,
    parse_info_output,
    parse_reverse_analysis,
)


@dataclass
class _Process:
    process: asyncio.subprocess.Process
    stdout_stream: BinaryIO
    stderr_stream: BinaryIO
    stdout_path: Path
    stderr_path: Path
    started_at: str
    started_monotonic: float


class KongAdapter(AgentAdapter):
    """Run Kong without importing or modifying its internal Python modules."""

    agent_id = "kong"

    def __init__(
        self,
        *,
        repo_root: Path | None = None,
        java_home: Path | None = None,
        ghidra_dir: Path | None = None,
        kong_config_dir: Path | None = None,
    ) -> None:
        self.repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.manifest = AgentManifest.load(Path(__file__).with_name("manifest.json"))
        self.kong_root = (self.repo_root / self.manifest.workdir).resolve()
        self.executable = self.kong_root / self.manifest.start[0]
        self.java_home = (java_home or _optional_path("JAVA_HOME")).resolve() if (java_home or _optional_path("JAVA_HOME")) else None
        self.ghidra_dir = (ghidra_dir or _optional_path("GHIDRA_INSTALL_DIR")).resolve() if (ghidra_dir or _optional_path("GHIDRA_INSTALL_DIR")) else None
        configured_dir = kong_config_dir or _optional_path("KONG_CONFIG_DIR")
        self.kong_config_dir = configured_dir.resolve() if configured_dir else None
        self._processes: dict[str, _Process] = {}

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        try:
            task_spec.validate()
            if task_spec.domain != "reverse":
                return _unavailable(ErrorCategory.INVALID_TASK, "Kong requires domain='reverse'", "KONG_DOMAIN")
            target = Path(task_spec.target).resolve()
            if not target.is_file():
                return _unavailable(ErrorCategory.INVALID_TASK, f"Kong target is not a file: {target}", "KONG_TARGET")
            if not self.executable.is_file() or not os.access(self.executable, os.X_OK):
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, f"Kong executable is unavailable: {self.executable}", "KONG_EXECUTABLE")
            if self.java_home is None or not (self.java_home / "bin/java").is_file():
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, "JDK 21+ is unavailable", "KONG_JAVA")
            java_version = await _java_version(self.java_home / "bin/java")
            if java_version is None or java_version < 21:
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, "Kong requires JDK 21+", "KONG_JAVA_VERSION")
            if self.ghidra_dir is None or not (self.ghidra_dir / "support/analyzeHeadless").is_file():
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, "Ghidra is unavailable", "KONG_GHIDRA")
            mode = _mode(task_spec)
            provider_ready = _provider_ready()
            if mode == "analyze" and not provider_ready:
                return _unavailable(
                    ErrorCategory.ENVIRONMENT_ERROR,
                    "Kong analyze requires ANTHROPIC_API_KEY, OPENAI_API_KEY, or KONG_BASE_URL with KONG_MODEL",
                    "KONG_LLM_UNAVAILABLE",
                )
            return HealthcheckResult(
                True,
                {
                    "executable": str(self.executable),
                    "ghidra_dir": str(self.ghidra_dir),
                    "java_version": java_version,
                    "mode": mode,
                    "provider_ready": provider_ready,
                    "manifest": self.manifest.to_dict(),
                },
            )
        except Exception as exc:
            return _unavailable(ErrorCategory.INVALID_TASK, str(exc), "KONG_HEALTHCHECK")

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        task_spec.validate()
        mode = _mode(task_spec)
        output_dir = run_layout.artifacts / "kong"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = [str(self.executable), mode, str(Path(task_spec.target).resolve())]
        if mode == "analyze":
            command.extend(["--headless", "--output", str(output_dir), "--format", "json", "--format", "source"])
            provider = os.environ.get("KONG_PROVIDER")
            model = os.environ.get("KONG_MODEL")
            base_url = os.environ.get("KONG_BASE_URL")
            if provider:
                command.extend(["--provider", provider])
            if model:
                command.extend(["--model", model])
            if base_url:
                command.extend(["--base-url", base_url])
        command.extend(["--ghidra-dir", str(self.ghidra_dir)])
        runtime = run_layout.logs / "kong-runtime"
        config_dir = self.kong_config_dir or runtime / "kong-config"
        environment = {
            "JAVA_HOME": str(self.java_home),
            "GHIDRA_INSTALL_DIR": str(self.ghidra_dir),
            "KONG_CONFIG_DIR": str(config_dir),
            "XDG_CONFIG_HOME": str(runtime / "xdg-config"),
            "XDG_CACHE_HOME": str(runtime / "xdg-cache"),
            "_JAVA_OPTIONS": _headless_java_options(os.environ.get("_JAVA_OPTIONS", "")),
        }
        environment["PATH"] = f"{self.java_home / 'bin'}:{os.environ.get('PATH', '')}"
        return PreparedTask(
            task_spec,
            run_layout,
            backend_input={"command": command, "environment": environment, "mode": mode},
            metadata={"manifest": self.manifest.to_dict(), "mode": mode},
        )

    async def run(self, prepared: PreparedTask) -> ExecutionHandle:
        command = prepared.backend_input["command"]
        environment = prepared.backend_input["environment"]
        stdout_path = prepared.run_layout.logs / "kong.stdout.log"
        stderr_path = prepared.run_layout.logs / "kong.stderr.log"
        stdout_stream = stdout_path.open("wb")
        stderr_stream = stderr_path.open("wb")
        try:
            process = await asyncio.create_subprocess_exec(
                *command,
                cwd=self.kong_root,
                env={**os.environ, **environment},
                stdout=stdout_stream,
                stderr=stderr_stream,
                start_new_session=True,
            )
        except Exception:
            stdout_stream.close()
            stderr_stream.close()
            raise
        backend_id = f"kong-{uuid.uuid4().hex}"
        started_at = utc_now()
        self._processes[backend_id] = _Process(
            process, stdout_stream, stderr_stream, stdout_path, stderr_path, started_at, time.monotonic()
        )
        return ExecutionHandle(backend_id, started_at, {"pid": process.pid})

    async def collect(self, prepared: PreparedTask, handle: ExecutionHandle) -> AgentResult:
        context = self._processes.get(handle.backend_id)
        if context is None:
            raise RuntimeError("unknown Kong process handle")
        returncode = await context.process.wait()
        context.stdout_stream.close()
        context.stderr_stream.close()
        stdout = context.stdout_path.read_text(encoding="utf-8", errors="replace")
        stderr = context.stderr_path.read_text(encoding="utf-8", errors="replace")
        mode = str(prepared.backend_input["mode"])
        elapsed = time.monotonic() - context.started_monotonic
        self._processes.pop(handle.backend_id, None)
        if mode == "info":
            return self._collect_info(prepared, context, returncode, stdout, stderr, elapsed)
        return self._collect_analysis(prepared, context, returncode, stdout, stderr, elapsed)

    def _collect_info(self, prepared: PreparedTask, context: _Process, returncode: int, stdout: str, stderr: str, elapsed: float) -> AgentResult:
        if returncode != 0:
            return _failed_result(prepared, context.started_at, returncode, stdout, stderr, elapsed)
        parsed = parse_info_output(stdout)
        output_path = prepared.run_layout.artifacts / "kong-info.txt"
        output_path.write_text(stdout, encoding="utf-8")
        artifact = Artifact.from_path("kong-info", "reverse_metadata", output_path, producer=self.agent_id)
        evidence = Evidence(
            "kong-info-evidence",
            "backend_analysis",
            self.agent_id,
            "Raw output from Kong's official info command backed by Ghidra.",
            artifact_ref=artifact.artifact_id,
        )
        handoff = HandoffDescriptor(
            semantic_type="evidence_bundle",
            carrier=HandoffCarrier.FILE,
            values=(),
            source_task_id=prepared.task_spec.task_id,
            source_evidence_refs=(evidence.evidence_id,),
        )
        evidence_handoff = Artifact(
            "kong-info-evidence-handoff",
            handoff.semantic_type,
            artifact.path,
            artifact.sha256,
            artifact.size,
            handoff.to_metadata(),
            self.agent_id,
        )
        finding = Finding(
            "kong-binary-metadata",
            "binary_metadata",
            f"{parsed['binary']} metadata",
            f"Kong identified {parsed.get('format')} {parsed.get('arch')} with {parsed['functions']} functions.",
            evidence_refs=(evidence.evidence_id,),
            metadata=parsed,
        )
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=ExecutionStatus.SUCCESS,
            started_at=context.started_at,
            finished_at=utc_now(),
            summary="Kong completed real Ghidra-backed binary metadata analysis.",
            findings=(finding,),
            evidence=(evidence,),
            artifacts=(artifact, evidence_handoff),
            metrics={"wall_seconds": elapsed, "functions": parsed["functions"], "mode": "info"},
            raw_output={"returncode": returncode, "stdout_log": str(context.stdout_path), "stderr_log": str(context.stderr_path), "kong_info": parsed},
        )

    def _collect_analysis(self, prepared: PreparedTask, context: _Process, returncode: int, stdout: str, stderr: str, elapsed: float) -> AgentResult:
        analysis_path = prepared.run_layout.artifacts / "kong/analysis.json"
        if returncode != 0 or not analysis_path.is_file():
            return _failed_result(prepared, context.started_at, returncode, stdout, stderr, elapsed)
        analysis = load_analysis(analysis_path)
        artifacts = [Artifact.from_path("kong-analysis", "reverse_analysis", analysis_path, producer=self.agent_id)]
        source_path = prepared.run_layout.artifacts / "kong/decompiled.c"
        if source_path.is_file():
            artifacts.append(Artifact.from_path("kong-decompiled-source", "decompiled_source", source_path, producer=self.agent_id))
        evidence = analysis_evidence("kong-analysis")
        handoff = HandoffDescriptor(
            semantic_type="evidence_bundle",
            carrier=HandoffCarrier.FILE,
            values=(),
            source_task_id=prepared.task_spec.task_id,
            source_evidence_refs=(evidence.evidence_id,),
        )
        artifacts.append(
            Artifact(
                "kong-evidence-handoff",
                handoff.semantic_type,
                artifacts[0].path,
                artifacts[0].sha256,
                artifacts[0].size,
                handoff.to_metadata(),
                self.agent_id,
            )
        )
        parsed = parse_reverse_analysis(
            analysis,
            evidence_id=evidence.evidence_id,
            artifact_sha256=analysis_sha256(analysis_path),
        )
        stats = parsed.stats
        functions = parsed.findings
        diagnostics = parsed.diagnostics.to_dict()
        if parsed.semantic_adequate:
            status = ExecutionStatus.SUCCESS
            summary = (
                f"Kong analyzed {stats.get('analyzed', len(functions))} functions and "
                f"produced {len(functions)} structured function result(s) "
                f"({diagnostics['named_records']} named)."
            )
            error = None
        else:
            status = ExecutionStatus.PARTIAL
            summary = (
                f"Kong's process succeeded but produced insufficient semantic output: "
                f"errors={stats.get('errors', 0)}, named={stats.get('named', 0)}, "
                f"analyzed={stats.get('analyzed', 0)}, records={diagnostics['parsed_records']}."
            )
            error = ErrorDetail(
                ErrorCategory.BACKEND_ERROR,
                "Kong process succeeded but semantic output is insufficient (no named functions).",
                code="KONG_SEMANTIC_OUTPUT_INSUFFICIENT",
                metadata={
                    "errors": stats.get("errors", 0),
                    "named": stats.get("named", 0),
                    "analyzed": stats.get("analyzed", 0),
                },
            )
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=status,
            started_at=context.started_at,
            finished_at=utc_now(),
            summary=summary,
            findings=functions,
            evidence=(evidence,),
            artifacts=tuple(artifacts),
            metrics={
                **stats,
                "adapter_wall_seconds": elapsed,
                "mode": "analyze",
                "process_success": True,
                "semantic_adequate": parsed.semantic_adequate,
                "parse_diagnostics": diagnostics,
            },
            error=error,
            raw_output={"returncode": returncode, "stdout_log": str(context.stdout_path), "stderr_log": str(context.stderr_path), "kong_analysis": analysis},
        )

    async def stop(self, prepared: PreparedTask | None, *, reason: str) -> None:
        for backend_id, context in list(self._processes.items()):
            if context.process.returncode is None:
                with suppress(ProcessLookupError):
                    os.killpg(context.process.pid, signal.SIGTERM)
                try:
                    await asyncio.wait_for(context.process.wait(), timeout=2)
                except TimeoutError:
                    with suppress(ProcessLookupError):
                        os.killpg(context.process.pid, signal.SIGKILL)
                    await context.process.wait()
            context.stdout_stream.close()
            context.stderr_stream.close()
            self._processes.pop(backend_id, None)


def _optional_path(name: str) -> Path | None:
    value = os.environ.get(name)
    return Path(value) if value else None


def _mode(task_spec: TaskSpec) -> str:
    value = task_spec.metadata.get("kong_mode", "analyze")
    if value not in {"analyze", "info"}:
        raise ValueError("TaskSpec metadata.kong_mode must be 'analyze' or 'info'")
    return str(value)


def _provider_ready() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or (os.environ.get("KONG_BASE_URL") and os.environ.get("KONG_MODEL"))
    )


async def _java_version(java: Path) -> int | None:
    process = await asyncio.create_subprocess_exec(str(java), "-version", stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
    stdout, stderr = await process.communicate()
    match = re.search(rb'version "(\d+)', stderr or stdout)
    return int(match.group(1)) if process.returncode == 0 and match else None


def _headless_java_options(current: str) -> str:
    option = "-Djava.awt.headless=true"
    return current if option in current else f"{current} {option}".strip()


def _unavailable(category: ErrorCategory, message: str, code: str) -> HealthcheckResult:
    return HealthcheckResult(False, {"code": code}, ErrorDetail(category, message, code=code))


def _failed_result(prepared: PreparedTask, started_at: str, returncode: int, stdout: str, stderr: str, elapsed: float) -> AgentResult:
    summary = f"Kong exited with status {returncode}."
    return AgentResult(
        task_id=prepared.task_spec.task_id,
        agent_id="kong",
        domain=prepared.task_spec.domain,
        status=ExecutionStatus.FAILED,
        started_at=started_at,
        finished_at=utc_now(),
        summary=summary,
        metrics={"wall_seconds": elapsed, "mode": prepared.backend_input.get("mode")},
        error=ErrorDetail(ErrorCategory.BACKEND_ERROR, summary, code="KONG_PROCESS_FAILED", metadata={"returncode": returncode}),
        raw_output={"returncode": returncode, "stdout": stdout, "stderr": stderr},
    )

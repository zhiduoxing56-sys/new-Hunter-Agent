"""Protocol v1 AgentAdapter for TRUDI's official FastMCP stdio server."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import signal
import time
import uuid
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from pentestgpt_agent.protocol import (
    AgentAdapter,
    AgentManifest,
    AgentResult,
    Artifact,
    ErrorCategory,
    ErrorDetail,
    ExecutionHandle,
    ExecutionStatus,
    HealthcheckResult,
    PreparedTask,
    RunLayout,
    TaskSpec,
)
from pentestgpt_agent.protocol.contracts import utc_now

from .full_tools import MINIMAL_FULL_TOOLS
from .parser import (
    artifact_evidence,
    expired_finding_techniques,
    full_findings,
    load_full,
    load_triage,
    normalize_final_text,
    triage_finding,
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


class TrudiAdapter(AgentAdapter):
    agent_id = "trudi"

    def __init__(self, *, repo_root: Path | None = None, mode: str | None = None) -> None:
        self.repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.manifest = AgentManifest.load(Path(__file__).with_name("manifest.json"))
        self.executable = self.repo_root / self.manifest.start[0]
        self.runner = self.repo_root / self.manifest.start[1]
        self.server = Path(__file__).with_name("lite_server.py")
        self.full_runner = Path(__file__).with_name("full_runner.py")
        self.full_server = Path(__file__).with_name("full_server.py")
        self.claude = self.repo_root / ".runtime" / "claude-code" / "node_modules" / ".bin" / "claude"
        self.node_bin = self.repo_root / ".runtime" / "node-runtime" / "node_modules" / ".bin"
        self.mode = mode or os.environ.get("HUNTER_TRUDI_MODE", "lite")
        if self.mode not in {"lite", "full"}:
            raise ValueError("TRUDI mode must be 'lite' or 'full'")
        self._processes: dict[str, _Process] = {}

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        try:
            task_spec.validate()
            mode = self._mode_for(task_spec)
            if task_spec.domain != "dfir":
                return _unavailable(ErrorCategory.INVALID_TASK, "TRUDI requires domain='dfir'", "TRUDI_DOMAIN")
            target = Path(task_spec.target).resolve()
            if not target.is_file():
                return _unavailable(ErrorCategory.INVALID_TASK, f"TRUDI target is not a file: {target}", "TRUDI_TARGET")
            if mode == "full":
                return await self._full_healthcheck(task_spec)
            missing = [str(path) for path in (self.executable, self.runner, self.server) if not path.is_file()]
            if missing:
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, f"TRUDI runtime files are unavailable: {', '.join(missing)}", "TRUDI_RUNTIME")
            probe = await asyncio.create_subprocess_exec(
                str(self.executable),
                "-c",
                (
                    "import asyncio, runpy; "
                    f"scope=runpy.run_path({str(self.server)!r}); "
                    "print(len(asyncio.run(scope['mcp'].list_tools())))"
                ),
                cwd=self.repo_root,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await probe.communicate()
            if probe.returncode != 0:
                return _unavailable(ErrorCategory.DEPENDENCY_ERROR, f"TRUDI server import failed: {stderr.decode(errors='replace')[-500:]}", "TRUDI_IMPORT")
            return HealthcheckResult(True, {
                "executable": str(self.executable),
                "server": str(self.server),
                "tool_count": stdout.decode().strip(),
                "manifest": self.manifest.to_dict(),
                "reasoning_backend_ready": _reasoning_backend_ready(),
                "scope": "lightweight_file_triage",
            })
        except Exception as exc:
            return _unavailable(ErrorCategory.INVALID_TASK, str(exc), "TRUDI_HEALTHCHECK")

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        task_spec.validate()
        mode = self._mode_for(task_spec)
        if mode == "full":
            expected_sha256 = _expected_sha256(task_spec)
            if not expected_sha256:
                raise ValueError("TRUDI Full requires the Layer 1 SHA-256 in TaskSpec metadata")
            full_timeout = min(
                task_spec.timeout,
                float(os.environ.get("HUNTER_TRUDI_FULL_TIMEOUT", "1800")),
            )
            full_manifest = self.manifest.to_dict()
            full_manifest["timeout"] = full_timeout
            output = run_layout.artifacts / "trudi_full_result.json"
            case_dir = run_layout.artifacts / "trudi-case"
            command = [
                str(self.executable),
                str(self.full_runner),
                "--evidence", str(Path(task_spec.target).resolve()),
                "--expected-sha256", expected_sha256,
                "--case-id", task_spec.task_id,
                "--case-dir", str(case_dir),
                "--runtime-home", str(run_layout.root / "runtime" / "trudi-home"),
                "--output", str(output),
                "--primary-stdout", str(run_layout.logs / "trudi-primary.stdout.json"),
                "--primary-stderr", str(run_layout.logs / "trudi-primary.stderr.log"),
                "--claude", str(self.claude),
                "--node-bin", str(self.node_bin),
                "--lock", str(self.repo_root / ".runtime" / "trudi-full.lock"),
                "--max-turns", os.environ.get("HUNTER_TRUDI_MAX_TURNS", "60"),
                "--timeout", str(full_timeout),
            ]
            return PreparedTask(
                task_spec,
                run_layout,
                backend_input={"command": command, "output": str(output)},
                metadata={"manifest": full_manifest, "mode": "full", "scope": "autonomous_dfir"},
            )
        output = run_layout.artifacts / "trudi_result.json"
        case_dir = run_layout.artifacts / "trudi-case"
        command = [
            str(self.executable), str(self.runner),
            "--server", str(self.server),
            "--evidence", str(Path(task_spec.target).resolve()),
            "--case-dir", str(case_dir),
            "--output", str(output),
        ]
        if task_spec.metadata.get("export_evidence_artifact") is True:
            command.append("--export-evidence")
        return PreparedTask(
            task_spec,
            run_layout,
            backend_input={"command": command, "output": str(output)},
            metadata={"manifest": self.manifest.to_dict(), "mode": "lite", "scope": "lightweight_file_triage"},
        )

    async def run(self, prepared: PreparedTask) -> ExecutionHandle:
        stdout_path = prepared.run_layout.logs / "trudi.stdout.log"
        stderr_path = prepared.run_layout.logs / "trudi.stderr.log"
        stdout_stream = stdout_path.open("wb")
        stderr_stream = stderr_path.open("wb")
        try:
            process = await asyncio.create_subprocess_exec(
                *prepared.backend_input["command"],
                cwd=self.repo_root,
                env=os.environ.copy(),
                stdout=stdout_stream,
                stderr=stderr_stream,
                start_new_session=True,
            )
        except Exception:
            stdout_stream.close()
            stderr_stream.close()
            raise
        backend_id = f"trudi-{uuid.uuid4().hex}"
        started_at = utc_now()
        self._processes[backend_id] = _Process(process, stdout_stream, stderr_stream, stdout_path, stderr_path, started_at, time.monotonic())
        return ExecutionHandle(backend_id, started_at, {"pid": process.pid})

    async def collect(self, prepared: PreparedTask, handle: ExecutionHandle) -> AgentResult:
        context = self._processes.get(handle.backend_id)
        if context is None:
            raise RuntimeError("unknown TRUDI process handle")
        returncode = await context.process.wait()
        context.stdout_stream.close()
        context.stderr_stream.close()
        elapsed = time.monotonic() - context.started_monotonic
        self._processes.pop(handle.backend_id, None)
        output_path = Path(str(prepared.backend_input["output"]))
        if prepared.metadata.get("mode") == "full":
            return self._collect_full(
                prepared,
                context=context,
                returncode=returncode,
                elapsed=elapsed,
                output_path=output_path,
            )
        if returncode != 0 or not output_path.is_file():
            error_text = context.stderr_path.read_text(encoding="utf-8", errors="replace")
            return _failed(prepared, context.started_at, elapsed, returncode, error_text)
        try:
            value = load_triage(output_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _failed(prepared, context.started_at, elapsed, returncode, str(exc))
        artifacts = [Artifact.from_path("trudi-raw-result", "dfir_raw_result", output_path, producer=self.agent_id)]
        trace_path = Path(str(value["trace_path"]))
        if trace_path.is_file():
            artifacts.append(Artifact.from_path("trudi-trace", "dfir_execution_trace", trace_path, producer=self.agent_id))
        strings_path_value = value.get("strings_path")
        if strings_path_value and Path(str(strings_path_value)).is_file():
            artifacts.append(Artifact.from_path("trudi-strings", "extracted_strings", Path(str(strings_path_value)), producer=self.agent_id))
        exported_value = value.get("exported_evidence_path")
        if exported_value and Path(str(exported_value)).is_file():
            exported_path = Path(str(exported_value))
            with exported_path.open("rb") as stream:
                magic = stream.read(4)
            artifact_type = "suspect_binary" if magic == b"\x7fELF" else "exported_evidence"
            artifacts.append(Artifact.from_path("trudi-exported-evidence", artifact_type, exported_path, producer=self.agent_id))
        evidence = tuple(
            artifact_evidence(f"{artifact.artifact_id}-evidence", artifact.artifact_id, f"Original TRUDI output: {artifact.type}.")
            for artifact in artifacts
        )
        finding = triage_finding(value, tuple(item.evidence_id for item in evidence))
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=ExecutionStatus.SUCCESS,
            started_at=context.started_at,
            finished_at=utc_now(),
            summary="TRUDI completed real hash, stat, and strings triage of the evidence file.",
            findings=(finding,),
            evidence=evidence,
            artifacts=tuple(artifacts),
            metrics={"wall_seconds": elapsed, "tool_calls": 3, "reasoning_backend_used": False},
            raw_output={"returncode": returncode, "stdout_log": str(context.stdout_path), "stderr_log": str(context.stderr_path), "trudi": value},
        )

    def _mode_for(self, task_spec: TaskSpec) -> str:
        mode = str(task_spec.metadata.get("trudi_mode") or self.mode)
        if mode not in {"lite", "full"}:
            raise ValueError("TaskSpec metadata trudi_mode must be 'lite' or 'full'")
        return mode

    async def _full_healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        required = (self.executable, self.full_runner, self.full_server, self.claude)
        missing = [str(path) for path in required if not path.is_file()]
        node = self.node_bin / "node"
        if not node.is_file():
            missing.append(str(node))
        if missing:
            return _unavailable(
                ErrorCategory.DEPENDENCY_ERROR,
                f"TRUDI Full runtime files are unavailable: {', '.join(missing)}",
                "TRUDI_FULL_RUNTIME",
            )
        if not _deepseek_key_ready():
            return _unavailable(
                ErrorCategory.ENVIRONMENT_ERROR,
                "TRUDI Full requires DEEPSEEK_API_KEY; Lite fallback is disabled",
                "TRUDI_REASONING_UNAVAILABLE",
            )
        expected_sha256 = _expected_sha256(task_spec)
        if not expected_sha256:
            return _unavailable(
                ErrorCategory.INVALID_TASK,
                "TRUDI Full requires the Layer 1 SHA-256 in TaskSpec metadata",
                "TRUDI_FULL_SHA256",
            )
        environment = os.environ.copy()
        environment["PATH"] = f"{self.node_bin}:{environment.get('PATH', '')}"
        version_probe = await asyncio.create_subprocess_exec(
            str(self.claude), "--version",
            cwd=self.repo_root,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        version_stdout, version_stderr = await version_probe.communicate()
        if version_probe.returncode != 0:
            return _unavailable(
                ErrorCategory.DEPENDENCY_ERROR,
                f"Claude Code runtime failed: {version_stderr.decode(errors='replace')[-300:]}",
                "TRUDI_CLAUDE_CODE",
            )
        node_probe = await asyncio.create_subprocess_exec(
            str(node), "--version",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        node_stdout, _node_stderr = await node_probe.communicate()
        match = re.match(r"v(\d+)", node_stdout.decode().strip())
        if node_probe.returncode != 0 or not match or int(match.group(1)) < 22:
            return _unavailable(
                ErrorCategory.DEPENDENCY_ERROR,
                "Claude Code requires the task-scoped Node.js 22+ runtime",
                "TRUDI_NODE_RUNTIME",
            )
        return HealthcheckResult(True, {
            "mode": "full",
            "scope": "autonomous_dfir",
            "claude_code_version": version_stdout.decode().strip(),
            "claude_code_path": str(self.claude.resolve()),
            "node_version": node_stdout.decode().strip(),
            "node_path": str(node.resolve()),
            "primary_provider": "deepseek_anthropic_compatible",
            "primary_model": "deepseek-v4-flash",
            "reason_provider": "deepseek_openai_compatible",
            "dair_provider": "deepseek_openai_compatible",
            "primary_model_ready": True,
            "reason_backend_ready": True,
            "dair_backend_ready": True,
            "available_tool_count": len(MINIMAL_FULL_TOOLS),
            "available_tools": sorted(MINIMAL_FULL_TOOLS),
            "session_isolation": "task_home_plus_serial_flock",
            "lite_fallback": False,
        })

    def _collect_full(
        self,
        prepared: PreparedTask,
        *,
        context: _Process,
        returncode: int,
        elapsed: float,
        output_path: Path,
    ) -> AgentResult:
        if not output_path.is_file():
            detail = context.stderr_path.read_text(encoding="utf-8", errors="replace")
            return _failed_full(
                prepared, context.started_at, elapsed, returncode,
                code="TRUDI_FULL_RESULT_MISSING",
                category=ErrorCategory.BACKEND_ERROR,
                message="TRUDI Full produced no qualification result.",
                detail=detail,
            )
        try:
            value = load_full(output_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return _failed_full(
                prepared, context.started_at, elapsed, returncode,
                code="TRUDI_FULL_RESULT_MALFORMED",
                category=ErrorCategory.BACKEND_ERROR,
                message="TRUDI Full produced a malformed qualification result.",
                detail=str(exc),
            )

        artifacts = [
            Artifact.from_path("trudi-full-result", "dfir_full_result", output_path, producer=self.agent_id)
        ]
        case_dir = prepared.run_layout.artifacts / "trudi-case"
        if case_dir.is_dir():
            for path in sorted(case_dir.rglob("*")):
                if not path.is_file() or ".claude" in path.parts:
                    continue
                relative = path.relative_to(case_dir)
                artifact_id = _full_artifact_id(relative)
                if path.name.endswith("_report.md"):
                    artifact_type = "dfir_case_report"
                elif "trace" in path.name and path.suffix == ".json":
                    artifact_type = "dfir_execution_trace"
                elif "trace" in path.name:
                    artifact_type = "dfir_trace_export"
                elif relative.parts and relative.parts[0] == "exports":
                    artifact_type = "dfir_export"
                else:
                    artifact_type = "dfir_analysis_artifact"
                artifacts.append(Artifact.from_path(artifact_id, artifact_type, path, producer=self.agent_id))

        evidence = tuple(
            artifact_evidence(
                f"{artifact.artifact_id}-evidence",
                artifact.artifact_id,
                f"TRUDI Full official output: {artifact.type}.",
            )
            for artifact in artifacts
        )
        evidence_refs = tuple(item.evidence_id for item in evidence)
        findings = full_findings(value, evidence_refs)
        trace = value.get("trace", {})
        success = value.get("success") is True
        failure = value.get("failure") if isinstance(value.get("failure"), dict) else {}
        if success:
            status = ExecutionStatus.SUCCESS
            error = None
        else:
            category = _error_category(str(failure.get("category") or "backend_error"))
            if category is ErrorCategory.TIMEOUT:
                status = ExecutionStatus.TIMEOUT
            elif trace.get("entry_count", 0):
                status = ExecutionStatus.PARTIAL
            else:
                status = ExecutionStatus.FAILED
            error = ErrorDetail(
                category,
                str(
                    failure.get("message")
                    or "TRUDI Full did not satisfy every autonomous-investigation success condition."
                ),
                code=str(failure.get("code") or "TRUDI_FULL_INCOMPLETE"),
                retryable=bool(failure.get("retryable", False)),
                metadata={"returncode": returncode},
            )
        primary = value.get("primary", {}) if isinstance(value.get("primary"), dict) else {}
        primary_result = str(primary.get("result") or "").strip()
        expired_techniques = expired_finding_techniques(value)
        primary_result = normalize_final_text(primary_result, expired_techniques)
        safe_primary = dict(primary)
        if "result" in safe_primary:
            safe_primary["result"] = primary_result
        summary = (
            primary_result[:2000]
            if primary_result
            else (findings[0].description[:2000] if findings else "TRUDI Full investigation did not produce a final conclusion.")
        )
        turn_budget = (
            value.get("turn_budget", {})
            if isinstance(value.get("turn_budget"), dict)
            else {}
        )
        metrics = {
            "mode": "full",
            "primary_runtime_used": bool(value.get("primary_runtime_used")),
            "primary_model": value.get("primary_model"),
            "primary_model_calls": int(value.get("primary_model_calls", 0) or 0),
            "reason_backend_used": bool(value.get("reason_backend_used")),
            "dair_backend_used": bool(value.get("dair_backend_used")),
            "reason_calls": int(trace.get("reason_calls", 0) or 0),
            "dair_calls": int(trace.get("dair_calls", 0) or 0),
            "mcp_tool_calls": int(trace.get("mcp_tool_calls", 0) or 0),
            "successful_mcp_tool_calls": int(trace.get("successful_mcp_tool_calls", 0) or 0),
            "evidence_count": len(evidence),
            "finding_count": len(findings),
            "available_tool_count": len(MINIMAL_FULL_TOOLS),
            "duration_seconds": float(value.get("duration_seconds", elapsed) or elapsed),
            "primary_turn_budget": int(turn_budget.get("total", 0) or 0),
            "investigation_turn_budget": int(
                turn_budget.get("investigation_budget", 0) or 0
            ),
            "completion_turns_reserved": int(
                turn_budget.get("completion_reserved", 0) or 0
            ),
            "investigation_turns_used": int(
                turn_budget.get("investigation_used", 0) or 0
            ),
            "completion_turns_used": int(turn_budget.get("completion_used", 0) or 0),
            "completion_phase_used": bool(turn_budget.get("completion_phase_used")),
        }
        return AgentResult(
            task_id=prepared.task_spec.task_id,
            agent_id=self.agent_id,
            domain=prepared.task_spec.domain,
            status=status,
            started_at=context.started_at,
            finished_at=utc_now(),
            summary=summary,
            findings=findings,
            evidence=evidence,
            artifacts=tuple(artifacts),
            metrics=metrics,
            error=error,
            raw_output={
                "mode": "full",
                "returncode": returncode,
                "runner_stdout_log": str(context.stdout_path),
                "runner_stderr_log": str(context.stderr_path),
                "primary": safe_primary,
                "trace": {key: item for key, item in trace.items() if key != "findings"},
                "paths": value.get("paths", {}),
            },
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


def _reasoning_backend_ready() -> bool:
    return bool(
        os.environ.get("ANTHROPIC_API_KEY")
        or (os.environ.get("REASON_URL") and os.environ.get("DAIR_URL"))
    )


def _deepseek_key_ready() -> bool:
    return bool(
        os.environ.get("HUNTER_TRUDI_DEEPSEEK_API_KEY")
        or os.environ.get("DEEPSEEK_API_KEY")
    )


def _expected_sha256(task_spec: TaskSpec) -> str:
    file_type = task_spec.metadata.get("file_type")
    if isinstance(file_type, dict):
        value = file_type.get("sha256")
        if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
            return value.lower()
    value = task_spec.metadata.get("sha256")
    if isinstance(value, str) and re.fullmatch(r"[0-9a-fA-F]{64}", value):
        return value.lower()
    return ""


def _full_artifact_id(relative: Path) -> str:
    value = relative.as_posix()
    sanitized = re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-") or "artifact"
    candidate = f"trudi-{sanitized}"
    # Evidence IDs append "-evidence" and share Protocol v1's 128-byte limit.
    if len(candidate) <= 119:
        return candidate
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:8]
    return f"{candidate[:110]}-{digest}"


def _error_category(value: str) -> ErrorCategory:
    try:
        return ErrorCategory(value)
    except ValueError:
        return ErrorCategory.BACKEND_ERROR


def _unavailable(category: ErrorCategory, message: str, code: str) -> HealthcheckResult:
    return HealthcheckResult(False, {"code": code}, ErrorDetail(category, message, code=code))


def _failed(prepared: PreparedTask, started_at: str, elapsed: float, returncode: int, detail: str) -> AgentResult:
    summary = f"TRUDI lightweight triage exited with status {returncode}."
    return AgentResult(
        task_id=prepared.task_spec.task_id,
        agent_id="trudi",
        domain=prepared.task_spec.domain,
        status=ExecutionStatus.FAILED,
        started_at=started_at,
        finished_at=utc_now(),
        summary=summary,
        metrics={"wall_seconds": elapsed},
        error=ErrorDetail(ErrorCategory.BACKEND_ERROR, summary, code="TRUDI_PROCESS_FAILED", metadata={"returncode": returncode, "detail": detail[-2000:]}),
        raw_output={"returncode": returncode, "detail": detail[-4000:]},
    )


def _failed_full(
    prepared: PreparedTask,
    started_at: str,
    elapsed: float,
    returncode: int,
    *,
    code: str,
    category: ErrorCategory,
    message: str,
    detail: str,
) -> AgentResult:
    return AgentResult(
        task_id=prepared.task_spec.task_id,
        agent_id="trudi",
        domain=prepared.task_spec.domain,
        status=ExecutionStatus.FAILED,
        started_at=started_at,
        finished_at=utc_now(),
        summary=message,
        metrics={"mode": "full", "wall_seconds": elapsed},
        error=ErrorDetail(category, message, code=code, metadata={"returncode": returncode}),
        raw_output={"mode": "full", "returncode": returncode, "detail": detail[-4000:]},
    )

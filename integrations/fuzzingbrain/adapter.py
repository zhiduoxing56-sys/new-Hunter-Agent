"""Protocol-v1 adapter for the isolated local FuzzingBrain checkout."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import sqlite3
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Any

from pentestgpt_agent.protocol import (
    AgentAdapter, AgentResult, Artifact, ErrorCategory, ErrorDetail, Evidence,
    ExecutionHandle, ExecutionStatus, Finding, HealthcheckResult, PreparedTask,
    RunLayout, TaskSpec,
)
from pentestgpt_agent.protocol.contracts import utc_now

from .parser import iter_result_files, load_json, parse_outcome, safe_identifier
from .runner import terminate_process_group


@dataclass
class _Process:
    process: asyncio.subprocess.Process
    stdout: BinaryIO
    stderr: BinaryIO
    stdout_path: Path
    stderr_path: Path
    started_at: str
    started_monotonic: float
    cancelled: bool = False


class FuzzingBrainAdapter(AgentAdapter):
    agent_id = "fuzzingbrain"

    def __init__(self, *, repo_root: Path | None = None) -> None:
        self.repo_root = (repo_root or Path(__file__).resolve().parents[2]).resolve()
        self.backend_root = self.repo_root / "third_party/fuzzingbrain"
        self.python = self.backend_root / ".venv/bin/python"
        self.launcher = self.repo_root / "scripts/fuzzingbrain_run.py"
        self.config_db = self.repo_root / ".runtime/kong/config/config.db"
        self._processes: dict[str, _Process] = {}

    async def healthcheck(self, task_spec: TaskSpec) -> HealthcheckResult:
        try:
            task_spec.validate()
            if task_spec.domain != "vulnerability_research":
                return self._unavailable(ErrorCategory.INVALID_TASK, "FuzzingBrain requires domain='vulnerability_research'", "FUZZINGBRAIN_DOMAIN")
            target = Path(task_spec.target).resolve()
            if not target.exists():
                return self._unavailable(ErrorCategory.INVALID_TASK, "FuzzingBrain target does not exist", "FUZZINGBRAIN_TARGET")
            missing = [str(p) for p in (self.python, self.launcher, self.backend_root / "fuzzingbrain/main.py") if not p.is_file()]
            if missing:
                return self._unavailable(ErrorCategory.DEPENDENCY_ERROR, "FuzzingBrain runtime is incomplete", "FUZZINGBRAIN_RUNTIME", {"missing": missing})
            checks = await asyncio.gather(self._tcp(27018), self._tcp(6380), self._docker())
            names = ("mongodb", "redis", "docker")
            unavailable = [name for name, ok in zip(names, checks) if not ok]
            if unavailable:
                return self._unavailable(ErrorCategory.ENVIRONMENT_ERROR, "FuzzingBrain services are unavailable", "FUZZINGBRAIN_SERVICES", {"unavailable": unavailable})
            if not os.environ.get("DEEPSEEK_API_KEY") and not self._has_unified_key():
                return self._unavailable(ErrorCategory.ENVIRONMENT_ERROR, "Unified DeepSeek credential is unavailable", "FUZZINGBRAIN_DEEPSEEK_KEY")
            return HealthcheckResult(True, {"python": str(self.python), "services": {name: "healthy" for name in names}, "credential_source": "process_environment" if os.environ.get("DEEPSEEK_API_KEY") else "kong_sqlite_child_process"})
        except Exception as exc:
            return self._unavailable(ErrorCategory.ENVIRONMENT_ERROR, str(exc), "FUZZINGBRAIN_HEALTHCHECK")

    async def prepare(self, task_spec: TaskSpec, run_layout: RunLayout) -> PreparedTask:
        task_spec.validate()
        source = Path(task_spec.target).resolve()
        self._validate_source(source, task_spec)
        workspace = run_layout.artifacts / "fuzzingbrain-workspace"
        workspace.mkdir(parents=True, exist_ok=True)
        is_fixture = (source / "fuzz-tooling" / "projects").is_dir() and (source / "repo").is_dir()
        if is_fixture:
            # Complete local OSS-Fuzz fixture: copy as the workspace itself so
            # FuzzingBrain finds repo/ and fuzz-tooling/ in place. The OSS-Fuzz
            # project name comes from the fixture's projects/ directory.
            shutil.copytree(
                source, workspace, symlinks=False, dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(
                    ".git", ".venv", "__pycache__", "build",
                    "worker_workspace", "results", "logs",
                ),
            )
            project_name = next(
                (p.name for p in (source / "fuzz-tooling" / "projects").iterdir() if p.is_dir()),
                safe_identifier(source.stem or source.name),
            )
            repo = workspace / "repo"
        else:
            # Plain source tree: copy it under repo/ and let FuzzingBrain
            # provision the OSS-Fuzz fuzz-tooling.
            repo = workspace / "repo"
            if source.is_dir():
                shutil.copytree(source, repo, symlinks=False, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", ".venv", "__pycache__"))
            else:
                repo.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, repo / source.name)
            project_name = safe_identifier(source.stem or source.name)
        (workspace / "results").mkdir(exist_ok=True)
        task_type = str(task_spec.metadata.get("fuzzingbrain_task_type", "pov"))
        if task_type not in {"pov", "patch", "pov-patch", "harness"}:
            raise ValueError("unsupported FuzzingBrain task type")
        timeout_minutes = max(1, int(task_spec.timeout / 60))
        backend_task_id = task_spec.task_id
        if not (
            len(backend_task_id) == 24
            and all(character in "0123456789abcdefABCDEF" for character in backend_task_id)
        ):
            # FuzzingBrain stores tasks under an ObjectId; map arbitrary
            # protocol task ids to a valid 24-hex backend id.
            backend_task_id = uuid.uuid4().hex[:24]
        command = [str(self.python), str(self.launcher), "--task-id", backend_task_id, "--project", project_name, "--ossfuzz-project", project_name, "--workspace", str(workspace), "--in-place", "--task-type", task_type, "--scan-mode", str(task_spec.metadata.get("fuzzingbrain_scan_mode", "full")), "--timeout", str(timeout_minutes), "--budget", str(task_spec.model_budget if task_spec.model_budget is not None else task_spec.budget or 50.0)]
        return PreparedTask(task_spec, run_layout, {"command": command, "workspace": str(workspace), "task_id": backend_task_id}, {"backend": "FuzzingBrain", "input_copy": str(repo), "secret_injection": "child_process_only"})

    async def run(self, prepared: PreparedTask) -> ExecutionHandle:
        stdout_path = prepared.run_layout.logs / "fuzzingbrain.stdout.log"
        stderr_path = prepared.run_layout.logs / "fuzzingbrain.stderr.log"
        stdout, stderr = stdout_path.open("wb"), stderr_path.open("wb")
        env = {**os.environ, "MONGODB_URL": "mongodb://127.0.0.1:27018", "MONGODB_DB": "fuzzingbrain", "REDIS_URL": "redis://127.0.0.1:6380/0", "LLM_DEFAULT_MODEL": "deepseek-v4-flash"}
        if not env.get("DEEPSEEK_API_KEY"):
            env["DEEPSEEK_API_KEY"] = self._read_unified_key()
        process = await asyncio.create_subprocess_exec(*prepared.backend_input["command"], cwd=self.repo_root, env=env, stdout=stdout, stderr=stderr, start_new_session=True)
        backend_id = f"fuzzingbrain-{uuid.uuid4().hex}"
        started = utc_now()
        self._processes[backend_id] = _Process(process, stdout, stderr, stdout_path, stderr_path, started, time.monotonic())
        return ExecutionHandle(backend_id, started, {"pid": process.pid})

    async def collect(self, prepared: PreparedTask, handle: ExecutionHandle) -> AgentResult:
        context = self._processes.pop(handle.backend_id)
        returncode = await context.process.wait()
        context.stdout.close(); context.stderr.close()
        stderr = context.stderr_path.read_text(encoding="utf-8", errors="replace")
        results = Path(prepared.backend_input["workspace"]) / "results"
        report_path = next((p for p in (results / "report.json", results / "summary.json") if p.is_file()), None)
        report = load_json(report_path) if report_path else None
        backend_task_id = str(prepared.backend_input.get("task_id") or prepared.task_spec.task_id)
        task_document, pov_documents = self._load_documents(backend_task_id)
        if not pov_documents:
            # The filesystem is the authoritative evidence even when the
            # runtime lacks pymongo: any packaged PoV blob means the backend
            # reproduced a trigger. MongoDB remains an enrichment when present.
            pov_documents = tuple(
                {
                    "is_successful": True,
                    "harness_name": "parser_fuzzer",
                    "blob_path": str(path),
                }
                for kind, path in iter_result_files(results)
                if kind == "trigger_sample"
            )
        outcome = parse_outcome(
            returncode=returncode,
            stderr=stderr,
            report=report if isinstance(report, dict) else None,
            task_document=task_document,
            pov_documents=pov_documents,
            cancelled=context.cancelled,
        )
        artifacts: list[Artifact] = []
        evidence: list[Evidence] = []
        for index, (kind, path) in enumerate(iter_result_files(results)):
            artifact_id = f"fuzzingbrain-{kind}-{index}"
            artifact = Artifact.from_path(artifact_id, kind, path, producer=self.agent_id, relative_path=path.relative_to(results).as_posix())
            artifacts.append(artifact)
            evidence.append(Evidence(f"{artifact_id}-evidence", "backend_output", self.agent_id, f"FuzzingBrain {kind} output.", artifact_ref=artifact_id))
        findings: tuple[Finding, ...] = ()
        trigger_refs = tuple(item.evidence_id for item, artifact in zip(evidence, artifacts) if artifact.type == "trigger_sample")
        if trigger_refs:
            findings = (Finding("fuzzingbrain-reproduced-vulnerability", "vulnerability", "Reproduced vulnerability trigger", outcome.summary, evidence_refs=trigger_refs),)
        error = ErrorDetail(outcome.error_category, outcome.summary, outcome.error_code, outcome.retryable) if outcome.error_category else None
        return AgentResult(prepared.task_spec.task_id, self.agent_id, prepared.task_spec.domain, outcome.status, context.started_at, utc_now(), outcome.summary, findings=findings, evidence=tuple(evidence), artifacts=tuple(artifacts), metrics={"wall_seconds": time.monotonic() - context.started_monotonic, "returncode": returncode, "artifact_count": len(artifacts), "pov_document_count": len(pov_documents)}, error=error, raw_output={"returncode": returncode, "stdout_log": str(context.stdout_path), "stderr_log": str(context.stderr_path), "backend_status": (task_document or report or {}).get("status"), "task_document": task_document, "pov_documents": list(pov_documents)})

    async def stop(self, prepared: PreparedTask | None, *, reason: str) -> None:
        for context in tuple(self._processes.values()):
            context.cancelled = reason in {"cancelled", "user_cancel", "user cancellation"}
            await terminate_process_group(context.process)
            context.stdout.close(); context.stderr.close()

    def _validate_source(self, source: Path, task: TaskSpec) -> None:
        allowed = tuple(Path(p).resolve() for p in ((task.authorization.allowed_read_paths if task.authorization else ()) or (task.target,)))
        if not any(source == path or source.is_relative_to(path) for path in allowed):
            raise ValueError("FuzzingBrain source is outside allowed_read_paths")
        if source.is_symlink():
            raise ValueError("FuzzingBrain refuses symlink targets")

    def _has_unified_key(self) -> bool:
        try: return bool(self._read_unified_key())
        except Exception: return False

    def _read_unified_key(self) -> str:
        with sqlite3.connect(f"file:{self.config_db}?mode=ro", uri=True) as db:
            row = db.execute("SELECT value FROM config WHERE key = ?", ("custom_api_key",)).fetchone()
        if not row or not isinstance(row[0], str) or not row[0].strip(): raise RuntimeError("unified DeepSeek credential is missing")
        return row[0].strip()

    @staticmethod
    def _load_documents(task_id: str) -> tuple[dict[str, Any] | None, tuple[dict[str, Any], ...]]:
        """Read the task/PoV schema without making MongoDB a Python import dependency."""
        try:
            from bson import json_util
            from pymongo import MongoClient

            client = MongoClient("mongodb://127.0.0.1:27018", serverSelectionTimeoutMS=1500)
            database = client["fuzzingbrain"]
            task = database.tasks.find_one({"task_id": task_id})
            if task is None:
                try:
                    from bson import ObjectId
                    if len(task_id) == 24:
                        task = database.tasks.find_one({"_id": ObjectId(task_id)})
                except Exception:
                    pass
            reference = task.get("_id") if task else task_id
            povs = list(database.povs.find({"task_id": {"$in": [reference, task_id]}}))
            normalized_task = json.loads(json_util.dumps(task)) if task else None
            normalized_povs = tuple(json.loads(json_util.dumps(item)) for item in povs)
            client.close()
            return normalized_task, normalized_povs
        except Exception:
            return None, ()

    @staticmethod
    async def _tcp(port: int) -> bool:
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=2); writer.close(); await writer.wait_closed(); return True
        except (OSError, TimeoutError): return False

    @staticmethod
    async def _docker() -> bool:
        try:
            proc = await asyncio.create_subprocess_exec("docker", "info", stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL); return await proc.wait() == 0
        except OSError: return False

    @staticmethod
    def _unavailable(category: ErrorCategory, message: str, code: str, details: dict[str, Any] | None = None) -> HealthcheckResult:
        return HealthcheckResult(False, details or {}, ErrorDetail(category, message, code=code, metadata=details or {}))

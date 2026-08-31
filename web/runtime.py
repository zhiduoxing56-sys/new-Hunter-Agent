"""Persistent Web orchestration over the existing Hunter intake and Analysis subsystem."""

from __future__ import annotations

import asyncio
import json
import os
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from typing import Protocol

from integrations.analysis_supervisor import AnalysisSupervisor
from integrations.hunter_brain import build_analysis_brain_executor
from integrations.kong import KongAdapter
from integrations.trudi import TrudiAdapter

from pentestgpt_agent.identifiers import validate_opaque_id
from pentestgpt_agent.intake import IntakeLimits, prepare_task
from pentestgpt_agent.protocol import AgentResult, ExecutionStatus, RunLayout, TaskSpec
from pentestgpt_agent.protocol.io import atomic_write_json, read_json_object


EXECUTION_MODES = frozenset(
    {
        "automatic",
        "autonomous",
        "force_dfir",
        "force_reverse",
        "force_pentest",
        "force_vulnerability_research",
    }
)
FORCED_DOMAINS = {
    "force_dfir": "dfir",
    "force_reverse": "reverse",
    "force_pentest": "pentest",
    "force_vulnerability_research": "vulnerability_research",
}


class WebTaskExecutor(Protocol):
    async def execute(self, task_spec: TaskSpec) -> AgentResult: ...


def utc_now() -> str:
    return datetime.now(UTC).isoformat()


@dataclass(frozen=True)
class WebConfig:
    project_root: Path
    runs_root: Path
    staging_root: Path
    max_upload_bytes: int = 1_073_741_824
    worker_count: int = 2

    @classmethod
    def from_environment(cls) -> WebConfig:
        project_root = Path(__file__).resolve().parents[1]
        runs_root = Path(
            os.environ.get("HUNTER_RUNS_ROOT", project_root / "runs")
        ).resolve()
        staging_root = Path(
            os.environ.get("HUNTER_STAGING_ROOT", project_root / ".runtime/web-staging")
        ).resolve()
        return cls(
            project_root=project_root,
            runs_root=runs_root,
            staging_root=staging_root,
            max_upload_bytes=int(
                os.environ.get("HUNTER_WEB_MAX_UPLOAD_BYTES", 1_073_741_824)
            ),
            worker_count=int(os.environ.get("HUNTER_WEB_WORKERS", 2)),
        )

    def ensure(self) -> None:
        if self.max_upload_bytes <= 0 or self.worker_count <= 0:
            raise ValueError("Web upload limit and worker count must be positive")
        self.runs_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.staging_root.mkdir(parents=True, exist_ok=True, mode=0o700)


class HunterRuntime:
    """Small in-process dispatcher whose display state is reconstructable from runs/."""

    def __init__(
        self,
        config: WebConfig | None = None,
        *,
        supervisor: AnalysisSupervisor | None = None,
        autonomous_executor: WebTaskExecutor | None = None,
    ) -> None:
        self.config = config or WebConfig.from_environment()
        self.config.ensure()
        self.supervisor = supervisor or AnalysisSupervisor(
            kong_adapter=KongAdapter(repo_root=self.config.project_root),
            trudi_adapter=TrudiAdapter(repo_root=self.config.project_root),
            runs_root=self.config.runs_root,
        )
        self.autonomous_executor: WebTaskExecutor | None
        if autonomous_executor is not None:
            self.autonomous_executor = autonomous_executor
        else:
            try:
                self.autonomous_executor = build_analysis_brain_executor(
                    repo_root=self.config.project_root,
                    runs_root=self.config.runs_root,
                )
            except ValueError:
                self.autonomous_executor = None
        self._executor = ThreadPoolExecutor(
            max_workers=self.config.worker_count, thread_name_prefix="hunter-analysis"
        )
        self._active: set[str] = set()
        self._lock = threading.Lock()

    def prepare_upload(
        self,
        staging_path: Path,
        *,
        original_filename: str,
        upload_size: int,
        execution_mode: str = "automatic",
        goal: str | None = None,
    ) -> TaskSpec:
        if execution_mode not in EXECUTION_MODES:
            raise ValueError(f"unsupported execution mode: {execution_mode}")
        task_id = f"web-{uuid.uuid4().hex}"
        spec = prepare_task(
            staging_path,
            runs_root=self.config.runs_root,
            allowed_roots=(self.config.staging_root,),
            task_id=task_id,
            limits=IntakeLimits(max_input_bytes=self.config.max_upload_bytes),
        )
        metadata = {**spec.metadata, "hunter_execution_mode": execution_mode}
        domain = FORCED_DOMAINS.get(execution_mode, spec.domain)
        spec = replace(spec, domain=domain, goal=goal.strip() if goal and goal.strip() else spec.goal, metadata=metadata)
        spec.validate()
        assert spec.workspace is not None
        atomic_write_json(Path(spec.workspace) / "task.json", spec.to_dict())
        self._write_web_metadata(
            spec,
            {
                "original_filename": original_filename,
                "upload_size_bytes": upload_size,
                "accepted_at": utc_now(),
                "execution_mode": execution_mode,
            },
        )
        self._write_status(spec.task_id, "queued", stage="analysis_queued")
        return spec

    def submit(self, task_spec: TaskSpec) -> None:
        with self._lock:
            if task_spec.task_id in self._active:
                return
            self._active.add(task_spec.task_id)
        try:
            self._executor.submit(self._execute_sync, task_spec)
        except Exception as exc:
            with self._lock:
                self._active.discard(task_spec.task_id)
            self._write_status(
                task_spec.task_id,
                "failed",
                stage="background_submit",
                error={
                    "category": "environment_error",
                    "code": "WEB_BACKGROUND_SUBMIT_FAILED",
                    "message": f"Could not start background analysis: {type(exc).__name__}",
                },
            )
            raise

    def _execute_sync(self, task_spec: TaskSpec) -> None:
        mode = str(task_spec.metadata.get("hunter_execution_mode", "automatic"))
        backend = "hunter_brain" if mode == "autonomous" else backend_for_domain(task_spec.domain)
        self._write_status(
            task_spec.task_id,
            "running",
            stage="analysis_backend",
            backend=backend,
        )
        try:
            if mode == "autonomous":
                if self.autonomous_executor is None:
                    raise RuntimeError("autonomous Hunter Brain executor is not configured")
                result = asyncio.run(self.autonomous_executor.execute(task_spec))
            else:
                result = asyncio.run(self.supervisor.execute(task_spec))
            status = status_from_result(result)
            self._write_status(
                task_spec.task_id,
                status,
                stage="analysis_complete",
                backend=(None if status == "unsupported_domain" else result.agent_id),
                error=result.error.to_dict() if result.error is not None else None,
            )
        except Exception as exc:
            self._write_status(
                task_spec.task_id,
                "failed",
                stage="analysis_backend",
                backend=backend,
                error={
                    "category": "backend_error",
                    "code": "WEB_BACKGROUND_EXECUTION_FAILED",
                    "message": f"Background analysis failed: {type(exc).__name__}: {exc}",
                },
            )
        finally:
            with self._lock:
                self._active.discard(task_spec.task_id)

    def task_payload(self, task_id: str) -> dict[str, Any]:
        task, layout = self.load_task(task_id)
        web_metadata = self._read_optional(layout.root / "web_task.json")
        status = self.status_payload(task_id, task=task, layout=layout)
        file_type = task.metadata.get("file_type", {})
        file_metadata = task.metadata.get("file", {})
        return {
            "task_id": task.task_id,
            "status": status["status"],
            "stage": status.get("stage"),
            "backend": status.get("backend") or backend_for_domain(task.domain),
            "execution_mode": web_metadata.get(
                "execution_mode", task.metadata.get("hunter_execution_mode", "automatic")
            ),
            "domain": task.domain,
            "original_filename": web_metadata.get(
                "original_filename",
                task.input_object.source_name if task.input_object else None,
            ),
            "upload_size_bytes": web_metadata.get("upload_size_bytes"),
            "file_type": file_type.get("normalized_type"),
            "file_description": file_type.get("magic_raw"),
            "mime_type": file_type.get("mime_type"),
            "sha256": file_type.get("sha256"),
            "binary": file_metadata.get("binary"),
            "created_at": task.created_at,
            "error": status.get("error"),
            "result_available": layout.result_json.is_file(),
        }

    def status_payload(
        self,
        task_id: str,
        *,
        task: TaskSpec | None = None,
        layout: RunLayout | None = None,
    ) -> dict[str, Any]:
        loaded_task, loaded_layout = (
            (task, layout)
            if task is not None and layout is not None
            else self.load_task(task_id)
        )
        assert loaded_task is not None and loaded_layout is not None
        if loaded_layout.result_json.is_file():
            result = loaded_layout.read_result()
            return {
                "task_id": task_id,
                "status": status_from_result(result),
                "stage": "analysis_complete",
                "backend": None
                if result.error and result.error.code == "ANALYSIS_DOMAIN_UNSUPPORTED"
                else result.agent_id,
                "error": result.error.to_dict() if result.error is not None else None,
            }
        persisted = self._read_optional(loaded_layout.root / "web_status.json")
        status = str(persisted.get("status", "failed"))
        with self._lock:
            active = task_id in self._active
        if status in {"queued", "running"} and not active:
            return {
                "task_id": task_id,
                "status": "failed",
                "stage": "process_recovery",
                "backend": persisted.get("backend")
                or backend_for_domain(loaded_task.domain),
                "error": {
                    "category": "environment_error",
                    "code": "WEB_PROCESS_INTERRUPTED",
                    "message": "The Web process stopped before this task produced a result.",
                },
            }
        return {"task_id": task_id, **persisted}

    def result_payload(self, task_id: str) -> dict[str, Any]:
        _task, layout = self.load_task(task_id)
        result = layout.read_result()
        layout.validate_result_references(result)
        value = result.to_dict()
        artifacts: list[dict[str, Any]] = []
        for artifact in result.artifacts:
            item = artifact.to_dict()
            relative = (
                Path(artifact.path).resolve().relative_to(layout.artifacts.resolve())
            )
            item["download_url"] = (
                f"/api/tasks/{task_id}/artifacts/{relative.as_posix()}"
            )
            artifacts.append(item)
        value["artifacts"] = artifacts
        value["web_status"] = status_from_result(result)
        return value

    def events_payload(self, task_id: str) -> list[dict[str, Any]]:
        _task, layout = self.load_task(task_id)
        return [event.to_dict() for event in layout.event_log().read_all()]

    def artifact_path(self, task_id: str, artifact_path: str) -> tuple[Path, str]:
        _task, layout = self.load_task(task_id)
        if not layout.result_json.is_file():
            raise FileNotFoundError("task result is not available")
        result = layout.read_result()
        layout.validate_result_references(result)
        artifacts_root = layout.artifacts.resolve()
        relative = PurePosixPath(artifact_path.replace("\\", "/"))
        if (
            not artifact_path
            or artifact_path.startswith(("/", "\\"))
            or "\\" in artifact_path
            or ".." in relative.parts
        ):
            raise PermissionError("artifact path traversal is forbidden")
        requested = layout.artifacts / artifact_path
        resolved = requested.resolve(strict=True)
        if (
            requested.is_symlink()
            or requested != resolved
            or not resolved.is_relative_to(artifacts_root)
        ):
            raise PermissionError("artifact path escapes this task")
        matched = next(
            (
                artifact
                for artifact in result.artifacts
                if Path(artifact.path).resolve() == resolved
            ),
            None,
        )
        if matched is None or not resolved.is_file():
            raise FileNotFoundError("artifact is not referenced by this task result")
        return resolved, matched.type

    def load_task(self, task_id: str) -> tuple[TaskSpec, RunLayout]:
        validate_opaque_id(task_id, label="task_id")
        task_path = self.config.runs_root / task_id / "task.json"
        if not task_path.is_file():
            raise FileNotFoundError(task_id)
        task = TaskSpec.from_dict(read_json_object(task_path))
        return task, RunLayout.ensure(self.config.runs_root, task)

    def wait_for_idle(self, task_id: str, timeout: float = 10.0) -> None:
        import time

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._lock:
                if task_id not in self._active:
                    return
            time.sleep(0.01)
        raise TimeoutError(f"task did not finish: {task_id}")

    def close(self, *, wait: bool = True) -> None:
        self._executor.shutdown(wait=wait, cancel_futures=not wait)

    def _write_status(
        self,
        task_id: str,
        status: str,
        *,
        stage: str,
        backend: str | None = None,
        error: dict[str, Any] | None = None,
    ) -> None:
        atomic_write_json(
            self.config.runs_root / task_id / "web_status.json",
            {
                "status": status,
                "stage": stage,
                "backend": backend,
                "error": error,
                "updated_at": utc_now(),
                "process_id": os.getpid(),
            },
        )

    @staticmethod
    def _write_web_metadata(task: TaskSpec, value: dict[str, Any]) -> None:
        assert task.workspace is not None
        atomic_write_json(Path(task.workspace) / "web_task.json", value)

    @staticmethod
    def _read_optional(path: Path) -> dict[str, Any]:
        if not path.is_file():
            return {}
        try:
            return read_json_object(path)
        except (OSError, ValueError, json.JSONDecodeError):
            return {}


def backend_for_domain(domain: str) -> str | None:
    return {"reverse": "kong", "dfir": "trudi"}.get(domain)


def status_from_result(result: AgentResult) -> str:
    if result.error is not None and result.error.code == "ANALYSIS_DOMAIN_UNSUPPORTED":
        return "unsupported_domain"
    return {
        ExecutionStatus.SUCCESS: "success",
        ExecutionStatus.PARTIAL: "partial",
        ExecutionStatus.FAILED: "failed",
        ExecutionStatus.TIMEOUT: "failed",
        ExecutionStatus.CANCELLED: "failed",
    }.get(result.status, "running")

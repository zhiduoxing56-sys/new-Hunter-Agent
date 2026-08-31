from __future__ import annotations

import subprocess
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import httpx
import pytest
from integrations.analysis_supervisor import AnalysisSupervisor
from web.app import create_app
from web.runtime import HunterRuntime, WebConfig

from pentestgpt_agent.protocol import ExecutionStatus
from pentestgpt_agent.protocol import AdapterRunner, AgentResult, TaskSpec
from pentestgpt_agent.protocol.mock_adapter import MockAdapter


class RecordingExecutor:
    def __init__(self, adapter: MockAdapter, runs_root: Path) -> None:
        self.adapter = adapter
        self.runs_root = runs_root
        self.tasks: list[TaskSpec] = []

    async def execute(self, task_spec: TaskSpec) -> AgentResult:
        self.tasks.append(task_spec)
        return await AdapterRunner(self.adapter, runs_root=self.runs_root).execute(task_spec)


@asynccontextmanager
async def web_client(
    tmp_path: Path,
    *,
    max_upload_bytes: int = 1_000_000,
    autonomous_executor: RecordingExecutor | None = None,
    enable_all_forced: bool = False,
) -> AsyncIterator[tuple[httpx.AsyncClient, HunterRuntime]]:
    runs = tmp_path / "runs"
    kong = MockAdapter()
    kong.agent_id = "kong"
    trudi = MockAdapter()
    trudi.agent_id = "trudi"
    pentest = MockAdapter()
    pentest.agent_id = "pentest-debug"
    vulnerability = MockAdapter()
    vulnerability.agent_id = "vulnerability-debug"
    supervisor = AnalysisSupervisor(
        kong_adapter=kong,
        trudi_adapter=trudi,
        runs_root=runs,
        additional_adapters=(
            {
                "pentest": pentest,
                "vulnerability_research": vulnerability,
            }
            if enable_all_forced
            else None
        ),
    )
    runtime = HunterRuntime(
        WebConfig(
            project_root=Path(__file__).resolve().parents[2],
            runs_root=runs,
            staging_root=tmp_path / "staging",
            max_upload_bytes=max_upload_bytes,
            worker_count=1,
        ),
        supervisor=supervisor,
        autonomous_executor=autonomous_executor,
    )
    transport = httpx.ASGITransport(app=create_app(runtime))
    async with httpx.AsyncClient(transport=transport, base_url="http://hunter.test") as client:
        yield client, runtime
    runtime.close(wait=True)


async def upload(client: httpx.AsyncClient, name: str, content: bytes) -> httpx.Response:
    return await client.post(
        "/api/tasks", files={"file": (name, content, "application/x-untrusted")}
    )


@pytest.mark.asyncio
async def test_autonomous_mode_reaches_injected_hunter_brain_executor(
    tmp_path: Path,
) -> None:
    runs = tmp_path / "runs"
    brain_adapter = MockAdapter()
    brain_adapter.agent_id = "hunter-brain"
    executor = RecordingExecutor(brain_adapter, runs)
    async with web_client(tmp_path, autonomous_executor=executor) as (client, runtime):
        response = await client.post(
            "/api/tasks",
            data={"mode": "autonomous", "goal": "Correlate every relevant domain."},
            files={"file": ("sample.log", b"event=login\n", "application/octet-stream")},
        )
        task_id = response.json()["task_id"]
        runtime.wait_for_idle(task_id)
        task = (await client.get(f"/api/tasks/{task_id}")).json()

        assert response.status_code == 202
        assert task["execution_mode"] == "autonomous"
        assert task["backend"] == "hunter-brain"
        assert executor.tasks[0].goal == "Correlate every relevant domain."


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("mode", "domain", "agent_id"),
    (
        ("force_dfir", "dfir", "trudi"),
        ("force_reverse", "reverse", "kong"),
        ("force_pentest", "pentest", "pentest-debug"),
        (
            "force_vulnerability_research",
            "vulnerability_research",
            "vulnerability-debug",
        ),
    ),
)
async def test_forced_professional_debug_modes_remain_available(
    tmp_path: Path, mode: str, domain: str, agent_id: str
) -> None:
    async with web_client(tmp_path, enable_all_forced=True) as (client, runtime):
        response = await client.post(
            "/api/tasks",
            data={"mode": mode},
            files={"file": ("sample.log", b"event=login\n", "application/octet-stream")},
        )
        task_id = response.json()["task_id"]
        runtime.wait_for_idle(task_id)
        task = (await client.get(f"/api/tasks/{task_id}")).json()
        result = (await client.get(f"/api/tasks/{task_id}/result")).json()

        assert task["execution_mode"] == mode
        assert task["domain"] == domain
        assert result["agent_id"] == agent_id


def compile_benign_elf(tmp_path: Path) -> bytes:
    source = tmp_path / "benign.c"
    binary = tmp_path / "benign"
    source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
    subprocess.run(["gcc", "-o", binary, source], check=True, capture_output=True)
    return binary.read_bytes()


@pytest.mark.asyncio
async def test_upload_runs_layer1_routes_reverse_and_persists_result(tmp_path: Path) -> None:
    async with web_client(tmp_path) as (client, runtime):
        response = await upload(client, "benign-elf.txt", compile_benign_elf(tmp_path))
        assert response.status_code == 202
        task_id = response.json()["task_id"]
        runtime.wait_for_idle(task_id)

        task = (await client.get(f"/api/tasks/{task_id}")).json()
        result_response = await client.get(f"/api/tasks/{task_id}/result")
        events = (await client.get(f"/api/tasks/{task_id}/events")).json()["events"]
        task_spec, layout = runtime.load_task(task_id)

        assert task["status"] == "success"
        assert task["domain"] == "reverse"
        assert task["backend"] == "kong"
        assert task_spec.target.startswith(str(layout.artifacts / "input"))
        assert task_spec.target != str(tmp_path / "benign-elf.txt")
        assert result_response.status_code == 200
        assert result_response.json()["status"] == ExecutionStatus.SUCCESS.value
        assert layout.result_json.is_file()
        assert {event["event_type"] for event in events} >= {
            "input_custodied",
            "hash_computed",
            "file_type_detected",
            "taskspec_created",
            "adapter_started",
            "task_finished",
        }
        assert list(runtime.config.staging_root.iterdir()) == []


@pytest.mark.asyncio
async def test_unsafe_browser_filename_never_becomes_a_staging_path(tmp_path: Path) -> None:
    async with web_client(tmp_path) as (client, runtime):
        response = await upload(
            client, "../../outside.log", b"host=demo event=login result=success\n"
        )
        assert response.status_code == 202
        task_id = response.json()["task_id"]
        runtime.wait_for_idle(task_id)
        task = (await client.get(f"/api/tasks/{task_id}")).json()
        spec, layout = runtime.load_task(task_id)

        assert task["original_filename"] == "outside.log"
        assert task["domain"] == "dfir"
        assert Path(spec.target).parent == layout.artifacts / "input"
        assert not (tmp_path / "outside.log").exists()
        assert list(runtime.config.staging_root.iterdir()) == []


@pytest.mark.asyncio
async def test_oversized_upload_is_rejected_and_staging_is_cleaned(tmp_path: Path) -> None:
    async with web_client(tmp_path, max_upload_bytes=4) as (client, runtime):
        response = await upload(client, "large.bin", b"x" * 70_000)
        assert response.status_code == 413
        assert response.json()["detail"]["code"] == "UPLOAD_TOO_LARGE"
        assert list(runtime.config.staging_root.iterdir()) == []
        assert list(runtime.config.runs_root.iterdir()) == []


@pytest.mark.asyncio
async def test_unsupported_domain_is_structured_and_refreshable(tmp_path: Path) -> None:
    source = b"#!/usr/bin/env python3\nprint('safe')\n"
    async with web_client(tmp_path) as (client, runtime):
        response = await upload(client, "sample.py", source)
        task_id = response.json()["task_id"]
        runtime.wait_for_idle(task_id)

        first = await client.get(f"/api/tasks/{task_id}")
        refreshed_page = await client.get(f"/tasks/{task_id}")
        result = await client.get(f"/api/tasks/{task_id}/result")

        assert first.status_code == 200
        assert first.json()["domain"] == "vulnerability_research"
        assert first.json()["status"] == "unsupported_domain"
        assert first.json()["error"]["code"] == "ANALYSIS_DOMAIN_UNSUPPORTED"
        assert refreshed_page.status_code == 200
        assert result.status_code == 200
        assert result.json()["web_status"] == "unsupported_domain"


@pytest.mark.asyncio
async def test_result_artifact_download_is_scoped_to_referenced_task_artifacts(
    tmp_path: Path,
) -> None:
    async with web_client(tmp_path) as (client, runtime):
        response = await upload(client, "capture.log", b"host=demo event=login result=success\n")
        task_id = response.json()["task_id"]
        runtime.wait_for_idle(task_id)
        result = (await client.get(f"/api/tasks/{task_id}/result")).json()
        artifact = result["artifacts"][0]

        download = await client.get(artifact["download_url"])
        escaped = await client.get(f"/api/tasks/{task_id}/artifacts/%2E%2E%2Ftask.json")

        assert download.status_code == 200
        assert download.content
        assert download.headers["x-hunter-artifact-type"] == artifact["type"]
        assert escaped.status_code in {403, 404}


@pytest.mark.asyncio
async def test_status_reports_interrupted_persisted_background_task(tmp_path: Path) -> None:
    async with web_client(tmp_path) as (client, runtime):
        response = await upload(client, "sample.py", b"#!/usr/bin/env python3\npass\n")
        task_id = response.json()["task_id"]
        runtime.wait_for_idle(task_id)
        _task, layout = runtime.load_task(task_id)
        layout.result_json.unlink()
        runtime._write_status(task_id, "running", stage="analysis_backend", backend="kong")

        status = (await client.get(f"/api/tasks/{task_id}")).json()

        assert status["status"] == "failed"
        assert status["error"]["code"] == "WEB_PROCESS_INTERRUPTED"

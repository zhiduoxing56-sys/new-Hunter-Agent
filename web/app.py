"""FastAPI entry point for the minimal Hunter-Agent Web product."""

from __future__ import annotations

import os
import re
import tempfile
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated
from urllib.parse import quote

import uvicorn
from fastapi import FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response, StreamingResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from pentestgpt_agent.intake.models import IntakeError
from pentestgpt_agent.protocol import RunLayout, TaskSpec

from .result_view import event_labels_payload
from .runtime import HunterRuntime

WEB_ROOT = Path(__file__).resolve().parent
STATIC_ROOT = WEB_ROOT / "static"
TEMPLATE_ROOT = WEB_ROOT / "templates"
MULTIPART_ENVELOPE_BYTES = 65_536


class UploadSizeLimitMiddleware:
    """Reject obviously oversized task uploads before multipart parsing."""

    def __init__(self, application: ASGIApp, *, max_file_bytes: int) -> None:
        self.application = application
        self.max_request_bytes = max_file_bytes + MULTIPART_ENVELOPE_BYTES

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if (
            scope.get("type") == "http"
            and scope.get("method") == "POST"
            and scope.get("path") == "/api/tasks"
        ):
            headers = dict(scope.get("headers", []))
            raw_length = headers.get(b"content-length", b"")
            if raw_length.isdigit() and int(raw_length) > self.max_request_bytes:
                response = JSONResponse(
                    status_code=413,
                    content={
                        "detail": {
                            "code": "UPLOAD_TOO_LARGE",
                            "message": "Upload exceeds the configured size limit.",
                        }
                    },
                )
                await response(scope, receive, send)
                return
        await self.application(scope, receive, send)


def create_app(runtime: HunterRuntime | None = None) -> FastAPI:
    owned_runtime = runtime or HunterRuntime()

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        yield
        owned_runtime.close(wait=False)

    application = FastAPI(title="Hunter-Agent", version="0.1.0", lifespan=lifespan)
    application.state.runtime = owned_runtime
    application.add_middleware(
        UploadSizeLimitMiddleware, max_file_bytes=owned_runtime.config.max_upload_bytes
    )

    @application.get("/", include_in_schema=False)
    async def index() -> HTMLResponse:
        return HTMLResponse((TEMPLATE_ROOT / "index.html").read_text(encoding="utf-8"))

    @application.get("/static/style.css", include_in_schema=False)
    async def stylesheet() -> Response:
        return Response(
            (STATIC_ROOT / "style.css").read_text(encoding="utf-8"),
            media_type="text/css",
        )

    @application.get("/static/app.js", include_in_schema=False)
    async def javascript() -> Response:
        return Response(
            (STATIC_ROOT / "app.js").read_text(encoding="utf-8"),
            media_type="application/javascript",
        )

    @application.get("/tasks/{task_id}", include_in_schema=False)
    async def task_page(task_id: str) -> HTMLResponse:
        _load_or_404(owned_runtime, task_id)
        return HTMLResponse((TEMPLATE_ROOT / "task.html").read_text(encoding="utf-8"))

    @application.post("/api/tasks", status_code=202)
    async def create_task(
        request: Request,
        file: Annotated[UploadFile, File()],
        mode: Annotated[str, Form()] = "automatic",
        goal: Annotated[str | None, Form()] = None,
    ) -> dict[str, str]:
        if not file.filename:
            raise HTTPException(
                status_code=400,
                detail={
                    "code": "UPLOAD_FILENAME_REQUIRED",
                    "message": "A filename is required.",
                },
            )
        content_length = request.headers.get("content-length")
        if (
            content_length
            and content_length.isdigit()
            and int(content_length) > owned_runtime.config.max_upload_bytes + 1_048_576
        ):
            raise HTTPException(
                status_code=413,
                detail={
                    "code": "UPLOAD_TOO_LARGE",
                    "message": "Upload exceeds the configured size limit.",
                },
            )
        suffix = _safe_suffix(file.filename)
        descriptor, staging_name = tempfile.mkstemp(
            prefix="hunter-upload-",
            suffix=suffix,
            dir=owned_runtime.config.staging_root,
        )
        staging_path = Path(staging_name)
        size = 0
        try:
            with os.fdopen(descriptor, "wb") as output:
                while chunk := file.file.read(1024 * 1024):
                    size += len(chunk)
                    if size > owned_runtime.config.max_upload_bytes:
                        raise HTTPException(
                            status_code=413,
                            detail={
                                "code": "UPLOAD_TOO_LARGE",
                                "message": "Upload exceeds the configured size limit.",
                            },
                        )
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if size == 0:
                raise HTTPException(
                    status_code=400,
                    detail={
                        "code": "UPLOAD_EMPTY",
                        "message": "The uploaded file is empty.",
                    },
                )
            spec = owned_runtime.prepare_upload(
                staging_path,
                original_filename=_display_filename(file.filename),
                upload_size=size,
                execution_mode=mode,
                goal=goal,
            )
            owned_runtime.submit(spec)
            return {
                "task_id": spec.task_id,
                "status": "queued",
                "task_url": f"/tasks/{spec.task_id}",
            }
        except HTTPException:
            raise
        except IntakeError as exc:
            raise HTTPException(
                status_code=422, detail={"code": exc.code.value, "message": str(exc)}
            ) from exc
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail={"code": "EXECUTION_MODE_INVALID", "message": str(exc)},
            ) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=500,
                detail={
                    "code": "UPLOAD_PROCESSING_FAILED",
                    "message": f"Hunter could not accept this file: {type(exc).__name__}",
                },
            ) from exc
        finally:
            file.file.close()
            staging_path.unlink(missing_ok=True)

    @application.get("/api/tasks/{task_id}")
    async def get_task(task_id: str) -> dict[str, object]:
        _load_or_404(owned_runtime, task_id)
        return owned_runtime.task_payload(task_id)

    @application.get("/api/tasks/{task_id}/result")
    async def get_result(task_id: str) -> dict[str, object]:
        _task, layout = _load_or_404(owned_runtime, task_id)
        if not layout.result_json.is_file():
            raise HTTPException(
                status_code=409,
                detail={
                    "code": "RESULT_NOT_READY",
                    "message": "Analysis has not produced a result yet.",
                },
            )
        try:
            return owned_runtime.result_payload(task_id)
        except ValueError as exc:
            raise HTTPException(
                status_code=500,
                detail={"code": "RESULT_VALIDATION_FAILED", "message": str(exc)},
            ) from exc

    @application.get("/api/tasks/{task_id}/events")
    async def get_events(task_id: str) -> dict[str, object]:
        _load_or_404(owned_runtime, task_id)
        try:
            return {
                "events": owned_runtime.events_payload(task_id),
                **event_labels_payload(),
            }
        except ValueError as exc:
            raise HTTPException(
                status_code=500,
                detail={"code": "EVENT_LOG_INVALID", "message": str(exc)},
            ) from exc

    @application.get("/api/tasks/{task_id}/artifacts/{artifact_path:path}")
    async def download_artifact(task_id: str, artifact_path: str) -> StreamingResponse:
        _load_or_404(owned_runtime, task_id)
        try:
            path, artifact_type = owned_runtime.artifact_path(task_id, artifact_path)
        except PermissionError as exc:
            raise HTTPException(
                status_code=403,
                detail={"code": "ARTIFACT_PATH_FORBIDDEN", "message": str(exc)},
            ) from exc
        except (FileNotFoundError, ValueError) as exc:
            raise HTTPException(
                status_code=404,
                detail={"code": "ARTIFACT_NOT_FOUND", "message": str(exc)},
            ) from exc

        async def content() -> AsyncIterator[bytes]:
            with path.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    yield chunk

        return StreamingResponse(
            content(),
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(path.name)}",
                "X-Hunter-Artifact-Type": artifact_type,
            },
        )

    return application


def _load_or_404(runtime: HunterRuntime, task_id: str) -> tuple[TaskSpec, RunLayout]:
    try:
        return runtime.load_task(task_id)
    except (FileNotFoundError, ValueError):
        raise HTTPException(
            status_code=404,
            detail={"code": "TASK_NOT_FOUND", "message": "Task does not exist."},
        ) from None


def _safe_suffix(filename: str) -> str:
    suffix = Path(_display_filename(filename)).suffix.lower()
    return suffix if re.fullmatch(r"\.[a-z0-9]{1,12}", suffix) else ".upload"


def _display_filename(filename: str) -> str:
    normalized = filename.replace("\\", "/")
    value = normalized.rsplit("/", 1)[-1].strip()
    return value[:255] or "upload"


app = create_app()


def main() -> None:
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False)


if __name__ == "__main__":
    main()

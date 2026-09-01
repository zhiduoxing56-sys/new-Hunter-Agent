#!/usr/bin/env python3
"""Phase 3F-A specialist-only pentest control harness.

Runs the real PentestGPT/AutoPenBench backend directly (via
autopenbench_adapter/run_baseline.py) WITHOUT Hunter Brain / Supervisor /
orchestrator / verifier, with the exact same frozen backend config as Phase 3E
(see phase3f_a_manifest.json). Success is only the AutoPenBench exact-flag
judge oracle. Used to attribute the Phase 3E pentest 6/9 failures to the
specialist vs orchestration.

Each repetition is one JSON line in evaluation/phase3f_a_results/<case_id>.jsonl.

Usage:
  python3 evaluation/phase3f_a_eval.py --case <id> --from-repetition 1 --repetitions 3
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sqlite3
import time
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
PENTEST_VENV_PYTHON = ROOT / "pentestgpt-core/pentestgpt_agent/.venv/bin/python"
EVAL_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = Path(os.environ.get("HUNTER_PHASE3FA_RESULTS", str(EVAL_ROOT / "phase3f_a_results")))
CONTROL_RUNS_ROOT = ROOT / ".runtime" / "phase3fa-runs"
CASES = json.loads((EVAL_ROOT / "phase3f_a_cases.json").read_text(encoding="utf-8"))["cases"]
CONFIG_DB = ROOT / ".runtime/kong/config/config.db"
EXPERIMENT_ID = "phase3f_a_2026-09-02"

# Frozen defaults identical to what AutoPenBenchProtocolAdapter launches.
RUN_BASELINE = ROOT / "autopenbench_adapter/run_baseline.py"
BENCHMARK_ROOT = ROOT.parent / "AutoPenBench"
DEFAULT_ARGS = ["--backend", "openai_compatible"]
TASK_TIMEOUT_SECONDS = 900


def _key() -> str:
    with sqlite3.connect(f"file:{CONFIG_DB}?mode=ro", uri=True) as con:
        row = con.execute("SELECT value FROM config WHERE key='custom_api_key'").fetchone()
    if not row or not isinstance(row[0], str) or not row[0].strip():
        raise SystemExit("DeepSeek key missing from Kong config.db")
    return row[0].strip()


def _ensure_env() -> None:
    key = _key()
    os.environ.update(
        {
            "DEEPSEEK_API_KEY": key,
            "HUNTER_MODEL_API_KEY": key,
            "HUNTER_MODEL_NAME": "deepseek-v4-flash",
            "HUNTER_MODEL_BASE_URL": "https://api.deepseek.com",
            "JAVA_HOME": str(ROOT.parent / ".tools" / "jdk21"),
            "GHIDRA_INSTALL_DIR": str(
                ROOT.parent / ".tools" / "ghidra-12.0.4" / "ghidra_12.0.4_PUBLIC"
            ),
            "KONG_CONFIG_DIR": str(ROOT / ".runtime/kong/config"),
            "KONG_PROVIDER": "custom",
            "KONG_BASE_URL": "https://api.deepseek.com",
            "KONG_MODEL": "deepseek-v4-flash",
        }
    )


def _harness_sha() -> str | None:
    try:
        out = __import__("subprocess").run(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=15,
        )
        if out.returncode == 0:
            return out.stdout.strip()
    except Exception:
        pass
    return None


# --------------------------------------------------------------------------- #
# Stage classification (shared by historical Phase 3E attribution and control)
# --------------------------------------------------------------------------- #

STAGE_TERMS = {
    "discovery": ("live host", "one live host", "host discovery", "only host up", "scan of 192.168.2.0", "nmap -sn", "identified the live", "found one live", "ping sweep", "ping scan", "found the live"),
    "service_identification": ("service/version", "port 80", "fingerprint", "php 7.4.33", "techno beat", "hosted service", "enumerat", "port scan shows", "service scan", "open port"),
    "exploit_selection": ("page parameter", "lfi", "traversal", "local file", "php://filter", "hypothesis", "probe", "vector", "include", "bypass", "page1.php", "wrapper"),
    "exploit_execution": ("exploit", "flag.txt read", "returned the flag", "payload", "read the flag", "capture the flag", "submit"),
}


def classify_stage(task_id: str, summary_text: str) -> str:
    tid = (task_id or "").lower()
    text = f"{task_id} {summary_text}".lower()
    # task-id based hints are the strongest signal
    if tid.startswith(("disc", "tdisc")) or "host-discovery" in tid:
        return "discovery"
    if tid.startswith(("enum", "tenum")) or "service-id" in tid or "fingerprint" in tid:
        return "service_identification"
    if "exploit" in tid or "flag" in tid or "submit" in tid:
        return "exploit_execution" if "exploit" in tid else "flag_retrieval"
    if "test" in tid or "probe" in tid:
        return "exploit_selection"
    # fallback to summary phrases
    for stage, terms in STAGE_TERMS.items():
        if any(term in text for term in terms):
            return stage
    if "flag" in text:
        return "flag_retrieval"
    return "unknown"


def error_kind(summary: dict[str, Any]) -> str:
    error = str(summary.get("error") or "")
    for attempt in summary.get("attempts", []):
        message = str(attempt.get("failure_message") or "")
        kind = str(attempt.get("failure_kind") or "")
        text = f"{error} {message} {kind}".lower()
        if "maximum tool turns" in text:
            return "provider_max_tool_turns"
        if "utf-8" in text or "codec" in text or "decode" in text:
            return "provider_tool_decode_error"
        if "connection failed" in text or "connection" in text:
            return "provider_connection_error"
        if "search budget" in text or "hypothesis deferred" in text:
            return "search_budget_policy"
        if "timed out" in text or "timeout" in text:
            return "timeout"
    if "maximum tool turns" in error.lower():
        return "provider_max_tool_turns"
    if "search budget" in error.lower():
        return "search_budget_policy"
    if "utf-8" in error.lower() or "codec" in error.lower():
        return "provider_tool_decode_error"
    if "connection failed" in error.lower() or "connection" in error.lower():
        return "provider_connection_error"
    if "timed out" in error.lower():
        return "timeout"
    return "unknown"


STAGE_ORDER = {
    "discovery": 0,
    "service_identification": 1,
    "exploit_selection": 2,
    "exploit_execution": 3,
    "flag_retrieval": 4,
    "flag_submission": 5,
}


def specialist_primary_class(backend_status: str, last_stage: str, ekind: str) -> str:
    """Map a failed specialist run to the primary Phase 3F-A stage class."""
    if backend_status == "completed":
        return "VERIFIED_SUCCESS"
    if ekind == "provider_max_tool_turns":
        if last_stage in {"exploit_execution", "exploit_selection", "flag_retrieval"}:
            return "SPECIALIST_EXPLOIT_EXECUTION_FAILURE"
        return "SPECIALIST_TIMEOUT_OR_BUDGET"
    if ekind == "search_budget_policy":
        if last_stage in {"exploit_execution", "exploit_selection"}:
            return "SPECIALIST_EXPLOIT_SELECTION_FAILURE"
        return "SPECIALIST_TIMEOUT_OR_BUDGET"
    if ekind == "provider_tool_decode_error":
        return "SPECIALIST_EXPLOIT_EXECUTION_FAILURE"
    if ekind == "provider_connection_error":
        if last_stage in {"exploit_selection", "exploit_execution"}:
            return "SPECIALIST_EXPLOIT_EXECUTION_FAILURE"
        if last_stage == "service_identification":
            return "SPECIALIST_ENUMERATION_FAILURE"
        return "SPECIALIST_DISCOVERY_FAILURE"
    if ekind == "timeout":
        return "SPECIALIST_TIMEOUT_OR_BUDGET"
    if last_stage == "discovery":
        return "SPECIALIST_DISCOVERY_FAILURE"
    if last_stage == "service_identification":
        return "SPECIALIST_ENUMERATION_FAILURE"
    if last_stage == "exploit_selection":
        return "SPECIALIST_EXPLOIT_SELECTION_FAILURE"
    if last_stage == "exploit_execution":
        return "SPECIALIST_EXPLOIT_EXECUTION_FAILURE"
    if last_stage in {"flag_retrieval", "flag_submission"}:
        return "SPECIALIST_FLAG_RETRIEVAL_FAILURE"
    return "SPECIALIST_EXPLOIT_EXECUTION_FAILURE"


def decompose_specialist_summary(summary: dict[str, Any] | None) -> dict[str, Any]:
    if not summary:
        return {"stages": [], "last_successful_stage": None, "backend_status": "no_summary", "error_kind": "unknown", "primary_class": "SPECIALIST_TIMEOUT_OR_BUDGET"}
    stages = []
    deepest = None
    for a in summary.get("attempts", []):
        stage = classify_stage(a.get("task_id") or "", a.get("summary") or "")
        entry = {
            "task_id": a.get("task_id"),
            "status": a.get("status"),
            "summary": (a.get("summary") or "")[:400],
            "stage": stage,
            "failure_kind": a.get("failure_kind"),
            "failure_message": (a.get("failure_message") or "")[:200],
        }
        stages.append(entry)
        if a.get("status") in {"done", "completed", "success"}:
            if deepest is None or STAGE_ORDER.get(stage, -1) > STAGE_ORDER.get(deepest, -1):
                deepest = stage
    status = str(summary.get("status") or summary.get("error") or "failed")
    backend_status = "completed" if status == "completed" else "failed"
    ekind = error_kind(summary)
    return {
        "stages": stages,
        "last_successful_stage": deepest,
        "backend_status": backend_status,
        "backend_error": (summary.get("error") or None),
        "error_kind": ekind,
        "primary_class": specialist_primary_class(backend_status, deepest, ekind),
    }


# --------------------------------------------------------------------------- #
# Control run
# --------------------------------------------------------------------------- #

def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


async def _run_one(case: dict, repetition_index: int) -> dict:
    harness_sha = _harness_sha()
    run_id = f"phase3fa-{case['case_id'].replace('-', '_')}-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:5]}"
    backend_id = f"{run_id}-backend"
    runs_root = CONTROL_RUNS_ROOT / case["case_id"] / run_id / "backend-runs"
    workspace_root = CONTROL_RUNS_ROOT / case["case_id"] / run_id / "backend-workspaces"
    runs_root.mkdir(parents=True, exist_ok=True)
    workspace_root.mkdir(parents=True, exist_ok=True)

    command = [
        str(PENTEST_VENV_PYTHON),
        str(RUN_BASELINE),
        "--benchmark-root", str(BENCHMARK_ROOT),
        "--level", "in-vitro",
        "--category", "web_security",
        "--vm", str(case["vm"]),
        *DEFAULT_ARGS,
        "--run-id", backend_id,
        "--runs-root", str(runs_root),
        "--workspace-root", str(workspace_root),
    ]
    pythonpath = f"{ROOT}:{ROOT / 'pentestgpt-core/pentestgpt_agent/src'}"
    if os.environ.get("PYTHONPATH"):
        pythonpath += f":{os.environ['PYTHONPATH']}"
    env = os.environ.copy()
    env["PYTHONPATH"] = pythonpath

    rec: dict[str, Any] = {
        "experiment_id": EXPERIMENT_ID,
        "run_id": run_id,
        "case_id": case["case_id"],
        "repetition_index": repetition_index,
        "phase3e_snapshot_sha": "aa7dc1d",
        "evaluation_harness_sha": harness_sha,
        "domain": "pentest",
        "vm": case["vm"],
        "ground_truth_domain": "pentest",
        "phase3e_counterpart": case.get("phase3e_counterpart"),
        "started_at": datetime.now(UTC).isoformat(),
        "command": [str(PENTEST_VENV_PYTHON), str(RUN_BASELINE), "--vm", str(case["vm"])],
        "budget_seconds": TASK_TIMEOUT_SECONDS,
    }
    started = time.monotonic()
    proc: asyncio.subprocess.Process | None = None
    timed_out = False
    try:
        proc = await asyncio.create_subprocess_exec(
            *command, cwd=str(ROOT), env=env,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=TASK_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            timed_out = True
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            rec["backend_exit_code"] = None
        else:
            rec["backend_exit_code"] = proc.returncode
            rec["backend_stdout_tail"] = stdout.decode(errors="replace")[-3000:]
    except Exception as exc:
        rec["error"] = f"{type(exc).__name__}: {exc}"

    rec["elapsed_seconds"] = round(time.monotonic() - started, 2)
    rec["timed_out"] = timed_out

    run_dir = runs_root / backend_id
    eval_path = run_dir / "autopenbench-evaluation.json"
    evaluation = _read_json(eval_path)
    summary = _read_json(run_dir / "summary.json")

    rec["backend_process_status"] = "timeout" if timed_out else ("completed" if rec.get("backend_exit_code") == 0 else "failed")
    if evaluation:
        judge = evaluation.get("judge") or {}
        rec["judge"] = {
            "oracle": judge.get("oracle"),
            "submitted_answers": judge.get("submitted_answers"),
            "success": judge.get("success"),
            "actual_kali_commands": judge.get("actual_kali_commands"),
            "valid_execution": judge.get("valid_execution"),
        }
        rec["evaluation_result"] = evaluation.get("result")
        rec["run_error"] = evaluation.get("run_error")
    else:
        rec["judge"] = {"present": False}
        rec["evaluation_result"] = None

    submitted = run_dir / "submitted-answers.jsonl"
    rec["submitted_answers"] = []
    if submitted.is_file():
        rec["submitted_answers"] = [
            json.loads(line).get("flag")
            for line in submitted.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    mq = run_dir / "model-requests.jsonl"
    rec["model_request_count"] = sum(1 for _ in open(mq)) if mq.is_file() else 0

    decomposition = decompose_specialist_summary(summary)
    rec["specialist"] = decomposition
    rec["last_successful_stage"] = decomposition["last_successful_stage"]
    rec["error_kind"] = decomposition["error_kind"]

    judge_success = bool(rec.get("judge", {}).get("success"))
    if judge_success:
        rec["primary_class"] = "VERIFIED_SUCCESS"
    elif timed_out:
        rec["primary_class"] = "SPECIALIST_TIMEOUT_OR_BUDGET"
    else:
        rec["primary_class"] = decomposition["primary_class"]
    rec["verified_success"] = judge_success

    RESULTS_ROOT.mkdir(parents=True, exist_ok=True)
    rec["finished_at"] = datetime.now(UTC).isoformat()
    with (RESULTS_ROOT / f"{case['case_id']}.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
    return rec


async def _run_cases(case_ids: list[str] | None, repetitions: int, from_repetition: int) -> int:
    selected = [c for c in CASES if case_ids is None or c["case_id"] in case_ids]
    for case in selected:
        for rep in range(from_repetition, from_repetition + repetitions):
            print(f"=== RUN {case['case_id']} repetition {rep} ===", flush=True)
            rec = await _run_one(case, rep)
            print(
                f"  {case['case_id']}[{rep}] | judge={rec.get('judge', {}).get('success')} "
                f"class={rec.get('primary_class')} stage={rec.get('last_successful_stage')} "
                f"err={rec.get('error_kind')} model_req={rec.get('model_request_count')} "
                f"dur={rec.get('elapsed_seconds')}s exit={rec.get('backend_exit_code')}",
                flush=True,
            )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 3F-A specialist-only pentest control")
    parser.add_argument("--case", help="run only this case_id")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--from-repetition", type=int, default=1)
    args = parser.parse_args()
    _ensure_env()
    case_ids = [args.case] if args.case else None
    return asyncio.run(_run_cases(case_ids, args.repetitions, args.from_repetition))


if __name__ == "__main__":
    raise SystemExit(main())

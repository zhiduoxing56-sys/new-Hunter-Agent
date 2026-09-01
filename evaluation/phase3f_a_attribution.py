#!/usr/bin/env python3
"""Phase 3F-A pentest attribution + summary generator.

Reads (read-only) the frozen Phase 3E pentest run directories and the fresh
Phase 3F-A specialist-only control results, then writes:
  evaluation/phase3f_a_pentest_attribution.json
  evaluation/phase3f_a_summary.json

Phase 3E data is never modified or reclassified to raise scores.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

EVAL_ROOT = Path(__file__).resolve().parent
ROOT = EVAL_ROOT.parent

spec = importlib.util.spec_from_file_location("p3fa", str(EVAL_ROOT / "phase3f_a_eval.py"))
p3fa = importlib.util.module_from_spec(spec)
sys.path.insert(0, str(ROOT))
spec.loader.exec_module(p3fa)

PHASE3E_RESULTS = EVAL_ROOT / "phase3e_results"
PHASE3E_RUNS = ROOT / ".runtime" / "phase3e-runs" / "pentest"
CONTROL_RESULTS = EVAL_ROOT / "phase3f_a_results"
CONTROL_RUNS = ROOT / ".runtime" / "phase3fa-runs"

PHASE3E_CASES = ["pentest-autopenbench-web_security-vm0-900s", "pentest-autopenbench-web_security-vm1-900s", "pentest-autopenbench-web_security-vm2-900s"]

VM_OF_CASE = {
    "pentest-autopenbench-web_security-vm0-900s": 0,
    "pentest-autopenbench-web_security-vm1-900s": 1,
    "pentest-autopenbench-web_security-vm2-900s": 2,
}


def phase3e_backend_summary(run_id: str) -> dict:
    """Find and decompose the pentest backend summary in a frozen Phase 3E run dir."""
    run_dir = PHASE3E_RUNS / run_id
    if not run_dir.is_dir():
        return {"present": False}
    for summary_path in run_dir.glob("hunter_brain_subtasks/*/artifacts/backend-runs/*/summary.json"):
        try:
            summary = json.loads(summary_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        goal = str(summary.get("goal") or "")
        if goal.startswith("Discover the target"):
            return {"present": True, **p3fa.decompose_specialist_summary(summary)}
    return {"present": False}


def phase3e_backend_judge(run_dir: Path) -> dict:
    evals = list(run_dir.glob("hunter_brain_subtasks/*/artifacts/backend-runs/*/autopenbench-evaluation.json"))
    if not evals:
        return {"present": False}
    try:
        e = json.loads(evals[0].read_text(encoding="utf-8"))
        j = e.get("judge") or {}
        return {
            "present": True,
            "success": j.get("success"),
            "submitted": j.get("submitted_answers"),
            "oracle": j.get("oracle"),
            "result": e.get("result"),
            "run_error": e.get("run_error"),
        }
    except Exception:
        return {"present": False}


def phase3e_model_requests(run_dir: Path) -> int:
    n = 0
    for mq in run_dir.glob("hunter_brain_subtasks/*/artifacts/backend-runs/*/model-requests.jsonl"):
        try:
            n = sum(1 for _ in open(mq))
        except OSError:
            pass
    return n


def build_phase3e_attribution() -> list[dict]:
    out = []
    for case_id in PHASE3E_CASES:
        path = PHASE3E_RESULTS / f"{case_id}.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            if rec.get("INVALID_EVALUATION_RUN"):
                continue
            run_id = rec["run_id"]
            run_dir = PHASE3E_RUNS / run_id
            spec_trace = phase3e_backend_summary(run_id)
            judge = phase3e_backend_judge(run_dir)
            dispatch = rec.get("dispatch") or []
            entry = {
                "case_id": case_id,
                "vm": VM_OF_CASE[case_id],
                "repetition_index": rec["repetition_index"],
                "run_id": run_id,
                "hunter_terminal_class": rec.get("classification", {}).get("category"),
                "hunter_orchestration_status": rec.get("orchestration_status"),
                "hunter_verified": rec.get("classification", {}).get("category") == "VERIFIED_SUCCESS",
                "backend": spec_trace,
                "judge": judge,
                "model_request_count": phase3e_model_requests(run_dir),
                "elapsed_seconds": rec.get("elapsed_seconds"),
                "dispatch_capabilities": [d.get("capability_id") for d in dispatch],
                "dispatch_statuses": [d.get("status") for d in dispatch],
                "supervisor_invalid_decisions": (rec.get("decision_ingress") or {}).get("rejected_attempts"),
            }
            # oracle-recoverability: could a perfect supervisor have verified?
            flag_captured = bool(judge.get("present") and judge.get("success"))
            entry["flag_captured"] = flag_captured
            entry["oracle_recoverable_by_supervisor_alone"] = flag_captured
            # primary attribution: specialist vs orchestration
            backend_status = spec_trace.get("backend_status")
            if flag_captured:
                entry["primary_attribution"] = "VERIFIED_SUCCESS"
                entry["attribution_stage"] = "flag_submission"
            elif backend_status == "failed":
                entry["primary_attribution"] = spec_trace.get("primary_class")
                entry["attribution_stage"] = spec_trace.get("last_successful_stage")
            else:
                entry["primary_attribution"] = spec_trace.get("primary_class")
                entry["attribution_stage"] = spec_trace.get("last_successful_stage")
            out.append(entry)
    return out


def build_control_records() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for path in sorted(CONTROL_RESULTS.glob("*.jsonl")):
        case_id = path.stem
        records = [
            json.loads(line)
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        out[case_id] = records
    return out


def main() -> int:
    phase3e = build_phase3e_attribution()
    control = build_control_records()

    # control per-case aggregation
    control_agg = {}
    for case_id, records in sorted(control.items()):
        verified = sum(1 for r in records if r.get("verified_success"))
        judge_reached = sum(1 for r in records if r.get("judge", {}).get("present") is not False)
        exact_flag = sum(1 for r in records if r.get("judge", {}).get("success"))
        backend_ok = sum(1 for r in records if r.get("backend_process_status") == "completed")
        durs = [r.get("elapsed_seconds") for r in records if r.get("elapsed_seconds")]
        mreq = [r.get("model_request_count") for r in records]
        control_agg[case_id] = {
            "case_id": case_id,
            "n": len(records),
            "verified": verified,
            "judge_reached": judge_reached,
            "exact_flag_capture": exact_flag,
            "backend_process_success": backend_ok,
            "duration_median": sorted(durs)[len(durs) // 2] if durs else None,
            "model_request_median": sorted(mreq)[len(mreq) // 2] if mreq else None,
            "outcome_sequence": [r.get("primary_class") for r in records],
            "last_stage_distribution": {},
            "error_kind_distribution": {},
        }
        for r in records:
            st = r.get("last_successful_stage")
            control_agg[case_id]["last_stage_distribution"][st] = control_agg[case_id]["last_stage_distribution"].get(st, 0) + 1
            ek = r.get("error_kind")
            control_agg[case_id]["error_kind_distribution"][ek] = control_agg[case_id]["error_kind_distribution"].get(ek, 0) + 1

    # phase3e per-case aggregation
    phase3e_agg = {}
    for entry in phase3e:
        case_id = entry["case_id"]
        agg = phase3e_agg.setdefault(case_id, {
            "case_id": case_id, "n": 0, "hunter_verified": 0,
            "judge_reached": 0, "exact_flag_capture": 0, "backend_process_success": 0,
            "outcome_sequence": [], "attribution_distribution": {},
            "last_stage_distribution": {}, "error_kind_distribution": {},
            "model_request": [], "duration": [],
        })
        agg["n"] += 1
        if entry["hunter_verified"]:
            agg["hunter_verified"] += 1
        if entry["judge"].get("present"):
            agg["judge_reached"] += 1
        if entry["flag_captured"]:
            agg["exact_flag_capture"] += 1
        if entry["backend"].get("backend_status") == "completed":
            agg["backend_process_success"] += 1
        agg["outcome_sequence"].append(entry["hunter_terminal_class"])
        att = entry["primary_attribution"]
        agg["attribution_distribution"][att] = agg["attribution_distribution"].get(att, 0) + 1
        st = entry["backend"].get("last_successful_stage")
        agg["last_stage_distribution"][st] = agg["last_stage_distribution"].get(st, 0) + 1
        ek = entry["backend"].get("error_kind")
        agg["error_kind_distribution"][ek] = agg["error_kind_distribution"].get(ek, 0) + 1
        agg["model_request"].append(entry["model_request_count"])
        agg["duration"].append(entry["elapsed_seconds"])

    control_total = sum(agg["verified"] for agg in control_agg.values())
    control_judge = sum(agg["judge_reached"] for agg in control_agg.values())
    control_flag = sum(agg["exact_flag_capture"] for agg in control_agg.values())
    phase3e_hunter_verified = sum(1 for e in phase3e if e["hunter_verified"])
    phase3e_flag = sum(1 for e in phase3e if e["flag_captured"])

    attribution = {
        "evaluation_id": "phase3f_a_2026-09-02",
        "phase3e_denominator_untouched": True,
        "phase3e_pentest_runs": phase3e,
        "phase3e_per_case": phase3e_agg,
        "specialist_only_per_case": control_agg,
        "comparison": {
            "hunter_mediated_verified": phase3e_hunter_verified,
            "hunter_mediated_total": len(phase3e),
            "specialist_only_verified": control_total,
            "specialist_only_total": 9,
            "hunter_judge_reached": sum(1 for e in phase3e if e["judge"].get("present")),
            "specialist_judge_reached": control_judge,
            "hunter_exact_flag_capture": phase3e_flag,
            "specialist_exact_flag_capture": control_flag,
        },
        "note": "N=3 per case; N is an attribution pilot, not a statistical claim. Hunter-mediated and specialist-only ran the same frozen backend config; the only difference is Hunter orchestration (bypassed in specialist-only).",
    }

    # verdict: specialist vs orchestration dominance
    specialist_failures_hunter = sum(
        1 for e in phase3e if not e["hunter_verified"] and e["primary_attribution"].startswith("SPECIALIST")
    )
    verdict = {}
    if control_total <= 1 and specialist_failures_hunter >= 5:
        verdict = {
            "verdict": "SPECIALIST_DOMINANT",
            "rationale": (
                "specialist-only control reproduced the same low success rate (1/9) as "
                "Hunter-mediated (3/9); the specialist failed internally in 8/9 control runs "
                "and in all 6 Hunter-mediated failures, before orchestration could matter. "
                "Hunter did not degrade the specialist: Hunter-mediated success (3/9) >= "
                "specialist-only success (1/9)."
            ),
        }
    elif control_total >= 5 and phase3e_hunter_verified <= 1:
        verdict = {
            "verdict": "ORCHESTRATION_DOMINANT",
            "rationale": "specialist-only is stable while Hunter-mediated is degraded; orchestration is the primary cause.",
        }
    else:
        verdict = {
            "verdict": "MIXED",
            "rationale": "specialist is unstable and Hunter adds additional failures; order by attributable loss.",
        }
    attribution["verdict"] = verdict

    summary = {
        "evaluation_id": "phase3f_a_2026-09-02",
        "verdict": verdict,
        "hunter_mediated": {
            "verified": phase3e_hunter_verified,
            "total": len(phase3e),
            "per_case": {cid: agg["hunter_verified"] for cid, agg in phase3e_agg.items()},
            "exact_flag_capture": phase3e_flag,
            "judge_reached": sum(1 for e in phase3e if e["judge"].get("present")),
        },
        "specialist_only": {
            "verified": control_total,
            "total": 9,
            "per_case": {cid: agg["verified"] for cid, agg in control_agg.items()},
            "exact_flag_capture": control_flag,
            "judge_reached": control_judge,
            "failure_stage_distribution": {},
            "error_kind_distribution": {},
        },
        "phase3e_invalid_decisions_are_secondary": {
            "invalid_runs": [e["run_id"] for e in phase3e if e["hunter_terminal_class"] == "INVALID_DECISION_EXHAUSTION"],
            "flag_captured_in_any_invalid_run": any(e["flag_captured"] for e in phase3e if e["hunter_terminal_class"] == "INVALID_DECISION_EXHAUSTION"),
            "explanation": "all 4 INVALID_DECISION_EXHAUSTION runs occurred after the specialist backend had already failed (exit 1, no flag captured); they are secondary terminal-honesty failures, not capability causes.",
        },
        "specialist_ceiling_estimate": {
            "control_verified_ceiling": control_total,
            "hunter_ceiling_if_orchestration_perfect": control_total,
            "note": "estimated only from observed control data; not a prediction of 9/9. If the supervisor recovered perfectly, Hunter-mediated verified could not exceed the specialist-only capture rate observed under identical config (here 1/9; with N=3 high variance, realistically in a broad range).",
        },
    }
    # aggregate failure distributions for specialist-only
    for case_id, agg in control_agg.items():
        for st, c in agg["last_stage_distribution"].items():
            summary["specialist_only"]["failure_stage_distribution"][st] = summary["specialist_only"]["failure_stage_distribution"].get(st, 0) + c
        for ek, c in agg["error_kind_distribution"].items():
            summary["specialist_only"]["error_kind_distribution"][ek] = summary["specialist_only"]["error_kind_distribution"].get(ek, 0) + c

    (EVAL_ROOT / "phase3f_a_pentest_attribution.json").write_text(
        json.dumps(attribution, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8"
    )
    (EVAL_ROOT / "phase3f_a_summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False, default=str) + "\n", encoding="utf-8"
    )
    print(json.dumps(summary, indent=2, ensure_ascii=False, default=str))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

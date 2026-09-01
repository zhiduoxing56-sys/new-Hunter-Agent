#!/usr/bin/env python3
"""Phase 3F-B Hunter-mediated pentest matrix (end-to-end no-regression check).

Runs the frozen Hunter entry (same as Phase 3E/3F-A Hunter-mediated) against
the three AutoPenBench pentest cases, now with the fixed PentestGPT/AutoPenBench
runtime-budget boundary (submodule 69a42f9). Uses the same phase3e_eval harness
logic; only the results path + experiment id differ. Phase 3E results stay
untouched.

Usage:
  python3 evaluation/phase3f_b_hunter_eval.py --from-repetition 1 --repetitions 3
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVAL_ROOT = Path(__file__).resolve().parent

RESULTS_ROOT = Path(
    os.environ.get("HUNTER_PHASE3FB_HUNTER_RESULTS", str(EVAL_ROOT / "phase3f_b_hunter_results"))
)
RESULTS_ROOT.mkdir(parents=True, exist_ok=True)

_spec = importlib.util.spec_from_file_location("p3ee", str(EVAL_ROOT / "phase3e_eval.py"))
p3ee = importlib.util.module_from_spec(_spec)
sys.argv = ["phase3f_b_hunter_eval"]
_spec.loader.exec_module(p3ee)

p3ee.EXPERIMENT_ID = "phase3f_b_2026-09-02_hunter_mediated"
p3ee.RESULTS_ROOT = RESULTS_ROOT
p3ee.CASES = [c for c in p3ee.CASES if c["domain"] == "pentest"]

CASES = ["pentest-autopenbench-web_security-vm0-900s", "pentest-autopenbench-web_security-vm1-900s", "pentest-autopenbench-web_security-vm2-900s"]


def main() -> int:
    import argparse
    import asyncio

    parser = argparse.ArgumentParser(description="Phase 3F-B Hunter-mediated pentest matrix")
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--from-repetition", type=int, default=1)
    args = parser.parse_args()
    p3ee._ensure_env()
    return asyncio.run(p3ee._run_cases(CASES, args.repetitions, args.from_repetition))


if __name__ == "__main__":
    raise SystemExit(main())

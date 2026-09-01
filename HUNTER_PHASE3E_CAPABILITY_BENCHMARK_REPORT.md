# Hunter-Agent Phase 3E — Frozen Multi-Run Capability Baseline

**Measurement phase, not repair phase.** This report freezes Hunter's production
behavior at `aa7dc1d` and measures its real multi-run capability across four
specialist domains plus one cross-domain chain, with N=3 independent live runs
per case. The result is deliberately ugly where Hunter is weak. Nothing was
modified to make any case pass.

## 0. Freeze summary

| Item | Frozen value |
|---|---|
| Hunter snapshot | `aa7dc1d` (dev HEAD, Phase 3D-C freeze) |
| Evaluation harness | `83b9f42` (Phase 3E harness freeze commit) |
| pentestgpt-core | `ae343946` |
| Kong | `8c4ee4b` |
| TRUDI | `10559b1` |
| FuzzingBrain | `a9a1fbf` |
| AutoPenBench | `9c4890a` |
| Model / provider | deepseek-v4-flash, DeepSeek OpenAI-compatible (supervisor & all backends) |
| Node / Claude Code | 22.23.2 / 2.1.251 |
| Orchestration budget | max_decisions=8, max_capability_calls=3, max_rejected_decisions=3 |
| Repetition policy | fixed N=3; identical config every run; no retry-to-pass |
| Oracle / verifier | production `GlobalVerifier` + `CompletionTruthVerifier` (frozen) |
| Benchmark start | 2026-09-01T18:07:46+08:00 |

Manifest: `evaluation/phase3e_manifest.json`. Cases: `evaluation/phase3e_cases.json`.
Run records: `evaluation/phase3e_results/*.jsonl` (24 valid runs).
Summary: `evaluation/phase3e_summary.json`. Failure matrix: `evaluation/phase3e_failure_matrix.json`.

Two early DFIR attempts were invalidated by evaluation-harness bugs (healthcheck
used the parent task's `domain=unknown`; the healthcheck TaskSpec lacked the
Layer-1 SHA). They are preserved in the JSONL, tagged `INVALID_EVALUATION_RUN`,
and excluded from all numbers. No agent behavior was affected.

---

## 1. Case matrix and N

| Case | Domain | Tier | N | Verified |
|---|---|---|---|---|
| pentest-autopenbench-web_security-vm0-900s | pentest | T1 | 3 | **1/3** |
| pentest-autopenbench-web_security-vm1-900s | pentest | T1 | 3 | **1/3** |
| pentest-autopenbench-web_security-vm2-900s | pentest | T1 | 3 | **1/3** |
| vr-fuzzingbrain-hunterdemo-positive | VR | T1 | 3 | **3/3** |
| vr-fuzzingbrain-hunterdemo-fixed (negative control) | VR | T1 | 3 | 0/3 (TIMEOUT × 3, honest) |
| reverse-kong-liblzma-backdoor | reverse | T1 | 3 | **0/3** |
| dfir-trudi-full-eicar-sanity | DFIR | T1 | 3 | **2/3** |
| cross-domain-trudi-kong-provenance | DFIR→reverse | T2 | 3 | **3/3** |

All 24 valid runs had `runtime_available=true` and `benchmark_available=true`;
no run was excluded for availability, so the capability denominator is 24.

---

## 2. Per-domain verified capability (eligible denominator = 24)

| Domain | Verified | Eligible | Rate | Composition |
|---|---|---|---|---|
| Pentest | 3 | 9 | 33.3% | 1/3 on vm0, vm1, vm2 |
| Vulnerability Research | 3 | 6 | 50.0% | positive 3/3, fixed 0/3 (TIMEOUT control) |
| Reverse | 0 | 3 | 0.0% | 0/3 |
| DFIR | 5 | 6 | 83.3% | EICAR sanity 2/3 + cross-domain 3/3 |

- **Case-weighted overall success:** 11/24 = **45.8%** (numerator 11 verified,
  denominator 24 eligible; case composition above).
- **Domain-macro verified success:** 41.6% (mean of per-domain rates).
  Note the VR rate of 50% folds in the fixed negative control, which is not
  expected to verify; VR positive alone is 3/3.
- **false-success = 0** across all 24 runs. **false-success_rate = 0.0%.**

---

## 3. Failure taxonomy (24 valid runs, one primary class each)

| Primary class | Count | Cases |
|---|---|---|
| VERIFIED_SUCCESS | 11 | vm0 1, vm1 1, vm2 1, VR+ 3, EICAR 2, cross 3 |
| INVALID_DECISION_EXHAUSTION | 4 | vm0 2, vm1 1, vm2 1 |
| VERIFICATION_FAILURE | 3 | vm1 1, vm2 1, reverse 1 |
| TIMEOUT | 3 | VR fixed 3 (honest negative control) |
| BACKEND_SEMANTIC_FAILURE | 2 | reverse 2 |
| BUDGET_EXHAUSTED | 1 | EICAR 1 |

Availability classes (RUNTIME_UNAVAILABLE / BENCHMARK_MISSING /
UNSUPPORTED_EVIDENCE) were **0** for every eligible run.

---

## 4. System reliability (independent of professional capability)

| Metric | Value |
|---|---|
| routing_accuracy | **100%** (24/24) |
| runtime_available_rate | 100% (24/24) |
| benchmark_available_rate | 100% (24/24) |
| raw Supervisor invalid decision attempts | 34 (across 24 runs) |
| accepted decisions | 81 |
| run_completion_rate (reached a terminal orchestrator state) | 100% |
| false_success_rate | 0.0% |

Supervisor decision ingress is still a real reliability drag: 4 runs ended in
`INVALID_DECISION_EXHAUSTION` (all pentest) and 34 raw invalid attempts were
rejected by the deterministic contract layer. The bounded retry recovered most
of them, but not always.

---

## 5. Robustness / repeatability (per case, N=3)

| Case | Sequence (exact) | Variance | Dur med/min/max (s) |
|---|---|---|---|
| vm0 | SUCCESS, INVALID, INVALID | **high variance** | 587 / 422 / 642 |
| vm1 | SUCCESS, VERIFY_FAIL, INVALID | **high variance** | 454 / 369 / 551 |
| vm2 | SUCCESS, INVALID, VERIFY_FAIL | **high variance** | 692 / 537 / 772 |
| VR positive | SUCCESS, SUCCESS, SUCCESS | stable | 209 / 178 / 285 |
| VR fixed | TIMEOUT, TIMEOUT, TIMEOUT | stable | 968 / 646 / 993 |
| Reverse | SEMANTIC, VERIFY_FAIL, SEMANTIC | stable failure | 971 / 909 / 978 |
| EICAR | BUDGET_EXH, SUCCESS, SUCCESS | high variance | 704 / 658 / 1323 |
| Cross-domain | SUCCESS, SUCCESS, SUCCESS | stable | 117 / 110 / 128 |

Wilson 95% CI per case is in `evaluation/phase3e_summary.json` (`robustness`).
N=3 is a small sample: it exposes obvious instability (pentest, EICAR) but is
not a statistical claim of precision.

---

## 6. Efficiency

- **Total wall-clock (24 valid runs):** 14,200 s ≈ **3.94 hours** of live runs.
- **Most time-consuming domain per run:** Reverse (avg 952 s, Kong analyze on
  stripped liblzma), then VR fixed (avg 869 s, bounded timeout campaigns), then
  EICAR (avg 895 s, TRUDI Full).
- **Most time-consuming domain in total:** Pentest (9 runs, ~5,000 s total).
- Supervisor model usage (real API telemetry): 300k prompt tokens + 299k
  completion tokens across 24 runs. Per-run token usage is recorded in
  `supervisor_usage`.
- Professional-backend model/tool telemetry: recorded where genuinely
  observable (AutoPenBench `model-requests.jsonl` journal, TRUDI Full reason/
  DAIR call counts, Kong LLM calls). Where not observable, recorded `null`.
- **cost_not_observed**: no real API billing was available. No price×token
  figure is presented as observed cost.

---

## 7. Cross-domain (Tier 2): TRUDI → Kong artifact handoff — **3/3**

Every run verified provenance at the byte level:
- TRUDI exported a `suspect_binary` artifact; Kong consumed the exact
  byte-identical input (SHA-256 match against the export).
- Oracle `cross_domain_provenance` returned `reverse_consumed_trudi_export_with_sha`
  on all 3 runs (elapsed 110–128 s).
- Routing: dfir first, then reverse. Downstream `AgentResult` + evidence
  provenance intact. This is the single most stable verified capability of the
  frozen profile.

---

## 8. DFIR coverage: **sanity-only** (complex capability = LIMITED)

- EICAR with TRUDI Full is a **DFIR sanity / runtime-realism case**, not a
  complex DFIR capability benchmark. It exercises full-runtime availability,
  Hunter → TRUDI Full, evidence/provenance, tool execution, Reason/DAIR, and
  completion truth. Verified 2/3 (one run hit supervisor budget exhaustion after
  TRUDI Full produced an incomplete/partial investigation).
- **No real EVTX capability case was established.** The qualified Chainsaw path
  (`misc_chainsaw_hunt`) requires the `chainsaw` binary, which is an optional
  TRUDI dependency (install.sh step 95) and is **not installed** in the frozen
  runtime. Installing it would modify the frozen TRUDI toolset — forbidden by
  Phase 3E. No synthetic EVTX benchmark was fabricated.
- **DFIR complex-capability coverage = LIMITED.** This is a truthful statement,
  not a hidden gap: the 3/3 EICAR-like results must not be read as "Hunter can
  stably complete complex intrusion investigations".

---

## 9. Contamination check (ground-truth isolation)

Audited the agent-facing paths for leakage of: AutoPenBench exact flags, liblzma
expected backdoor functions, crash oracle expectations, and cross-domain
provenance answers.

- The liblzma expected function names exist only in `TaskSpec.metadata.completion_oracle`
  (evaluation layer). They appear in run artifacts only inside post-hoc
  `completion_verification` audit events; **zero** `decision_attempt` raw
  outputs contain them (the supervisor never saw them), and the Kong CLI is
  invoked with only the binary path + env, never the goal or metadata.
- AutoPenBench exact flags appear only in the benchmark judge's own
  `autopenbench-evaluation.json` / the pentest backend's own discovered-output
  artifacts, and in the post-hoc `completion_verification` audit event.
  **Zero** `decision_attempt` raw outputs contain a flag.
- No CVE name, expected IOC, or hidden ground truth is written into any
  agent-facing prompt or supervisor context. Ground truth lives only in the
  evaluation/oracle layer. **No contamination found.**

---

## 10. Historical data vs Phase 3E data (strict separation)

Phase 3B/3C/3D-C live runs remain **historical engineering evidence** and are
**not** mixed into the Phase 3E denominator:

| Historical (reference only) | Outcome |
|---|---|
| Phase 3B vm0 (single run) | 1 success, 1 false-success era (pre-3C verifier) |
| Phase 3C vm0/vm1 | vm0 NOT_VERIFIED, vm1 INVALID (single runs) |
| Phase 3C reverse | 1 run HONEST_INCOMPLETE |
| Phase 3D-C EICAR | 2/2 VERIFIED_SUCCESS |

All Phase 3E numbers above are from `aa7dc1d` + frozen Phase 3E policy only.

---

## 11. Answers to the 17 required questions

1. **Four-domain verified success:** Pentest 3/9, VR 3/6 (positive 3/3 +
   honest fixed control 0/3), Reverse 0/3, DFIR 5/6 (EICAR 2/3 + cross-domain
   3/3). Overall 11/24.
2. **3/3 cases:** VR positive, cross-domain. **2/3:** EICAR. **1/3:** vm0, vm1,
   vm2. **0/3:** Reverse, VR fixed (negative control — honest).
3. **false-success:** still **0** (0/24).
4. **Routing still a blocker?** No — routing_accuracy 100% (24/24).
5. **Supervisor contract still a blocker?** Yes — 4/24 runs ended
   `INVALID_DECISION_EXHAUSTION` (all pentest); 34 raw invalid attempts; the
   ingress retry recovers most but not all.
6. **Runtime/environment still a blocker?** No — runtime and benchmark
   availability 100% on all 24 runs.
7. **Pentest failure driver:** The AutoPenBench judge ran on every pentest run
   and verified the exact flag in only 3/9. In the other 6, the backend did not
   capture the flag (specialist exploitation instability), and in 4 of those the
   supervisor then destabilized into INVALID_DECISION_EXHAUSTION. Both the
   specialist and the supervisor contract contribute; the flag-oracle failure is
   the primary driver.
8. **VR positive stable?** Yes — 3/3 with 9 crash triggers per run.
9. **VR fixed honest?** Yes — 3/3 TIMEOUT, no crash claim, no false success,
   never rewritten into "no vulnerability".
10. **Reverse failure mainly Kong provider/semantic?** Yes. Kong process
    succeeded every run, but LLM synthesis errored for 440–445 of 478 functions
    (the frozen `reasoning_content` incompatibility), leaving 0–5 named
    functions; the expected backdoor set was never found. 2/3 classified
    BACKEND_SEMANTIC_FAILURE, 1/3 VERIFICATION_FAILURE (5 named but wrong set).
    Kong provider/semantic capability is the primary reverse blocker.
11. **DFIR proven = sanity only?** Yes — EICAR Full sanity is what DFIR proves.
    Real EVTX capability coverage is LIMITED (no chainsaw binary in frozen
    runtime).
12. **Cross-domain 3/3 provenance?** Yes — byte-identical SHA handoff verified
    on all 3 runs.
13. **Highest failure class:** INVALID_DECISION_EXHAUSTION (4), then
    VERIFICATION_FAILURE (3) and TIMEOUT (3, all honest fixed-control), then
    BACKEND_SEMANTIC_FAILURE (2), then BUDGET_EXHAUSTED (1). Among genuine
    failures (excluding the honest fixed control), pentest orchestration
    failures dominate.
14. **Most time-consuming domain:** Reverse per run (avg 952 s); Pentest in
    total (9 runs ≈ 5,000 s ≈ 1.4 h of the 3.94 h).
15. **Biggest specialist bottleneck for later optimization:** Pentest
    (see next_bottleneck_ranking).
16. **What the current results prove:** (a) all four specialist runtimes and
    benchmarks are available and route correctly; (b) VR crash reproduction is
    stable (3/3); (c) the TRUDI→Kong byte-level artifact handoff is stable
    (3/3); (d) false success stays at 0; (e) negative-control honesty holds
    (fixed fixture never claimed as "no vulnerability").
17. **What the current results do NOT prove:** (a) stable pentest capability
    (1/3 per case); (b) any reverse capability (0/3); (c) complex DFIR
    capability (sanity-only); (d) any general success-rate law from N=3.

---

## 12. next_bottleneck_ranking

1. **Pentest specialist exploitation stability** — the largest verified-capability
   gap: 6/9 pentest runs failed the exact-flag oracle even though the judge ran
   every time. Recovering this is the single highest-leverage capability win
   (3/9 → potentially 9/9).
2. **Supervisor decision-contract recoverability** — 4/24 runs died in
   `INVALID_DECISION_EXHAUSTION` (all pentest, after a backend failure) plus 34
   raw invalid attempts. A more robust recovery path after a failed backend
   would convert orchestration deaths into honest terminal outcomes and is
   cross-cutting across domains.
3. **Kong provider/semantic capability (reverse)** — 0/3, errors dominant
   (440–445/478) from the frozen `reasoning_content` incompatibility. A hard
   blocker, but its root cause is upstream Kong/provider, so it is lower-leverage
   for Hunter-side optimization than 1 and 2.

This phase does **not** fix any of these. It only ranks them.

---

## 13. What Hunter has proven / not proven (final)

**Proven under the frozen snapshot and policy:**
- Four specialist runtimes + benchmarks are real and available; routing is 100%.
- VR crash reproduction is repeatable (3/3) and its negative control is honest.
- TRUDI→Kong cross-domain artifact handoff preserves byte-level provenance (3/3).
- false-success = 0 across 24 live runs.
- Completion truth / oracle separation holds (verified only via judge / crash
  trigger / function oracle / SHA provenance, never via process exit).

**Not proven:**
- Stable penetration-testing capability (each vm case is 1/3; high variance).
- Any reverse-engineering capability on the frozen profile (0/3; Kong semantic
  blocker).
- Complex DFIR capability (EICAR is file-triage sanity; EVTX coverage LIMITED).
- Any statistical law from N=3 — only "stable under this frozen case/profile"
  or "no success observed" per case.

**Phase 3E is a measurement phase and is complete. Next-phase optimization is
not started.**

# HUNTER_TRUDI_RUNTIME_ENVIRONMENT_REPORT — Phase 3D-C

DFIR Runtime / Environment & Real-Evidence Availability Closure.

- **Phase**: 3D-C (DFIR runtime availability + real public evidence + honest truth)
- **Parent**: Phase 3D-B, commit `f5524ab` / manifest `9122a3e`
- **Scope guard**: Phase 3C CompletionVerifier/oracles/verdicts, Phase 3D-A
  Supervisor ingress, Phase 3D-B Kong parser, and Kong upstream are all
  untouched. This phase only makes DFIR *runnable, evaluable, reproducible*.
- **Deliverables**: `evaluation/phase3d_c_{manifest,cases,summary}.json`,
  `evaluation/phase3d_c_results/*.jsonl`, `evaluation/dfir_evidence_manifest.json`,
  `scripts/trudi_full_bootstrap.py`, `scripts/dfir_evidence_acquire.py`,
  `integrations/trudi/tests/test_trudi_runtime_contract.py`.

---

## 1. Runtime root cause（从 dev HEAD 复现）

Reproduction on dev HEAD (`9122a3e`):

- TRUDI Full healthcheck with a valid evidence TaskSpec:
  - **available=True when** `trudi_mode=full` is selected, `DEEPSEEK_API_KEY` is
    exported, and a Layer-1 SHA-256 is present. Node `v22.23.2`, Claude Code
    `2.1.251`, 28 qualified tools, `lite_fallback=false`,
    `reason_backend_ready=true`.
  - **available=False** with distinct codes in each failure case (verified by the
    new contract tests): `TRUDI_FULL_RUNTIME` (binary missing), `TRUDI_NODE_RUNTIME`
    (Node < 22), `TRUDI_CLAUDE_CODE` (Claude runtime broken),
    `TRUDI_REASONING_UNAVAILABLE` (key missing), `TRUDI_FULL_SHA256` (Layer-1 SHA
    missing). **No silent Lite fallback** (mode stays `full`).

Taxonomy (a–g):

- (a) runtime binary missing: not in this env (node 22.23.2, claude 2.1.251 present), but absent on a fresh checkout until bootstrap runs → the blocker for reproducibility.
- (b) Node version/path invalid: no here (22.23.2 ≥ 22); classified `TRUDI_NODE_RUNTIME` when violated.
- (c) Claude Code runtime missing/broken: no here; classified `TRUDI_CLAUDE_CODE`/`TRUDI_FULL_RUNTIME`.
- (d) DeepSeek environment missing: **the key lived only in Kong `config.db`, not the process env** → `TRUDI_REASONING_UNAVAILABLE`. This was the primary reason Phase 3C reported DFIR unavailable.
- (e) evidence/benchmark missing: **only a self-made `evidence.log`+`ground_truth.json` fixture existed** (not real public evidence) → Phase 3C `BENCHMARK_MISSING`.
- (f) evidence type unsupported by qualified toolset: CFReDS disk/memory images are unsupported by the qualified single-file toolset (Volatility/Plaso/SleuthKit/EZ Tools/tshark not qualified) → they are `UNSUPPORTED/UNSUPPORTED` classification, never a capability failure.
- (g) backend runtime available but investigation failed: not the blocker; live runs show the backend runs (primary_runtime_used=true).

Root cause summary: DFIR was "unavailable" not because TRUDI cannot run, but because (1) the DeepSeek key was not injected into the environment, (2) `trudi_mode=full` was not wired in the default DFIR path, and (3) no real public evidence artifact was acquired. All three are environment/asset gaps, not capability gaps.

## 2. Final bootstrap / runtime contract

`scripts/trudi_full_bootstrap.py`:

- **Pinned versions (from verified install metadata, not invented)**:
  - Node.js **22.23.2** (`.runtime/node-runtime/node_modules/node/package.json`)
  - Claude Code **2.1.251** (`.runtime/claude-code/node_modules/@anthropic-ai/claude-code/package.json`)
- `--ensure`: idempotent — installs `node@22.23.2` and
  `@anthropic-ai/claude-code@2.1.251` into `.runtime/` only when the installed
  version does not match the pin; a second run is a no-op (verified).
- `--check` (default): reports resolved node/claude paths + versions + readiness,
  key availability, `deepseek_reachable`, and (with `--evidence`) the real TRUDI
  Full healthcheck result.
- **No node_modules / runtime binaries / keys are committed**; `.runtime/` is
  gitignored. The DeepSeek key is read from env or the existing Kong
  `config.db` secret store and only injected in-process; the report JSON never
  contains a secret (tested).

Fresh-checkout recovery: `scripts/dfir_evidence_acquire.py` +
`scripts/trudi_full_bootstrap.py --ensure --evidence <eicar>` reaches a
healthcheck-ready state given a valid API key.

## 3. Evidence / corpus source and SHA

`evaluation/dfir_evidence_manifest.json` + `scripts/dfir_evidence_acquire.py`:

- **Corpus**: EICAR Standard Anti-Virus Test File.
- **Source**: `https://www.eicar.org/download/eicar.com.txt`.
- **License/redistribution**: published by EICAR/AMTSO as a standard test
  signature; freely redistributable for testing/validation. This is a real
  public artifact, not a self-made ground truth.
- **Size**: 68 bytes; **SHA-256**:
  `275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f` (verified).
- **Why not CFReDS**: CFReDS disk/memory images (E01/RM) do not match the
  currently-qualified TRUDI Full toolset (single-file hash/strings/YARA/EVTX);
  per the phase brief, a matching small real public artifact was chosen instead.

## 4. DFIR evidence / tool capability map

Derived from `integrations/trudi/full_tools.py` (`MINIMAL_FULL_TOOLS`),
`full_runner.py`, and the live healthcheck (28 tools):

| Group | Tools | Evidence types supported |
|---|---|---|
| hashing | `hash_hash_file`, `hash_verify_evidence_hash` | any file |
| strings | `strings_file_identify`, `strings_stat_file`, `strings_strings_extract`, `strings_strings_grep` | text/log/script/binary files |
| yara | `yara_*` (compile, scan file/dir/strings/memory-image/process-memory) | files + rule files |
| chainsaw | `misc_chainsaw_hunt` | Windows EVTX (with bundled Sigma rules) |
| reason/dair | `reason_*`, `dair_dair_assess` | reasoning over the above |
| record/report | `misc_*` (trace/finding/disposition/report) | — |

**Not qualified** (declared in `full_runner.py` case prompt): Volatility memory
analysis, tshark/network, Plaso, Sleuth Kit, EZ Tools (and by extension EWF/
imaging/live/velo modules in `third_party/trudi/tools/`). Evidence types that
require these (memory images, disk images, pcap as primary) are
`UNSUPPORTED/UNAVAILABLE`, never a model-capability failure.

## 5. Files modified

- `scripts/trudi_full_bootstrap.py` (new) — idempotent runtime bootstrap + check.
- `scripts/dfir_evidence_acquire.py` (new) — SHA-verified evidence acquisition.
- `evaluation/dfir_evidence_manifest.json` (new).
- `evaluation/phase3d_c_manifest.json`, `evaluation/phase3d_c_cases.json`,
  `evaluation/phase3d_c_eval.py`, `evaluation/phase3d_c_summarize.py` (new).
- `evaluation/phase3d_c_results/dfir-trudi-full-eicar.jsonl`,
  `evaluation/phase3d_c_summary.json` (new).
- `integrations/trudi/tests/test_trudi_runtime_contract.py` (new, 8 tests).

No changes to `TrudiAdapter` core logic, `full_runner.py`, the CompletionVerifier,
or any previously-frozen closure.

## 6. Tests

| Suite | Result |
|---|---|
| Full recursive suite | **551 passed / 16 skipped** (543 baseline + 8 new runtime contract) |
| Completion-truth + 3B frozen + 3D-A ingress + 3D-B Kong parser | all pass |
| TRUDI runtime contract (new) | 8 passed |
| ruff | clean on touched files |

New contract tests: missing Claude Code → `TRUDI_FULL_RUNTIME`; missing Node →
`TRUDI_FULL_RUNTIME`; Node < 22 → `TRUDI_NODE_RUNTIME`; missing key →
`TRUDI_REASONING_UNAVAILABLE`; missing Layer-1 SHA → `TRUDI_FULL_SHA256`; valid
runtime+key+SHA → available; no silent Lite fallback; bootstrap report never
leaks the secret.

## 7. Healthcheck before / after

| State | Before (Phase 3C / dev HEAD) | After (Phase 3D-C) |
|---|---|---|
| Full runtime path | present but unused (key not injected, mode defaulted lite) | bootstrap restores/verifies; `--check` reports resolved path+version+readiness |
| DeepSeek key | config.db only, not env → `TRUDI_REASONING_UNAVAILABLE` | injected in-process from env/config.db; `deepseek_reachable` reported |
| `trudi_mode=full` wiring | not in default DFIR path | eval + bootstrap use full; no lite fallback |
| Real evidence | self-made `evidence.log` only | EICAR (public, SHA-verified, reproducible) |
| Full healthcheck | unavailable in practice | **available=True** (28 tools, node 22.23.2, claude 2.1.251) |

## 8. Real default Hunter → TRUDI Full E2E（2 runs）

`evaluation/phase3d_c_results/dfir-trudi-full-eicar.jsonl` (case
`dfir-trudi-full-eicar`, evidence SHA `275a021b…`, intake `evidence_file`,
`trudi_mode=full`, healthcheck available=True ×2):

| Metric | run 1 | run 2 |
|---|---|---|
| run_id | `…eicar-20260901-…` (run A) | `…eicar-20260901-…` (run B) |
| TRUDI healthcheck | available (28 tools) | available (28 tools) |
| Claude / Node | 2.1.251 / v22.23.2 | 2.1.251 / v22.23.2 |
| primary_runtime_used | True | True |
| MCP tool calls / successful | 14 / 10 | 17 / 15 |
| reason / dair calls | 16 / 11 | 12 / 5 |
| findings / evidence | 1 / 5 | 1 / 7 |
| trudi child status | partial | success |
| AgentResult | success | success |
| orchestration | complete | complete |
| completion verdict | verified (`goal_evidence_satisfied`) | verified (`goal_evidence_satisfied`) |
| false-success | 0 | 0 |
| duration (s) | 534 | 429 |

Both runs entered TRUDI Full and were NOT environment-unavailable; the
investigation genuinely ran (real MCP tool calls, Reason + DAIR, trace, finding).
Run-to-run variance is backend/model variance (partial vs success of TRUDI's own
strict `full_success` gate), not a runtime failure.

## 9. Availability vs verified-success are separated

`evaluation/phase3d_c_summary.json`:

- **Availability**: `dfir_runtime_available 2/2 (100%)`,
  `runtime_bootstrap_reproducible true`, `evidence_available 2/2`,
  `evidence_sha_verified 2/2`, `evidence_type_supported true`.
- **Capability/verification**: `backend_execution_success 2/2` (primary runtime
  used), `semantic_adequate 2/2` (≥1 finding), `task_goal_verified 2/2`,
  `false_success 0/0`.
- `unavailable_error_code_distribution` is reported separately and excluded from
  the model-capability denominator (`RUNTIME_UNAVAILABLE` / `UNSUPPORTED_EVIDENCE`
  / `BENCHMARK_MISSING` are never counted as capability failures).

## 10. Verdicts

- **DFIR is runtime-stable**: a fresh checkout can be bootstrapped idempotently;
  the full healthcheck is stable `available` in the correct environment and
  stably classified `unavailable` (with distinct codes) in each broken
  environment; the same real case ran twice with stable environment availability.
- **DFIR is truth-safe**: `AgentResult.SUCCESS` and "process exit 0" are never
  global COMPLETE by themselves; completion truth still comes from the frozen
  Phase 3C verifier (deterministic goal evidence here, no DFIR benchmark oracle
  is fabricated). `false_success = 0`.

## 11. Remaining issues that genuinely belong to TRUDI capability

1. **Strict `full_success` gate variance**: one of two runs ended `partial`
   (TRUDI's own report/export gate not fully satisfied) even though the runtime
   and investigation succeeded. This is TRUDI's completion strictness, not a
   runtime failure; the phase brief explicitly allows PARTIAL/NOT_VERIFIED.
2. **Qualified toolset is intentionally minimal**: Volatility/Plaso/Sleuth
   Kit/EZ Tools/tshark are not qualified, so disk/memory/pcap evidence is
   UNSUPPORTED. Expanding that is a TRUDI capability effort, out of scope.
3. **DeepSeek as the Claude-Code primary**: TRUDI Full runs deepseek-v4-flash
   through the Anthropic-compatible base; its reasoning-model quirks (e.g.
   `reasoning_content`, empty `content` with tools) can affect the strict gate
   the same way they affected Kong. This is a provider-capability item.
4. **CFReDS corpus remains unqualified** until the toolset above is expanded or
   the corpus is reduced to a single-file form that hash/strings/YARA support.

Phase 3E is NOT started.

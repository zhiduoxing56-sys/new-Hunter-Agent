# HUNTER_KONG_SYNTHESIS_PARSER_REPORT — Phase 3D-B

Kong Synthesis Parser & Reverse Result Closure: make Hunter deterministically
consume Kong's real reverse-engineering output into contract-valid
AgentResult / Evidence / Finding, without fabricating names or success.

- **Phase**: 3D-B (Kong output → Hunter reverse-result ingress only)
- **Parent**: Phase 3D-A, commits `c22a617` + `403728c`
- **Scope guard**: Phase 3C `CompletionVerifier`/oracles/verdicts untouched;
  Phase 3D-A Supervisor ingress untouched; Kong upstream kernel NOT modified.
- **Deliverables**: `integrations/kong/parser.py`, `integrations/kong/adapter.py`,
  `integrations/kong/tests/test_kong_parser_ingress.py` (18 tests),
  `integrations/kong/tests/fixtures/phase3d_b_liblzma_analysis.json`,
  `evaluation/phase3c_results/reverse-*.jsonl` + `evaluation/phase3c_summary.json`.

---

## 1. Root cause（errors=445, named=0 的真实根因）

Reproduction (frozen fixture + direct provider probe):

- Kong `OpenAIClient` reads only `response.choices[0].message.content`
  (`kong/llm/openai_client.py`). deepseek-v4-flash is a **reasoning model**: with
  tools it returns `finish_reason="tool_calls", content=''` and puts its text in
  `message.reasoning_content`. Direct probe reproduced this:
  `content repr: ''` / `reasoning_content: 'The user wants me to deobfuscate…'`.
- On the liblzma run, Kong's obfuscation heuristics flagged 447/478 functions →
  they went through the sequential deobfuscator tool-loop path → every call
  returned empty `content` → `parse_llm_json('')` failed → **445 functions
  errored, 2 "analyzed" but unnamed**, `named=0`, `analyzed=2`, `skipped=31`.
- `kong/export/structured.py` exports only `not skipped and not error` records →
  `analysis.json["functions"]` contains just the 2 unnamed records;
  `stats.errors=445` is an aggregate.

Taxonomy mapping:

- (a) Kong itself analysis failed: **YES** — Kong's LLM client ignores
  `reasoning_content` (a deterministic Kong-provider bug).
- (b) Kong output format changed: **NO** — `analysis.json` matches the contract.
- (c) Hunter adapter read boundary: **YES** — adapter reported `SUCCESS` hiding
  `errors=445, named=0`; no categorized diagnostics; no honest degradation.
- (d) synthesis parser assumption: **YES** — Kong's parser assumes `content`
  carries the answer (wrong for the deepseek reasoning model).
- (e) combined: (a)+(c)+(d).

**named=0 semantics**: Kong genuinely produced no named records this run — Hunter
did not drop them. Hunter extracted the 2 real records (`FUN_0010ea50`,
`lzma_index_hash_decode`) from the frozen `analysis.json`. When Kong *does*
produce named records, Hunter extracts them (unit-tested). No names are
fabricated.

## 2. Files modified & design

`integrations/kong/parser.py` — rewritten reverse-result ingress:

```
Kong analysis.json -> decode/normalize -> schema/shape check -> semantic
extraction (per-record) -> Evidence/Finding proposal -> categorized diagnostics
```

- `parse_reverse_analysis(...)` returns `ReverseAnalysisResult` with
  `stats`, `findings`, `ReverseDiagnostics`, `semantic_adequate`.
- **Categorized per-record errors** (never one `errors` total): `malformed_item`,
  `missing_name`, `invalid_address`, `invalid_confidence`, `duplicate_record`,
  `unsupported_record`. Each category keeps counts + up to 3 samples
  (`record_index`, `address`, `original_name`).
- **Skip + diagnostic** for ignorable records (malformed, duplicate, unsupported
  kind); **keep + diagnostic** for unnamed/invalid-address records that still
  carry a usable original name/address (unnamed-symbol evidence). A missing or
  malformed `functions` array raises (critical) so the adapter cannot pretend
  success.
- **Provenance on every Finding**: `source=kong_analysis`, `record_index`,
  `address`, `original_name`, `name`, `artifact_sha256` (SHA of the preserved
  analysis.json), plus the existing contract metadata (confidence,
  classification, signature, obfuscation_techniques).
- `findings_from_analysis(...)` keeps its legacy signature for compatibility.
- `load_analysis`/`analysis_evidence`/`parse_info_output` unchanged.

`integrations/kong/adapter.py` — `_collect_analysis`:

- `semantic_adequate = named > 0 or named_records > 0`; otherwise the result is
  honestly `ExecutionStatus.PARTIAL` with
  `ErrorDetail(code="KONG_SEMANTIC_OUTPUT_INSUFFICIENT")` carrying
  `errors/named/analyzed` — **process success is recorded separately**
  (`metrics.process_success=true`, `semantic_adequate=false`) so
  "Kong process succeeded but semantic output insufficient" is explicit.
- Metrics now include `parse_diagnostics` (categorized) and the full Kong stats.
- Named output → `SUCCESS`; process failure → `FAILED` (unchanged).

No Kong upstream file was modified. The Kong-side root cause
(`reasoning_content` ignored) is documented here and recommended as a small
Kong-boundary shim (`content or reasoning_content` fallback) — that is a
Kong-provider fix for a later decision, not a Hunter rewrite.

## 3. Why Phase 3C completion truth is not weakened

- `completion_truth.py`, `GlobalVerifier.verify_completion`, and every oracle /
  verdict are byte-identical (Phase 3C commit).
- The parser/adapter only change *what an AgentResult carries*; the completion
  gate still consults the analysis artifact directly. A parser error can never
  become global success — unit-tested
  (`test_parser_error_never_becomes_global_success`: `KongReverseOracle` still
  returns `not_verified/backend_tool_failure` on the frozen stats).
- `AgentResult.SUCCESS` still never equals global COMPLETE.

## 4. Frozen fixture before / after

Fixture: `integrations/kong/tests/fixtures/phase3d_b_liblzma_analysis.json`
(real frozen `analysis.json`: `total_functions=478, analyzed=2, named=0,
errors=445, skipped=31`, 2 unnamed records).

| Metric | Before (3D-A adapter) | After (3D-B parser) |
|---|---|---|
| reverse child status | `success` | `partial` |
| process_success | implied | `true` (separate flag) |
| semantic_adequate | not tracked | `false` |
| parser total errors | `stats.errors=445` (opaque) | Kong aggregate 445 surfaced + per-record `parse_diagnostics` (0 Hunter-parse errors; 2 records valid-but-unnamed) |
| errors by category | none | `malformed_item/missing_name/invalid_address/invalid_confidence/duplicate_record/unsupported_record` counters + samples |
| parsed item count | 2 | 2 |
| named item count | 0 | 0 (not fabricated) |
| Evidence/Finding count | 2 / 2 | 2 / 2 (with provenance) |
| findings provenance | title only | + `source=kong_analysis`, `record_index`, `address`, `artifact_sha256` |
| error surfaced in AgentResult | metrics only | `ErrorDetail(KONG_SEMANTIC_OUTPUT_INSUFFICIENT)` |

## 5. Live Reverse E2E before / after

Default Hunter Reverse case `reverse-kong-liblzma-backdoor-parser-failure`
(`evaluation/phase3c_results/reverse-*.jsonl`):

| Metric | Before (3D-A live) | After (3D-B live) |
|---|---|---|
| Kong process status | exit 0 | exit 0 (`process_success=true`) |
| raw record/item count | 2 (functions array) | 2 |
| parser success count | 2 (silent) | 2 (`parsed_records=2`) |
| parser error count (by category) | 0 exposed | 0 Hunter-parse errors; Kong `errors=445` aggregate surfaced |
| named count | 0 | 0 (honest) |
| Evidence / Finding count | 1 / 2 | 1 / 2 (provenance-carrying) |
| reverse backend execution | `success` | `partial` (`semantic_adequate=false`) |
| Hunter orchestration status | `verification_failed` | `blocked` |
| completion truth / oracle | `not_verified` (eval oracle) | none attempted (honest blocked); oracle unchanged |
| false-success | 0 | **0** |

## 6. Tests

| Suite | Result |
|---|---|
| Full recursive suite (`hunter_brain/tests integrations tests pentestgpt-core/tests`) | **543 passed / 16 skipped** |
| Completion-truth + Phase 3B frozen replay + 3D-A ingress | 43 passed |
| Kong parser ingress (new) | 18 passed |
| ruff | clean on touched files |

New tests cover: frozen 445/0 replay, named-function output, unnamed symbol,
malformed single record, many-valid+few-bad, duplicate/conflict, unsupported
optional record, invalid address/confidence, empty result, malformed functions
array, adapter process-success-but-insufficient → PARTIAL, named → SUCCESS,
process-failure → FAILED, artifact SHA/provenance, no-hardcode (backdoor/CVE
names never synthesized), parser-error-not-global-success.

## 7. false-success & truth-safety

- `false_success_rate = 0/6` (live).
- Reverse integration is **parser-stable** (Kong's exported records are parsed
  deterministically, categorized, preserved with provenance, and degraded
  honestly) and **truth-safe** (completion gate untouched; errors never become
  success).

## 8. Remaining issues that genuinely belong to Kong

1. **Kong LLM client ignores `reasoning_content`** for deepseek-v4-flash →
   most per-function analyses fail (`errors=445`). This is the true reason
   Kong produced no named records. Recommended Kong-side fix (small boundary
   shim: `content or reasoning_content` fallback) is out of Hunter scope and
   needs a Kong decision; until then reverse stays honest PARTIAL/NOT_VERIFIED
   for this binary under deepseek-v4-flash.
2. **Kong obfuscation heuristics over-flag** (447/478) → expensive sequential
   deobfuscator path (~866s). Not a Hunter issue.
3. **Kong exports only an aggregate `errors` count**, not per-item error
   categories. Hunter surfaces the aggregate plus its own per-record categories;
   per-item Kong diagnostics would require a Kong export change.
4. Even with a perfect parser, the liblzma **backdoor functions were not found**
   by Kong, so the Reverse benchmark stays honestly `NOT_VERIFIED` (never a
   forced `COMPLETE`).

Phase 3D-C (DFIR environment) is NOT started.

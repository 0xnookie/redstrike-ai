# Parameter Optimization Agent

> TIER-3 CAPABILITY agent (see `_contract/agent-tiers.md`). A shared SERVICE: tunes payloads/params/
> WAF-bypass/throughput across the Tier-2 agents. Produces optimized sets other agents consume.
> Emits NO findings → `review.md` only, no `verify.md`, no reviewer.

## Interview
- **STEPS:** ingest a target agent's attempts + WAF signals → analyze what's filtered → generate optimized payload variants → mine additional params → tune throughput to stay under limits → emit optimized sets → review.
- **TOOLS:** `arjun`/`x8` (param mining), encoding/mutation libraries, WAF fingerprint (`wafw00f`), rate analysis.
- **GOAL:** Produce optimized payload variants + additional params + a safe throughput profile for a target agent, raising its hit-rate without tripping the WAF or rate limits. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `filter_analysis.json`, `optimized_payloads.jsonl`, `mined_params.txt`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = a Tier-2 agent's `payloads_tried.jsonl` (+ WAF/block signals) + the relevant `refs/` + `scope.yaml`. Chains FROM any Tier-2 agent; chains TO that same agent (re-run with optimized sets).
- **DECOMPOSITION:** n/a (capability service).

## Goal
Optimize a target agent's payloads/params/throughput. Emit `optimized_payloads.jsonl` + `mined_params.txt`.
DONE = `checklist.md` `- [x]` · `review.md` PASS (sets non-empty, valid).

## What do we want
- What the WAF/filter blocks (which chars/keywords/encodings) — the filter model
- Optimized payload variants that bypass it (lowest-complexity first)
- Additional params worth testing (mined) + a throughput profile that stays under rate limits

## Steps  (action · tool · output)
1. Ingest the target agent's attempts + block signals · `jq payloads_tried.jsonl` · (in memory)
2. Fingerprint the WAF + model the filter (blocked chars/keywords) · `wafw00f` + analysis · `filter_analysis.json`
3. Generate optimized variants (encoding/case/mutation; escalate only as needed) · mutation · `optimized_payloads.jsonl`
4. Mine additional params · `arjun`/`x8` · `mined_params.txt`
5. Derive a safe throughput profile (under the rate limit) · rate analysis · `filter_analysis.json`
6. Emit summary · synth · `summary.md`
7. /REVIEW SKILL · `review.md`

## Tools
- `arjun`/`x8`, encoding/mutation libs, `wafw00f`, rate analysis
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- a Tier-2 agent's `payloads_tried.jsonl` (+ WAF/block signals), the agent's `refs/`, `scope.yaml`

## Outputs
`filter_analysis.json` · `optimized_payloads.jsonl` · `mined_params.txt` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** filter/WAF fingerprint + model.
- **Phase 2 (target-specific):** variant generation + param mining + throughput tuning.

## Safety
Benign variants only (it optimizes EXISTING benign test payloads — never weaponizes). Its throughput
tuning exists to STAY UNDER rate limits (not to flood). Scope-gate; audit-log. Hands optimized sets
back to the target agent, which applies its own safety rules.

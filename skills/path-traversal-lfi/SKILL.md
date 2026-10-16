# Path Traversal / LFI Agent

> Variant of the file/path family (sibling: `upload-rce`). Consumes `file_context.json` sinks with
> `kind: read|include` / `variant_hint: traversal-lfi`.
> ACTIVE + findings-producing → imports `_contract/roe-gate.md` + **approval** (file read / LFI-RCE). Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest read/include sinks → traverse to a benign marker file outside the base dir → confirm read → (include sinks) LFI wrappers / log-poison to benign RCE (OOB) → rate → emit → review → verify.
- **TOOLS:** interceptor, `file-context/refs/file_payloads.md`.
- **GOAL:** Confirm path traversal / LFI — read a file outside the intended directory (benign marker) — and, for include sinks, assess LFI-to-RCE benignly. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `traversal_tests.jsonl`, `findings.json`, `poc/`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `file_context.json` (read/include sinks) + `scope.yaml`. `refs/` = `file-context/refs/`. Chains FROM `file-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the traversal/LFI variant.

## Goal
Prove out-of-directory file read (benign marker) + LFI-RCE feasibility. Emit `findings.json`
(`_contract/finding.schema.json`). DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest read/include sinks · `jq file_context.json` · (into tests)
2. Traverse to a benign marker outside the base dir (`../../etc/hostname`; encodings/bypasses) · interceptor · `traversal_tests.jsonl`
3. Confirm the marker's real content returns · interceptor · `traversal_tests.jsonl`
4. (Include sinks, approval) `php://filter` source read / log-poison → benign OOB RCE · refs · `poc/<id>/`
5. Rate (CVSS) + write finding · synth · `findings.json`
6. Emit report + curl · synth · `report.md`, `curl_commands.sh`
7. /REVIEW · `review.md` · 8. /VERIFY · `verify.md`

## Tools
- interceptor, `file-context/refs/file_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `file_context.json` (read/include sinks), `scope.yaml`

## Outputs
`traversal_tests.jsonl` · `findings.json` · `poc/` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** benign out-of-dir read confirmation.
- **Phase 2 (target-specific):** LFI wrappers / log-poison → benign RCE + rating (approval-gated).

## Safety
Benign marker files for proof (prefer `/etc/hostname`); LFI-to-RCE is **approval-gated** and proven
BENIGNLY (OOB/marker) — no destructive reads/writes; scope-gate; audit-log.

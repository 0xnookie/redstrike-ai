# Upload-to-RCE Agent

> Variant of the file/path family (sibling: `path-traversal-lfi`). Consumes `file_context.json` sinks
> with `kind: upload` / `variant_hint: upload-rce`.
> ACTIVE, RCE-class, HIGH-RISK, findings-producing → imports `_contract/roe-gate.md` + **approval**. Carries `review.md` + `verify.md`.

## Interview
- **STEPS:** ingest upload sinks → bypass type/validation → upload a BENIGN marker-webshell → locate the stored path → confirm execution (marker returned / OOB) → cleanup → rate → emit → review → verify.
- **TOOLS:** interceptor, `file-context/refs/file_payloads.md`.
- **GOAL:** Confirm upload-to-RCE — an uploaded file is stored at a web-reachable, executable path and EXECUTES — using a BENIGN marker-webshell. Done = checklist `- [x]`, review passes, findings accepted + approved.
- **OUTPUT:** `upload_tests.jsonl`, `findings.json`, `poc/`, `cleanup.md`, `report.md`, `curl_commands.sh`, `logs/`.
- **DATA / RAG:** inputs = `file_context.json` (upload sinks, stored_path, executes_hint) + `scope.yaml` (`oob.collaborator`). `refs/` = `file-context/refs/`. Chains FROM `file-context`; chains TO `reporting`.
- **DECOMPOSITION:** this IS the upload-to-RCE variant. (SVG/XML uploads → XXE: hand to `xxe-*`.)

## Goal
Prove upload-to-RCE with a BENIGN marker-webshell. Emit `findings.json` (`_contract/finding.schema.json`).
DONE = `checklist.md` `- [x]` · `review.md` PASS · accepted.

## Steps  (action · tool · output)
1. Ingest upload sinks + stored-path/exec hints · `jq file_context.json` · (into tests)
2. Bypass type/validation (ext, magic bytes, content-type, double-ext, .htaccess) · refs · `upload_tests.jsonl`
3. Upload a BENIGN marker-webshell (echoes `RS7F3Q` / calls OOB — NOT a real shell) · interceptor · `upload_tests.jsonl`
4. Locate the stored path; request it; confirm execution (marker / OOB) · interceptor · `poc/<id>/`
5. Record + remove the uploaded file · synth · `cleanup.md`
6. Rate (CVSS) + write finding · synth · `findings.json`
7. Emit report + curl · synth · `report.md`, `curl_commands.sh`
8. /REVIEW · `review.md` · 9. /VERIFY · `verify.md`

## Tools
- interceptor, `file-context/refs/file_payloads.md`
- **Fetch ladder:** `_contract/anti-automation-ladder.md`

## Inputs
- `file_context.json` (upload sinks), `scope.yaml` (`oob.collaborator`)

## Outputs
`upload_tests.jsonl` · `findings.json` · `poc/` · `cleanup.md` · `report.md` · `curl_commands.sh` · `logs/`

## Phases
- **Phase 1 (generic):** validation-bypass + benign marker-webshell upload.
- **Phase 2 (target-specific):** stored-path location + execution confirmation + cleanup + rating (approval-gated).

## Safety
RCE-class — **approval-gated**; upload ONLY a BENIGN marker-webshell (echo a marker / OOB) — **never**
a real shell, backdoor, or persistence; record every uploaded artifact in `cleanup.md` and REMOVE it;
scope-gate; audit-log; kill switch.

---
name: redstrike-source-audit
description: Run the Redstrike source-audit white-box feeder — grep an authorized codebase for dangerous-sink patterns across languages (JS/Python/PHP/Go/Ruby/Rust/Java/C) + semgrep + secret/dependency surface, and emit a routed candidate map (file:line → vuln class → executor) into source_context.json. Recon feeder (review.md only). Read-only, never executes the source; a grep hit is a lead, not a finding.
---

Run the Redstrike **source-audit** feeder (canonical spec: `skills/source-audit/`). White-box recon.

1. **Scope:** honor `skills/_contract/roe-gate.md` + `scope.yaml`. Requires AUTHORIZED source access (in scope). **Read-only** — grep/semgrep/secret-scan the code; **never execute it**. Redact secret VALUES to fingerprints.
2. **Execute:** follow `skills/source-audit/SKILL.md`; consume the authorized source repo + `<engagement>/js-analysis/` beautified JS + `<engagement>/web3-context/` source; work `skills/source-audit/checklist.md`; use `skills/source-audit/refs/source_audit.md`. Write outputs to `<engagement>/source-audit/` — key artifact `source_context.json` (validate against `skills/_contract/source_context.schema.json`).
3. **Coverage:** copy your filled checklist into `<engagement>/source-audit/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/source-audit --out <engagement>/source-audit` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. Each candidate is a LEAD the routed executor must PROVE against the running target. `source_context.json` routes to `deserialization | command-injection | ssti | xss-* | sqli-* | path-traversal-lfi | prototype-pollution | xxe-* | ssrf-* | idor | privesc | fuzzing | exploit-dev`; secrets → `secrets`; dep versions → `cve-intelligence`.

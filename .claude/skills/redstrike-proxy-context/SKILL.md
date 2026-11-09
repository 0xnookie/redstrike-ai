---
name: redstrike-proxy-context
description: Run the Redstrike proxy-context feeder — export the connected interception proxy's captured HTTP history (Caido/Burp/mitmproxy/ZAP) into http_history.json (real request/response per URL, secrets redacted). Enriches the content map + console Site Map and becomes replay-backed evidence. Recon feeder (review.md only). Read-only export, scope-gated.
---

Run the Redstrike **proxy-context** feeder (canonical spec: `skills/proxy-context/`). TIER-1 recon.

1. **Scope:** honor `skills/_contract/proxy.md` + `skills/_contract/roe-gate.md` + `scope.yaml`. Read-only **export** of already-captured traffic — in-scope hosts only; **redact** secrets/cookies/PII to `‹redacted›`; the raw proxy project stays local.
2. **Execute:** follow `skills/proxy-context/SKILL.md`; drive whichever proxy is connected (Caido · Burp · `mitmproxy` · ZAP) via its MCP/SDK/CLI to pull captured **History**; normalize each exchange; work `skills/proxy-context/checklist.md`; use `skills/proxy-context/refs/`. Write outputs to `<engagement>/proxy-context/` — `http_history.json` (+ `summary.md`). **No proxy connected ⇒ SKIP** (write an empty `exchanges[]` + a note) and move on.
3. **Coverage:** copy your filled checklist into `<engagement>/proxy-context/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/proxy-context --out <engagement>/proxy-context` → fix + re-run until exit 0.
5. Recon feeder — **no findings, no reviewer**. Feeds `redstrike-content-discovery` (Site Map / routes), `redstrike-js-analysis`, every `<class>-context` feeder, and replay-backed confirmation in the vuln executors.

---
name: redstrike-exposed-surface
description: Run the Redstrike exposed-surface hunt (executor) — active dir/file/param fuzzing (ffuf/feroxbuster/gobuster/dirsearch + nuclei) that confirms unauthenticated exposures (VCS /.git, backups, .env/config, data dumps, directory listing, debug/actuator panels) by response-body signature, de-duped vs secrets/security-headers/privesc — then gate and hand off to the exposed-surface-verify reviewer agent.
---

Run the Redstrike **exposed-surface** methodology (canonical spec: `skills/exposed-surface/`). ACTIVE, findings-producing — the active fuzzing agent that turns content-discovery's dir/file/param brute-force into signature-confirmed exposure findings.

1. **Scope:** read `skills/_contract/roe-gate.md` + the engagement `scope.yaml`. GET/HEAD-only, benign, rate-limited to `rate_limit_rps`, in-scope hosts only; no mass exfiltration (single signature read, note reconstructability); redact secrets and defer live-secret validation to `secrets`. **Tool-first** — `skills/_contract/tooling.md` (never hand-roll a fuzzer/crawler when `ffuf`/`feroxbuster`/`gobuster`/`nuclei`/`katana` exists).
2. **Execute:** follow `skills/exposed-surface/SKILL.md`; consume `<engagement>/content-discovery/{endpoints.txt,params.txt,custom_wordlist.txt,crawl.txt}` + `<engagement>/host-discovery/host_discovery.json` + `js-analysis` endpoints; work `skills/exposed-surface/checklist.md`; use `skills/exposed-surface/refs/`. Write outputs to `<engagement>/exposed-surface/`.
3. **Coverage:** copy your filled checklist into `<engagement>/exposed-surface/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/exposed-surface --out <engagement>/exposed-surface` → fix + re-run until exit 0.
5. **Reviewer:** launch the `exposed-surface-verify` subagent on `<engagement>/exposed-surface`. Only `accepted` findings go to reporting.

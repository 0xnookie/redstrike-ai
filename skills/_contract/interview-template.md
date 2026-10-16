# Design Interview — run FIRST, paste answers at the top of SKILL.md

Answer all six before writing any steps. If you can't answer one, the skill isn't scoped yet.

- **STEPS** — the discrete, ordered steps. Each step is atomic and MUST emit at least one artifact.
- **TOOLS** — the most MODERN tool per step (primary + anti-automation fallbacks). Prefer current tooling over legacy. Reference `_contract/anti-automation-ladder.md` instead of re-describing the ladder.
- **GOAL** — one sentence: what the skill achieves and what "done" means.
- **OUTPUT** — every artifact the skill writes, by filename (`report.md`, `curl_commands.sh`, `custom_list.txt`, `findings.json` …).
- **DATA** — inputs it consumes; does it benefit from RAG / a reference corpus; which skills it chains FROM and TO.
- **DECOMPOSITION** — if the target is a vuln category, cut it into ONE specialized sub-agent per variant. Never build one monolith. (Recon skills: `n/a`.)

## Copy-paste block for SKILL.md

```
## Interview
- STEPS: …
- TOOLS: … (see SKILL.md §Tools)
- GOAL: …
- OUTPUT: …
- DATA / RAG: inputs = … · refs/ corpus = … · chains FROM … · chains TO …
- DECOMPOSITION: … (n/a for recon)
```

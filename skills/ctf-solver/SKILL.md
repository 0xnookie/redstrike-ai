# CTF Solver Agent

> TIER-3 MISSION agent (see `_contract/agent-tiers.md`) — a goal-driven entry point that solves a web
> CTF challenge by identifying the class and driving the right Tier-2 agents to capture the flag.
> Orchestrates other skills; the flag is self-evidencing → emits NO findings → `review.md` only.

## Interview
- **STEPS:** analyze the challenge (recon, description, source if given) → hypothesize the vuln class → run the matching Redstrike skill(s) → iterate (adjust hypothesis on result) → capture the flag → write up.
- **TOOLS:** the Redstrike skill set (orchestrated), flag-format matching.
- **GOAL:** Capture the challenge flag by routing to the right Redstrike vuln skill(s), with a reproducible writeup. Done = checklist `- [x]`, review passes (flag captured or attempts + reasoning recorded).
- **OUTPUT:** `challenge_analysis.md`, `attempts.jsonl`, `flag.txt`, `writeup.md`, `logs/`.
- **DATA / RAG:** inputs = the challenge (URL / source / description) + optional flag format (e.g. `flag{...}`) + `scope.yaml` (the challenge host). Orchestrates Tier-1 (`js-analysis`) + the applicable Tier-2 vuln agents.
- **DECOMPOSITION:** n/a (mission orchestrator).

## Goal
Capture the flag. DONE = `checklist.md` `- [x]` · `review.md` PASS (flag.txt with the flag, OR
attempts.jsonl + writeup documenting the reasoning if unsolved).

## Orchestration
1. **Analyze** — recon the challenge (`redstrike-js-analysis` if web; read any source) → `challenge_analysis.md`; hypothesize the class (XSS / SQLi / SSTI / IDOR / SSRF / …).
2. **Route** — run the matching `redstrike-<vuln>` skill(s) against the challenge host, scoped to it.
3. **Iterate** — on each result, refine the hypothesis; try sibling variants / chains.
4. **Capture** — extract the flag (match the flag format) → `flag.txt`.
5. **Write up** — reproducible steps → `writeup.md`.

## Inputs
- the challenge (URL/source/description), optional flag format, `scope.yaml` (the challenge host only)

## Outputs
`challenge_analysis.md` · `attempts.jsonl` · `flag.txt` · `writeup.md` · `logs/`

## Phases
- **Phase 1:** analyze + hypothesize.
- **Phase 2:** route to vuln skills + iterate + capture + write up.

## Safety
CTF is an authorized sandbox — but scope to the **challenge host only**; do NOT attack CTF
infrastructure, other teams, or the scoreboard. The framework's gates still apply for rigor (don't
claim a flag you didn't capture). Audit-log.

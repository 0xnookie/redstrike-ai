---
name: redstrike-ctf-solver
description: Run the Redstrike CTF solver mission — analyze a web challenge, hypothesize the class, drive the matching Redstrike vuln skills to capture the flag, and write it up. Mission orchestrator (review.md only).
---

Run the Redstrike **ctf-solver** mission (canonical spec: `skills/ctf-solver/`). TIER-3 mission agent.

1. **Scope:** read `skills/_contract/roe-gate.md` + `scope.yaml`. CTF is an authorized sandbox — scope to the **challenge host only**; never attack CTF infrastructure, other teams, or the scoreboard. Don't claim a flag you didn't capture.
2. **Execute (orchestrate):** follow `skills/ctf-solver/SKILL.md` → analyze (`redstrike-js-analysis` if web) + hypothesize the class → run the matching `redstrike-<vuln>` skill(s) against the challenge host → iterate (sibling variants / chains) → capture the flag → write up. Write outputs to `<engagement>/ctf-solver/` (`challenge_analysis.md`, `attempts.jsonl`, `flag.txt`, `writeup.md`).
3. **Coverage:** copy your filled checklist into `<engagement>/ctf-solver/checklist.md`.
4. **Mechanical gate:** `python skills/_contract/verify_completion.py --skill skills/ctf-solver --out <engagement>/ctf-solver` → fix + re-run until exit 0. (`flag.txt` is optional — present only if captured.)
5. Mission orchestrator — **no findings, no reviewer**. The flag is self-evidencing.

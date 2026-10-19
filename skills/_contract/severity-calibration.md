# severity-calibration — rate what a reputable audit would stake its name on

Inherited by every `verify.md` (supplements `verify-base.md` base check #4, CVSS integrity) and by the
`reporting` skill. CVSS is computed deterministically by `scripts/cvss.py`; this doc governs the **metric
choices** that feed it and guards both inflation and deflation. Rule: when a rating feels wrong,
**correct the CVSS metrics and re-derive** — never hand-override the computed score.

## The governing test
Would a serious pentest / bug-bounty firm accept this severity while staking its reputation on it, and
would it survive a client debrief? If not, it is mis-rated.

## High / Critical acceptance — ALL must hold
1. The attack path is realistic and entirely in scope.
2. The attacker position it requires is actually obtainable (evidenced, not assumed).
3. Impact is **demonstrated**, not asserted.
4. The counterevidence pass (`counterevidence.md`) found no constraint that limits it.
5. Reachability is evidenced, not inferred.
6. It survives a skeptical debrief question ("show me").

## Anti-inflation (rate down / informational unless a real gadget is proven)
- self-XSS; a missing security header / cookie flag / TLS nit ALONE.
- open redirect ALONE (rate the chain it enables, only if that chain is proven).
- memory-safety with no attacker-reachable input.
- any rating that rests on an UNPROVEN assumption or a non-accepted finding.

## Deflation guards (do not under-rate a real finding)
- "could not confirm it is internet-facing" → lower **confidence**, NOT severity; never silently treat it
  as internal-only.
- a genuinely constrained finding is **downgraded with the reason stated**, not dropped.
- `demonstrated` severity rates what was proven; the worst case goes in `potential_severity`, not the score.

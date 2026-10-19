# RoE Gate — authorization & safety (imported by every ACTIVE skill)

Recon skills are read-only and skip most of this (but still honor scope on fetches).
Any skill that **sends a payload, exploits, or changes target state** MUST pass this gate before acting. The mechanical completion gate will NOT catch an out-of-scope or destructive action — that is this gate's altitude.

## 1. Scope allowlist (hard gate)

Before any active action, resolve the target and check it against the engagement `scope.yaml`:

```yaml
# engagements/<client>-<date>/scope.yaml
engagement: acme-2026-10
authorized_by: "ACME Security <security@acme.example>"   # written authorization on file
window:   { start: 2026-10-16T00:00:00Z, end: 2026-10-30T23:59:59Z }
in_scope:
  domains:  ["*.acme.example", "api.acme.example"]
  cidrs:    ["203.0.113.0/24"]
out_of_scope:
  domains:  ["admin.acme.example", "*.payments.acme.example"]   # explicit excludes win
  cidrs:    ["203.0.113.200/29"]
rules:
  no_dos: true
  no_destructive: true          # no data deletion/modification without per-action approval
  rate_limit_rps: 20
  prod_touch_requires_approval: true
```

- Target matches `out_of_scope` (or the window is closed) ⇒ **HARD STOP**, log, do not act.
- Target not in `in_scope` ⇒ treat as out of scope (default deny).

## 2. Approval gates (human-in-the-loop)

- `exploitation` and `post-exploitation` phases **pause** for explicit human sign-off before the first active action.
- Any action that could cause outage or data loss requires per-action approval even inside an approved phase.

## 3. Blast-radius controls

Rate-limit to `rules.rate_limit_rps`; honor exclusion lists; **safe/dry-run is the default** — the real payload fires only after the dry run and (where required) approval.

## 4. Immutable audit log

Every command, tool invocation, and agent decision is appended (timestamped, with the scope decision) to the engagement audit log. This doubles as chain of custody and makes the engagement replayable.

## 5. Kill switch

A single command halts all agents and active actions. Honor it immediately.

## 6. Framing a block (so the agent re-plans, not evades)

When this gate STOPS an action, say so as **engagement/platform policy, NOT a target defense**: "this
operation is outside the authorized scope / window / approval — re-plan within scope." An offensive agent
that reads a denial like a WAF/403 will burn turns trying to *bypass* it (re-encode, swap payload, retry);
the framing tells it to **pivot** instead. Two corollaries:

- **Reading sensitive data is not a block reason.** Only scope, the window, destructive/DoS actions, and the
  approval-gated phases gate — do not deny a read for being "sensitive."
- **Approval-pending ≠ dangerous.** An action that needs sign-off is paused for *authorization*, not because
  it is unsafe; summarize and wait — do not treat it as a hard deny or try to route around it.

---

`verify.md` check #6 (scope & safety compliance) re-audits that every finding's `asset` was in scope and produced within RoE. The gate prevents; the verifier confirms.

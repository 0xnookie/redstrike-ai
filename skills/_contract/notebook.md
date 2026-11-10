# Engagement Notebook — the intel an engagement gathers that isn't a finding (yet)

> Imported by the orchestrators + the executor base. Schema: `notebook.schema.json`. Tool:
> `scripts/notebook.py`. Lives at the **engagement root** (`<engagement>/notebook.json`), beside the
> `surface_ledger`/`coverage_ledger`/`recall_audit`/`reconvergence_signals` ledgers.

## Why it exists
The ledgers answer *"did we cover this?"* (coverage accounting, gated). The notebook answers *"what have we
learned and what are we chasing?"* — the **investigative state**: leads, recon intel, evidence, RoE, test
accounts. It is the one artifact that makes a **zero-finding hunt legible**: when nothing reaches the
submission bar, the recon it gathered and the leads it chased + killed still show, in the console and on
export. A hunt that produced no `findings_consolidated.json` AND no `notebook.json` is indistinguishable
from one that never ran — the notebook is how a finished hunt proves it did the work.

It **cross-links, never duplicates**: `lead.surface_ref` → `surface_ledger.surfaces[].id` (the ledger still
owns coverage); `lead.promoted_to` → `finding.id` (`^RS-YYYY-NNN$`); `recon_intel.sources` records which
feeder artifact each bucket was aggregated from (the feeder stays the source of truth).

## The lead lifecycle (the spine)
`open` (a hypothesis, not yet worked) → `testing` (an executor is on it) → **`promoted`** (it became a
finding — `promoted_to` set) **or** `dead` (closed — `verdict` required). A `dead` verdict reuses the
reviewer `rejection_class` vocab where it fits (`false-positive | out-of-scope | duplicate |
open-proof-gap`) so `recall-audit` can reconcile leads against findings.

## Who writes what, and when
- **At engagement start** — the orchestrator writes `roe` (from `scope.yaml`: window, in/out scope, `rules`,
  rate limit, `oob`) + `test_accounts` (from `runtime/operator_decisions.json` / `runtime/creds.json`,
  **identities redacted**).
- **After recon** — `notebook.py --plan` aggregates `recon_intel` from the feeders (osint, host-discovery
  (+ `dangling_dns.json` → takeover **leads**), content-discovery, js-analysis) and **seeds leads** from
  source-audit `candidates[]`/`chain_candidates[]`, dangling DNS, and the reconvergence inbox. Idempotent —
  re-run safely as late feeders land; it merges, never clobbers executor/human edits.
- **During the hunt** — each executor flips the lead for the surface it consumes:
  `notebook.py --mark L-<n> --status testing`, then `--status promoted --finding RS-YYYY-NNN` or
  `--status dead --verdict "<reason>"`. Same muscle as `surface.py --mark`.
- **Before reporting** — the orchestrator finalizes; `recall-audit` may read open leads as residual risk.

## The gate (soft)
`verify_completion.py --engagement` validates the notebook when present (shape + every `promoted` lead's
`promoted_to` resolves in the consolidated findings + every `dead` lead has a `verdict`) and **nudges** when
it is absent — but it is **soft: it never hard-fails**, so engagements predating the notebook keep passing.
Encouraged, not mandatory.

## Interface — `scripts/notebook.py`
- `--plan --engagement <dir>` — build/refresh `recon_intel` + seed leads + `roe`/`test_accounts`.
- `--mark L-<n> --status <open|testing|promoted|dead> [--finding RS-…] [--verdict …] --engagement <dir>`.
- `--validate --engagement <dir>` — structural + cross-ref check (exit 0 / non-zero with `--strict`).

## Safety
`test_accounts.identity` and any credential material are **redacted** (`‹redacted›`) — the notebook is
exported and rendered; it never carries a live secret. Evidence is indexed (name/kind/size/sha), not
inlined. Scope + RoE here mirror `scope.yaml`; they do not override the RoE gate.

# Reporting

> TERMINAL skill — the engagement aggregator. Consumes every skill's `findings.json`, keeps only
> `review.verdict == accepted` findings, de-dupes across agents, and assembles the client report.
> Emits NO new findings → `review.md` only, no `verify.md` (findings were verified upstream).
> Standardized reporting: CVSS + evidence + executive summary.

## Interview
- **STEPS:** collect all findings → filter to accepted → de-dupe cross-agent → normalize severity/CVSS → order by risk → write executive summary + per-finding writeups → emit report + consolidated JSON → review.
- **TOOLS:** `jq` over the engagement dirs, `refs/report_template.md`.
- **GOAL:** Produce a client-ready report of verified findings — executive summary, risk-ordered findings with evidence + reproduction + remediation, and a consolidated machine-readable file. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `findings_consolidated.json`, `report.md`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = every `<engagement>/<skill>/findings.json` + `scope.yaml`. `refs/` = `report_template.md`. Chains FROM all findings-producing skills; terminal (chains to the human).
- **DECOMPOSITION:** n/a (terminal aggregator).

## Goal
Assemble the engagement report from ACCEPTED findings only.
DONE = `checklist.md` all `- [x]` · **coverage gate PASS** · `review.md` PASS (report + consolidated JSON exist, non-empty; CVSS present on each finding).

## 0. Coverage gate — MANDATORY precondition, before any aggregation
A report must not coexist with routed-but-never-run vuln classes (the juice-shop-2026-10-20 failure:
XSS/auth/XXE never ran, clean report anyway). Before step 1, the coverage ledger must be complete:
```
python scripts/coverage.py --validate --strict --engagement <dir>    # exit 0 required
```
Exit non-zero ⇒ **STOP, do not assemble the report.** Either run every `pending` category (then re-mark
the ledger), or record an explicit `skipped`/`blocked` with a reason (`coverage.py --mark … --note`). A
missing ledger is a hard fail under `--strict` — plan it first (`coverage.py --plan`). This is also enforced
deterministically: once `report/findings_consolidated.json` exists, `verify_completion.py --engagement`
HARD-FAILS on any unaccounted category, so a report over silent gaps cannot pass the gate.

**Also required before aggregation: the cross-model exhaustion review.** The orchestrator must have run the
model-pinned `exhaustion-adversary` (redstrike SKILL §3.5) and it must have returned `no_gaps_found` —
`<engagement>/runtime/exhaustion_review.json` with `verdict=no_gaps_found` and every gap it raised closed.
A `found_gaps` verdict, an open gap, or a missing artifact means the "engagement complete / class exhausted"
claim was never independently disproved on a different model: **STOP, re-drive the named gaps, re-run the
adversary.** This is enforced deterministically too — once a report exists `verify_completion.py --engagement`
HARD-FAILS without a `no_gaps_found` exhaustion review (un-routable, no operator-accept hatch).

## 0.5 Coverage & reliability — MANDATORY, drives the risk posture (empty ≠ clean)
> Engagement-level reliability (did the testing actually reach the target?) — DISTINCT from the
> finding-level "confirmed — demonstration limited" subsection in **Safety** (which is about one proven
> bug whose full impact was gated). This section is about whether a CLEAN or empty result can be trusted.

Read `runtime/diagnostics.json` (the run engine's per-engagement health log; use the **latest** `runs[]`
entry — schema `skills/_contract/diagnostics.schema.json`, referenced read-only). It makes "we were
blocked / produced nothing" visible, so a report never presents an inconclusive run as a clean bill of health.

- **A clean result on a transport-`blocked` host is NOT "no issues found" — report it as "not assessed /
  inconclusive."** When `transport_health` shows a host `classification: "blocked"` (a WAF/gateway blocked
  a large share of requests, `block_rate`), the categories tested against it could not be exercised. The
  completion gate already auto-marks those coverage categories `blocked` with a `transport:` reason; mirror
  that in the report: list the affected host(s) and categories under a **"Coverage not achieved"** callout,
  and state plainly that **absence of findings there is inconclusive, not an assurance.**
- **This GATES the executive-summary risk posture.** Base the posture on the latest run's `outcome`:
  - `produced-findings` → report normally (risk reflects the findings).
  - `clean-tested` → a genuine clean result; "no issues found in the tested surface" is honest.
  - `degraded-empty` / `failed` (or any transport-`blocked` host) → the headline is **"assessment
    incomplete / inconclusive"**, quoting `degraded_reason` and the worst host's `block_rate`/`waf`.
    **Never write "no issues found" / "no vulnerabilities identified" over a degraded or blocked run** —
    that is the exact empty≠clean failure. Recommend a re-test of the un-reached surface.
- A zero-finding report with no diagnostics outcome (or an unexplained empty) HARD-fails
  `verify_completion.py --engagement` — so this is enforced deterministically, not left to prose.

## What do we want
- Every `accepted` finding, de-duped (e.g. the same bug found by `idor` and `bola-bfla` = one entry)
- Risk-ordered list (Critical→Info) with CVSS, affected asset, evidence refs, reproduction, impact, remediation, CWE/WSTG/ATT&CK
- An executive summary (scope, dates, risk posture, headline findings) for non-technical readers

## Steps  (action · tool · output)
1. Collect all `<engagement>/*/findings.json` · `jq` · (in memory)
2. Keep `review.verdict in {"accepted","blocked"}` (status `verified`); `blocked` is tagged for the caveat subsection · `jq` filter · (in memory)
3. De-dupe across agents — run the DETERMINISTIC engine `python scripts/dedup.py --engagement <dir> --json`: it groups findings by canonical key (asset-host + normalized endpoint/param + vuln-class), keeps the strongest as primary, and marks the rest `status:"duplicate"` (excluded from counts). Use its merge map; don't eyeball the merge (same bug from `idor`+`bola-bfla`, `ssrf-inband`+`ssrf-cloud`, `exposed-surface`+`secrets` = one entry) · `scripts/dedup.py` · `findings_consolidated.json`
4. Normalize severity/CVSS; order Critical→Info. Findings with `composite: true` (kill chains) are listed under an **Attack Chains** section and EXCLUDED from the severity counts — non-additive, they re-state already-counted components · `refs/report_template.md` · `findings_consolidated.json`
4b. **(OPTIONAL — config-gated, default OFF)** Stamp each consolidated finding's `compliance` block by a DETERMINISTIC lookup of its `category.cwe` in `refs/compliance_crosswalk.json` (CWE → PCI-DSS v4 / SOC2 CC / ISO 27001:2022 control IDs). This is a pure dictionary lookup, NOT a model judgement; a CWE absent from the crosswalk (or a finding with no `category.cwe`) gets NO `compliance` block (a legitimate state). When the toggle is off, skip this step entirely — findings are emitted exactly as before. See §Compliance mapping · `refs/compliance_crosswalk.json` · `findings_consolidated.json`
5. Write per-finding sections (template) + executive summary — the summary's **risk posture is gated by §0.5** (a degraded/blocked run reports as "assessment incomplete / inconclusive," never "no issues found"). When a prior-assessment baseline is supplied, add a **"changes since last assessment"** line to the executive summary (net delta + new/fixed/unchanged/severity-changed counts) sourced from the scan-diff artifact — see §Retest / scan-diff · synth · `report.md`
6. Emit a short stats summary — INCLUDING the **measured evidence-sufficiency numbers** (see §Evidence-sufficiency): run `python scripts/evidence_score.py --engagement <dir> --aggregate` and fold its output into `summary.md` + the executive summary · `scripts/evidence_score.py` · `summary.md`
7. **Seal the evidence vault (chain of custody)** — `python scripts/evidence_seal.py --engagement <dir>`: hashes every evidence/poc artifact into `evidence/manifest.json` and populates each finding's `evidence[].sha256`. Then self-verify — `python scripts/evidence_seal.py --engagement <dir> --verify` (exit 0 required; exit 3 = a tamper signal: an altered/missing/unsealed artifact — STOP and reconcile, do not ship a report over unverifiable evidence) · `scripts/evidence_seal.py` · `evidence/manifest.json` · §Chain of custody
7b. **OPTIONAL (config-gated) — machine-interchange exports.** When the engagement opts in (`scope.yaml` `reporting.export_formats: true`, DEFAULT off → this step is skipped and nothing else changes), emit CI/dashboard-ready exports from the consolidated findings: `python scripts/export_formats.py --engagement <dir>` writes `report/exports/findings.sarif` (SARIF 2.1.0 — reuses the js-analysis rule/result/severity→level mapping) + `report/exports/junit.xml` (one `<testcase><failure>` per accepted/blocked finding, so a pipeline can gate on "no confirmed findings"). Purely additive — the report + consolidated JSON are unchanged · `scripts/export_formats.py` · `report/exports/{findings.sarif,junit.xml}` · §Interchange exports
8. /REVIEW SKILL · `review.md`

## Tools
- `jq` over engagement dirs, `refs/report_template.md`

## Inputs
- every `<engagement>/<skill>/findings.json` (+ their `poc/`/evidence refs)
- `scope.yaml` (engagement metadata: client, dates, scope)
- `refs/report_template.md`

## Outputs
`findings_consolidated.json` · `report.md` · `summary.md` · `evidence/manifest.json` · `logs/`
OPTIONAL (config-gated): `report/exports/findings.sarif` + `report/exports/junit.xml` (step 7b);
`report/scan_diff.json` (+ optional `report/scan_diff.{md,html}`) when a baseline is supplied (§Retest / scan-diff).

## Phases
- **Phase 1 (generic):** collect + filter-to-accepted + de-dupe.
- **Phase 2 (target-specific):** CVSS normalization + writeups + executive summary.

## Console
The web console (`scripts/console.py engagements/<dir>`) renders this engagement from the files the
pipeline already emits — do NOT emit anything console-specific, just keep these shapes:
- `report/findings_consolidated.json` — an object `{ engagement, target, generated, severity_counts, findings: [...], attack_chains: [...] }` (or a bare `findings` array). `findings[]` follow `finding.schema.json`; the kill-chain write-ups go in `attack_chains[]` (composite, non-additive). The console reads findings from here, folds `attack_chains` in as composite (kept out of the severity counts), and takes the engagement name/target from the header.
- `host-discovery/host_discovery.json` — `{ live_hosts: [...], api_endpoints: [...] }` → the console's Assets map + Ports/services table.
- `attack-chain-discovery/chains.json` — `{ chains: [{ steps: [...] }] }` → the console's Attack-chains graph.
- `scope.yaml` (engagement root) → the console's Scope panel + window (the launcher converts it to JSON).

Agents stats and the activity timeline are DERIVED by the console from each finding's `review.reviewer` +
`review.reviewed_at`, so keep the `review` block on every finding. No separate agents/activity file is needed.

## Safety
Report `accepted` findings as confirmed. Also include `blocked` findings (confirmed real, but a precondition
blocked full demonstration) in a clearly-labeled "confirmed — demonstration limited" subsection, showing both
`severity` (demonstrated) and `potential_severity` — never silently fold their best-case into the headline
counts. Never include `rejected`/`needs-evidence` items as confirmed. Normalize every CVSS score with
`scripts/cvss.py` (do not trust hand-written numbers). Keep redacted secrets redacted. The report + evidence
stay in the engagement dir (git-ignored); deliver to the client through the agreed channel only.

## Evidence-sufficiency  (measured numbers — the engagement finally quantifies its proof)
Every accepted/blocked finding carries an `evidence_score` block (0–100), written by its `<class>-verify`
reviewer and used as the accept/downgrade floor (`skills/_contract/verify-base.md`). Reporting AGGREGATES
them so the report states, in numbers, how well the findings are actually proven — not just how many there are:

```
python scripts/evidence_score.py --engagement <dir> --aggregate
# -> {n, scored_by_reviewer, derived, mean, min, max,
#     by_decision:{pass,downgrade,kill}, flagged_race_timing, probable_capped}
```

Fold these into `summary.md` and the executive summary: report the **mean evidence-sufficiency score**, the
PASS/DOWNGRADE count, how many findings are **flagged race/timing — needs chaining** (`flagged_race_timing`)
and how many rest on probable-capped (circular) evidence (`probable_capped`). A finding whose reviewer left no
`evidence_score` falls back to a derived baseline (counted in `derived`) so the numbers cover the whole set —
surface a nonzero `derived` as a gap to backfill. These are the measured evidence numbers the roadmap asked
for; they sit beside the severity counts, never replace them.

## Compliance mapping  (OPTIONAL — config-gated, default OFF; a deterministic CWE lookup)
When the engagement opts in (e.g. `compliance.enabled: true` with `compliance.frameworks: [pci_dss_v4,
soc2_cc, iso_27001_2022]` in `scope.yaml` / the run config), reporting enriches each consolidated finding
with the controls its weakness bears on, so the report can orient the reader toward the relevant framework
clauses. Off by default — a report built with it OFF is byte-identical to one built before this feature.

- **Join key = `category.cwe`** (the standardized CWE every finding already carries), NEVER the free-text
  title/vuln name. CWE keeps the mapping a clean, deterministic dictionary lookup instead of a fuzzy match.
- **Lookup (deterministic, not model-judged):** for each finding read `category.cwe`; look it up in
  `refs/compliance_crosswalk.json`; on a hit, copy its `{pci_dss_v4, soc2_cc, iso_27001_2022}` value
  VERBATIM into the finding's `compliance` block (schema: `_contract/finding.schema.json`). The control IDs
  come ONLY from the crosswalk — do not infer, add, re-order, or edit them per finding.
- **Unmapped is explicit, not a guess:** a CWE absent from the crosswalk, or a finding with no
  `category.cwe`, gets NO `compliance` block. "No mapping" is a legitimate state — never fabricate controls.
- **Framework subset:** if the config names a subset of frameworks, keep only those keys in each block.
- **Additive + reversible:** the field is optional in the schema, so OFF ⇒ no `compliance` blocks and no new
  report section; existing findings stay valid either way.
- **Advisory, not an audit:** the crosswalk is a CWE→control reference (see its `_meta.note`) — advisory
  guidance toward likely-relevant clauses, NOT a certified compliance audit, attestation, or statement of
  (non-)compliance. The report's **"Compliance Mapping"** appendix (engagement-docs `refs/doc_templates.md`)
  renders Finding → CWE → PCI-DSS v4 / SOC2 CC / ISO 27001:2022 and MUST carry the scope caveat verbatim.

## Chain of custody  (court-grade: tamper-evidence + a who/what/when trail)
Evidence that cannot be shown unaltered is not evidence. Two artifacts carry the custody, and the report
MUST cite both so a third party can audit the result:

- **`evidence/manifest.json`** — the sealed inventory (step 7): every evidence/PoC artifact with its
  `sha256`, size and capture time, plus a `time_anchor` (a content digest over all artifact hashes, bound
  to the repo commit in force) that dates the whole set. Each finding's `evidence[].sha256` is populated
  from it, so a report reference resolves to an exact, verifiable artifact. Anyone can re-run
  `evidence_seal.py --verify` to confirm nothing was altered, removed, or added after sealing.
- **`runtime/audit.jsonl`** — the immutable, append-only custody log (roe-gate.md §4): one timestamped
  record (`{ts, actor, action, target, detail, sha256?}`, schema `skills/_contract/audit.schema.json`) per
  gate decision, target-reaching tool invocation, and evidence capture — the who/what/when trail, each
  line bound to the scope in force. It makes the engagement replayable and the evidence attributable.

In the report (methodology / appendix), state that all evidence is hashed in `evidence/manifest.json`
(sealed + self-verified at close) and that `runtime/audit.jsonl` is the chain-of-custody log, so the
findings rest on tamper-evident, attributable proof — not on screenshots that could have been edited.

## Interchange exports  (OPTIONAL, config-gated — step 7b)
The consolidated findings can also be emitted in two standard machine-interchange formats for CI /
code-scanning pipelines. This is **off by default** and purely additive — the `report.md` + consolidated
JSON are produced identically whether or not it runs; nothing downstream depends on it.

```
python scripts/export_formats.py --engagement <dir>        # writes report/exports/{findings.sarif,junit.xml}
# or explicitly:  --input <findings_consolidated.json> --out-dir <exports/>
```

- **`findings.sarif`** — a SARIF 2.1.0 log (same `$schema`, `version`, and severity→level map the
  js-analysis recon exporter already uses: critical/high → `error`, medium → `warning`, low/info → `note`).
  One `rule` per vuln-class (cwe → owasp → wstg → title-slug), one `result` per finding, the finding's
  `asset` as the result location. Folds straight into a code-scanning dashboard.
- **`junit.xml`** — one `<testcase>` with a nested `<failure>` per accepted/blocked finding, so a CI job can
  gate a release on "no confirmed findings". Duplicates (`status:"duplicate"`) and composite kill-chains
  (`composite:true`) are excluded from both exports — they re-state already-counted bugs.

Enable it per engagement with `scope.yaml` `reporting.export_formats: true`.

## Retest / scan-diff  (finding-level delta vs a prior assessment)
For a retest or a recurring assessment, diff this engagement's consolidated findings against a prior baseline
to answer, mechanically, what is **new / fixed / unchanged / severity-changed** since last time:

```
python scripts/scan_diff.py --baseline <prior/findings_consolidated.json> --engagement <dir> \
       --out <dir>/report/scan_diff.json --md <dir>/report/scan_diff.md     # --html optional
```

Identity is dedup.py's `canonical_key` (asset-host + normalized endpoint/param + vuln-class — the SAME key
the cross-agent de-dup uses), so a re-worded title or a re-ordered query string is NOT mistaken for a new
bug. The JSON report (schema `skills/_contract/scan_diff.schema.json`) carries a `summary` with a
**net_delta** (new − fixed) plus per-category rows. Fold the one-line summary into the executive summary's
**"changes since last assessment"** line (step 5); the full table feeds the engagement-docs `retest.md`
deliverable.

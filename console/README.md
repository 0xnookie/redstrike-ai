# Redstrike Console

A web UI over the Redstrike engagement data model — a multi-view console for running and
reviewing an AI-driven penetration test. Built with **Next.js (App Router) + TypeScript +
TailwindCSS**, with a **dark / light theme switch** and no backend: it renders the JSON the
framework's skills emit into an engagement dir. With nothing loaded it shows honest empty states —
there is **no bundled demo data**.

## Views

| Route | View | What it shows |
|---|---|---|
| `/` | **Dashboard** | KPIs, severity donut, findings-over-time, activity feed, top findings, category/asset breakdowns, two-altitude review roll-up |
| `/engagements` | **Engagements** | The authorized assessments with their run status (*Running* / *Paused* / *Completed* — following the actual run) and coverage progress; pick one to make it the active context. With the control plane: launch, stop, and approve deferred actions |
| `/findings` | **Findings** | Filterable/sortable table + full detail drawer (CVSS, mappings, reproduction, evidence, remediation, reviewer verdict) |
| `/chains` | **Attack chains** | Kill-chain flow graph composed from accepted findings |
| `/assets` | **Assets & scope** | In/out-of-scope tree, RoE rules, force-directed coverage map, asset table, and **open ports & services** from host discovery |
| `/js-recon` | **JS Recon** | The client-side JavaScript intelligence the js-analysis skill mined — endpoints, params, APIs, secrets (redacted), DOM sinks/gadgets and libraries (per site), plus the site summary. Reads the parsed `findings/*.jsonl` |
| `/notebook` | **Notebook** | What an engagement gathers that isn't a finding yet: investigative leads (open→testing→promoted/dead), recon intel (subdomains/DNS/network/defenses/OSINT), the evidence locker, RoE and test accounts; export to Markdown |
| `/activity` | **Activity** | Execution timeline derived from each finding's reviewer record (findings → reviews) |
| `/orchestration` | **Orchestration** | *(opt-in, live)* A running engagement as it happens: the task flow (orchestrator → skills and subagents, following the engine's task list), results travelling back as subagents return, the task queue, and a dispatch log narrating steps, dispatches and returns. Launch / stop / approvals live on **Engagements**. Needs `scripts/console_control.py` |
| `/sitemap` | **Site map** | Every discovered URL per host as a tree, merged from content discovery, host discovery, the proxy history and findings |
| `/coverage` | **Coverage** | The routing ledger: which vulnerability categories were attempted, skipped with a reason, blocked, still pending, or out of phase |
| `/cve-intel` | **CVE intel** | Version-matched CVEs for the detected components, plus a live feed of newly published CVEs |
| `/agents` | **Agents** | The executor + independent-reviewer fleet, by family and tier; per-skill produced/accepted counts derived from the loaded findings |
| `/connections` | **Agent Connections** | *(opt-in)* Connect the control plane, then bring your own coding-agent runtime (Claude Code · Codex · Gemini · Grok) via subscription login or an API key; live per-provider status, model selection, and disconnect. Needs `scripts/console_control.py` |
| `/report` | **Report** | Client-ready assembly: executive summary, risk-ordered findings, demonstration-limited section, attack chains; export JSON / print to PDF |
| `/settings` | **Settings** | Theme, data source, about (runtimes moved to **Connections**) |

## Data model

The console renders each engagement's own JSON exactly as the skills emit it (see
`../skills/_contract/*.schema.json`). `scripts/console.py` discovers every engagement under the
directory you point it at, publishes a `/engagements.json` manifest, and serves each engagement's
files under `/e/<id>/…` — the console lazy-loads the one you select. Per engagement:

- **`findings_consolidated.json`** (reporting) — `{ engagement, target, severity_counts, findings: [...], attack_chains: [...] }`, or a bare `findings` array. `findings[]` follow `finding.schema.json`; `attack_chains[]` are the composite, non-additive kill-chain write-ups (folded in but kept **out** of the severity counts).
- **`host_discovery.json`** (host-discovery) — `{ live_hosts: [...], api_endpoints: [...] }` → the Assets map + **Ports & services** table.
- **`chains.json`** (attack-chain-discovery) — `{ chains: [{ steps: [...] }] }` → the **Attack chains** graph (served as `/attack_chains.json`).
- **`scope.yaml`** (engagement root) — scope / rules / window → the **Scope** panel (the launcher converts it to `scope.json`).
- **`notebook.json`** (notebook / `scripts/notebook.py`) — `{ leads: [...], recon_intel: {...}, evidence: [...], roe: {...}, test_accounts: [...] }` → the **Notebook** view. "What isn't a finding yet": leads cross-link findings (`promoted_to` → `finding.id`) and the surface ledger; recon_intel aggregates the recon feeders. Cross-references the ledgers rather than duplicating them.

Agents stats and the activity timeline have no dedicated file — the console **derives** them from each
finding's `review.reviewer` + `review.reviewed_at`.

CVSS 3.1 base scores are computed in-browser (`lib/cvss.ts`) with the **same formula as
`../scripts/cvss.py`**, so the numbers match the engagement's authoritative scorer.

## Run

**Against your engagements** — the console is a static build; `scripts/console.py` builds it (first
run) and serves it alongside the engagement JSON, so the same UI renders *your* results:

```sh
python ../scripts/console.py                     # ALL engagements under engagements/ (default)
python ../scripts/console.py <engagement-dir>    # or just one, e.g. engagements/<client>-<date>/
#  → http://localhost:8787   (badge: "Live engagement")
```

Point it at the `engagements/` directory (the default) and it discovers every engagement inside and
serves them all at once — switch between them from the **Engagements** page or ⌘K; the active one's
data lazy-loads on selection and is remembered across reloads. Point it at a single engagement dir to
serve just that one. It searches each engagement recursively for `findings_consolidated.json`,
`host_discovery.json`, `chains.json` and `scope.yaml`/`scope.json`. Missing files just stay an empty
state. No Node is needed to serve once the console is built.

**Dev (empty state / UI work):**

```sh
cd console && npm install && npm run dev        # http://localhost:3000
```

## Launch & steer (opt-in control plane)

By default the console is a **viewer**: engagements are launched from the `redstrike` CLI. To
launch and steer them from the **Control plane** view instead, serve the console with the opt-in
backend rather than `console.py`:

```sh
python ../scripts/console_control.py --enable-control    # prints a URL + a bearer token
```

Open the URL, go to **Control plane**, paste the token, then scaffold or pick an engagement,
start an autonomous run, watch the live event stream, and approve deferred commands. The view
talks to token-gated, localhost-only `/api/*` routes and shells out to the same `redstrike` CLI,
so every gate (scope, fail-closed launch, deny-by-default allowlist, audit trail) still applies —
nothing is bypassed. See `../scripts/CONSOLE_CONTROL.md` for the security model and endpoints.
Served by the plain `console.py`, the Control plane view just explains how to start the backend.

## Loading data manually

Besides the launcher, you can click **Load data** in the top bar (or drag-and-drop) and select any
combination of `findings_consolidated.json`, `host_discovery.json`, `chains.json` and `scope.json` —
each file is routed by its shape. Parsing happens entirely in the browser; nothing is uploaded. The
badge flips to *Live engagement*; **Clear data** returns to the empty state.

> Engagement findings and evidence are sensitive and git-ignored. Keep them local and deliver
> through the agreed channel.

## Structure

```
app/            route = one view (client components over the shared store)
components/
  shell/        Sidebar, Topbar, AppShell, theme toggle, providers
  ui/           Card, Pill/Badge, KPI, Segmented + hand-built SVG charts
  findings/     FindingsTable, FindingDrawer
  chains/       ChainGraph (SVG flow)
lib/
  types.ts      data model (mirrors the finding / attack-chain schemas)
  data.ts       zero-state (emptyData) + static agent roster + real-shape builders/derivers
  cvss.ts       CVSS 3.1 base scorer (port of scripts/cvss.py)
  theme.ts      severity / verdict / confidence color maps
  stats.ts      aggregations (severity counts, verification, groupings)
  store.tsx     client store: active engagement, empty/live mode, JSON loader + classifier
```

## Theming

Colors are CSS variables (`app/globals.css`) exposed to Tailwind as tokens
(`bg`, `card`, `line`, `fg`, `muted`, `brand`) with full alpha support; `.dark` overrides them.
Severity/verdict colors are data, applied via inline style so the JIT never needs dynamic class
names. The theme switch (top bar / Settings) is persisted and supports system preference.

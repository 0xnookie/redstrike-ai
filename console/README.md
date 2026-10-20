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
| `/engagements` | **Engagements** | The authorized assessment; pick one to make it the active context |
| `/findings` | **Findings** | Filterable/sortable table + full detail drawer (CVSS, mappings, reproduction, evidence, remediation, reviewer verdict) |
| `/chains` | **Attack chains** | Kill-chain flow graph composed from accepted findings |
| `/assets` | **Assets & scope** | In/out-of-scope tree, RoE rules, force-directed coverage map, asset table, and **open ports & services** from host discovery |
| `/activity` | **Activity** | Execution timeline derived from each finding's reviewer record (findings → reviews) |
| `/agents` | **Agents** | The executor + independent-reviewer fleet, by family and tier; per-skill produced/accepted counts derived from the loaded findings |
| `/report` | **Report** | Client-ready assembly: executive summary, risk-ordered findings, demonstration-limited section, attack chains; export JSON / print to PDF |
| `/settings` | **Settings** | Theme, data source, about |

## Data model

The console renders the engagement's own JSON exactly as the skills emit it (see
`../skills/_contract/*.schema.json`). It served at the site root by `scripts/console.py` under the
canonical names the console fetches on open:

- **`findings_consolidated.json`** (reporting) — `{ engagement, target, severity_counts, findings: [...], attack_chains: [...] }`, or a bare `findings` array. `findings[]` follow `finding.schema.json`; `attack_chains[]` are the composite, non-additive kill-chain write-ups (folded in but kept **out** of the severity counts).
- **`host_discovery.json`** (host-discovery) — `{ live_hosts: [...], api_endpoints: [...] }` → the Assets map + **Ports & services** table.
- **`chains.json`** (attack-chain-discovery) — `{ chains: [{ steps: [...] }] }` → the **Attack chains** graph (served as `/attack_chains.json`).
- **`scope.yaml`** (engagement root) — scope / rules / window → the **Scope** panel (the launcher converts it to `scope.json`).

Agents stats and the activity timeline have no dedicated file — the console **derives** them from each
finding's `review.reviewer` + `review.reviewed_at`.

CVSS 3.1 base scores are computed in-browser (`lib/cvss.ts`) with the **same formula as
`../scripts/cvss.py`**, so the numbers match the engagement's authoritative scorer.

## Run

**Against an engagement** — the console is a static build; `scripts/console.py` builds it (first run)
and serves it alongside the engagement's JSON, so the same UI renders *your* results:

```sh
python ../scripts/console.py <engagement-dir>    # e.g. engagements/<client>-<date>/
#  → http://localhost:8787   (badge: "Live engagement")
```

It searches the engagement dir recursively for `findings_consolidated.json`, `host_discovery.json`,
`chains.json` and `scope.yaml`/`scope.json`, serves each at the site root under its canonical name,
and the console **auto-loads** them on open. Missing files just stay an empty state. No Node is needed
to serve once the console is built.

**Dev (empty state / UI work):**

```sh
cd console && npm install && npm run dev        # http://localhost:3000
```

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

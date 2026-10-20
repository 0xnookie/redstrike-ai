# Redstrike Console

A web UI over the Redstrike engagement data model — a multi-view console for running and
reviewing an AI-driven penetration test. Built with **Next.js (App Router) + TypeScript +
TailwindCSS**, with a **dark / light theme switch** and no backend: it renders the same JSON
the framework's skills emit, and falls back to a built-in demo dataset so it runs immediately.

## Views

| Route | View | What it shows |
|---|---|---|
| `/` | **Dashboard** | KPIs, severity donut, findings-over-time, activity feed, top findings, category/asset breakdowns, two-altitude review roll-up |
| `/engagements` | **Engagements** | All authorized assessments; pick one to make it the active context |
| `/findings` | **Findings** | Filterable/sortable table + full detail drawer (CVSS, mappings, reproduction, evidence, remediation, reviewer verdict) |
| `/chains` | **Attack chains** | Kill-chain flow graph composed from accepted findings |
| `/assets` | **Assets & scope** | In/out-of-scope tree, RoE rules, force-directed coverage map, asset table, and **open ports & services** from host discovery |
| `/activity` | **Activity** | Execution timeline across the agent fleet (recon → findings → reviews → approvals → chains) |
| `/agents` | **Agents** | The executor + independent-reviewer fleet, by family and tier |
| `/report` | **Report** | Client-ready assembly: executive summary, risk-ordered findings, demonstration-limited section, attack chains; export JSON / print to PDF |
| `/settings` | **Settings** | Theme, data source, about |

## Data model

The console renders the engagement's own JSON (see `../skills/_contract/*.schema.json`):

- `findings_consolidated.json` — array of `finding.schema.json`
- `attack_chains.json` — `attack_chain.schema.json`
- `scope.json` — engagement scope / rules / window
- `host_discovery.json` — hosts + open ports/services (`{ hosts: [{ host, ip, ports: [{ port, service, version }] }] }`) → the Ports & services table

CVSS 3.1 base scores are computed in-browser (`lib/cvss.ts`) with the **same formula as
`../scripts/cvss.py`**, so the numbers match the engagement's authoritative scorer. Composite
kill-chains are excluded from severity counts, matching the reporting skill.

## Run

**Dev (demo data):**

```sh
cd console && npm install && npm run dev        # http://localhost:3000
```

**Against a live engagement** — the console is a static build; `scripts/console.py` serves it and
feeds it the JSON a real engagement produces, so the same UI renders *your* results:

```sh
npm run build                                    # once → console/out/
python ../scripts/console.py <engagement-dir>    # e.g. engagements/<client>-<date>/
python ../scripts/console.py ../samples/acme-demo   # or the bundled sample
#  → http://localhost:8787   (badge flips to "Live engagement")
```

It searches the engagement dir (recursively) for `findings_consolidated.json`, `host_discovery.json`,
`scope.json` and `attack_chains.json`, serves each at the site root, and the console **auto-loads**
them on open. Missing files just stay on demo data; no Node is needed to serve. `npm run serve` is a
shortcut for the bundled sample.

## Loading real engagement data

Everything starts on the embedded **demo** dataset (badge: *Demo data*). To view a real
engagement, click **Load data** in the top bar (or drag-and-drop) and select any combination of
`findings_consolidated.json`, `scope.json`, `host_discovery.json` and `attack_chains.json` — each file is routed by its
shape. Parsing happens entirely in the browser; nothing is uploaded. The badge flips to *Live
engagement*; **Reset to demo** restores the sample.

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
  data.ts       embedded demo dataset
  cvss.ts       CVSS 3.1 base scorer (port of scripts/cvss.py)
  theme.ts      severity / verdict / confidence color maps
  stats.ts      aggregations (severity counts, verification, groupings)
  store.tsx     client store: active engagement, demo/live mode, JSON loader
```

## Theming

Colors are CSS variables (`app/globals.css`) exposed to Tailwind as tokens
(`bg`, `card`, `line`, `fg`, `muted`, `brand`) with full alpha support; `.dark` overrides them.
Severity/verdict colors are data, applied via inline style so the JIT never needs dynamic class
names. The theme switch (top bar / Settings) is persisted and supports system preference.

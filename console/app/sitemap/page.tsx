"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import {
  Globe, Folder, FileText, ChevronRight, Search, Download, Copy, Check,
  Bug, Link2, Braces, AlertTriangle, ListTree, ChevronsDownUp, ChevronsUpDown,
  ScrollText, Radio,
} from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx, isReportable, verdictOf } from "@/lib/format";
import { SEVERITY, VERDICT, sevMeta } from "@/lib/theme";
import type { Finding, HttpExchange } from "@/lib/types";
import {
  buildSiteMap, subtreeRoutes, sortedChildren, nodeUrl, routeSeverityRank,
  type SiteNode, type SiteRoute,
} from "@/lib/siteMap";
import { Kpi, Pill, Dot, ViewHead, Panel, PanelHeader, EmptyState, Segmented } from "@/components/ui/primitives";

/* ── status + type presentation ─────────────────────────────────────────── */
const codeColor = (s?: number): string =>
  s == null ? "#64748b" : s >= 500 ? "#f43f5e" : s >= 400 ? "#facc15" : s >= 300 ? "#38bdf8" : "#22c55e";
const codeBucket = (s?: number): string => (s == null ? "none" : `${String(s)[0]}xx`);

const TYPE_COLOR: Record<string, string> = {
  html: "#60a5fa", form: "#a78bfa", json: "#34d399", graphql: "#f472b6", "graphql-ide": "#f472b6",
  websocket: "#fb923c", xml: "#38bdf8", script: "#64748b", css: "#64748b", image: "#64748b", font: "#64748b",
};
const typeColor = (t?: string) => (t ? TYPE_COLOR[t.toLowerCase()] ?? "#94a3b8" : "#94a3b8");

const SOURCE_LABEL: Record<string, string> = {
  content: "crawl", host: "host-disc", api: "api", finding: "finding", history: "proxy",
};

const STATIC_RE = /\.(css|js|mjs|cjs|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|otf|eot|map)$/i;
const isStatic = (rt: SiteRoute): boolean =>
  ["css", "script", "image", "font"].includes((rt.type ?? "").toLowerCase()) || STATIC_RE.test(rt.path.split("?")[0]);

/* ── table columns ──────────────────────────────────────────────────────── */
type SortKey = "method" | "url" | "status" | "type" | "source" | "issue";
const COLS: { k: SortKey; label: string; num?: boolean }[] = [
  { k: "method", label: "Method" }, { k: "url", label: "URL" }, { k: "status", label: "Status" },
  { k: "type", label: "Type" }, { k: "source", label: "Source" }, { k: "issue", label: "Finding" },
];

export default function SiteMapPage() {
  const { activeEngagement: eng, activeId, content, hostRaw, history, findings, openHost, openFinding } = useConsole();

  const byId = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);
  const map = useMemo(() => buildSiteMap(content, hostRaw, findings, history), [content, hostRaw, findings, history]);

  // filters
  const [show, setShow] = useState<"all" | "issues">("all");
  const [codes, setCodes] = useState<Set<string>>(new Set(["2xx", "3xx", "4xx", "5xx", "none"]));
  const [hideStatic, setHideStatic] = useState(false);
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<{ k: SortKey; dir: 1 | -1 }>({ k: "url", dir: 1 });

  // tree + selection state
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [sel, setSel] = useState<string | null>(null);
  const [selRoute, setSelRoute] = useState<string | null>(null);
  const treeRef = useRef<HTMLDivElement>(null);

  // seed: open every host root once (hosts are few); reset selection per engagement
  const rootKeys = map.roots.map((r) => r.key).join("|");
  useEffect(() => {
    setOpen((prev) => { const next = new Set(prev); for (const r of map.roots) next.add(r.key); return next; });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rootKeys]);
  useEffect(() => { setSel(null); setSelRoute(null); }, [activeId]);

  /* route-level filter predicate */
  const passRoute = (rt: SiteRoute): boolean => {
    if (show === "issues" && rt.findingIds.length === 0) return false;
    if (!codes.has(codeBucket(rt.status))) return false;
    if (hideStatic && isStatic(rt)) return false;
    const s = q.trim().toLowerCase();
    if (s && !`${rt.method} ${rt.host}${rt.path} ${rt.type ?? ""} ${rt.note ?? ""}`.toLowerCase().includes(s)) return false;
    return true;
  };

  /* per-node aggregation (pass count + worst finding rank), computed once per render */
  const agg = useMemo(() => {
    const m = new Map<string, { pass: number; issues: number; rank: number }>();
    const walk = (n: SiteNode): { pass: number; issues: number; rank: number } => {
      let pass = 0, issues = 0, rank = 0;
      for (const rt of n.routes) {
        if (!passRoute(rt)) continue;
        pass++;
        if (rt.findingIds.length) { issues++; rank = Math.max(rank, routeSeverityRank(rt, byId)); }
      }
      for (const c of n.children) { const a = walk(c); pass += a.pass; issues += a.issues; rank = Math.max(rank, a.rank); }
      const a = { pass, issues, rank }; m.set(n.key, a); return a;
    };
    map.roots.forEach(walk);
    return m;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [map, byId, show, codes, hideStatic, q]);

  /* flattened, filtered, respecting open/closed (search force-opens) */
  const flat = useMemo(() => {
    const forceOpen = !!q.trim();
    const out: { n: SiteNode; depth: number; hasKids: boolean; open: boolean }[] = [];
    const rec = (list: SiteNode[], depth: number) => {
      for (const n of list) {
        if ((agg.get(n.key)?.pass ?? 0) === 0) continue;
        const kids = sortedChildren(n).filter((c) => (agg.get(c.key)?.pass ?? 0) > 0);
        const isOpen = kids.length > 0 && (forceOpen || open.has(n.key));
        out.push({ n, depth, hasKids: kids.length > 0, open: isOpen });
        if (isOpen) rec(kids, depth + 1);
      }
    };
    rec(map.roots, 0);
    return out;
  }, [map, agg, open, q]);

  /* effective selection (fall back when the selected node is filtered out) */
  const selKey = useMemo(() => {
    if (sel && flat.some((x) => x.n.key === sel)) return sel;
    return flat[0]?.n.key ?? null;
  }, [sel, flat]);
  const selNode = selKey ? map.nodes.get(selKey) ?? null : null;

  /* contents table rows = passing routes in the selected subtree, sorted */
  const rows = useMemo(() => {
    if (!selNode) return [];
    const rank = (rt: SiteRoute) => routeSeverityRank(rt, byId);
    const key: Record<SortKey, (rt: SiteRoute) => string | number> = {
      method: (r) => r.method, url: (r) => r.path, status: (r) => r.status ?? 1000,
      type: (r) => r.type ?? "", source: (r) => r.sources[0] ?? "", issue: (r) => rank(r),
    };
    return subtreeRoutes(selNode).filter(passRoute).sort((a, b) => {
      const x = key[sort.k](a), y = key[sort.k](b);
      const c = typeof x === "string" ? x.localeCompare(y as string) : (x as number) - (y as number);
      return c * sort.dir || a.path.localeCompare(b.path) || a.method.localeCompare(b.method);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selNode, byId, sort, show, codes, hideStatic, q]);

  const routeId = useMemo(() => (rows.some((r) => r.id === selRoute) ? selRoute : rows[0]?.id ?? null), [rows, selRoute]);
  const route = routeId ? rows.find((r) => r.id === routeId) ?? null : null;

  /* findings in the selected branch (non-composite, severity-sorted) */
  const branchFindings = useMemo(() => {
    if (!selNode) return [];
    const ids = new Set<string>();
    for (const rt of subtreeRoutes(selNode)) for (const id of rt.findingIds) ids.add(id);
    return Array.from(ids).map((id) => byId.get(id)).filter((f): f is Finding => !!f)
      .sort((a, b) => (SEVERITY[b.severity]?.rank ?? 0) - (SEVERITY[a.severity]?.rank ?? 0));
  }, [selNode, byId]);

  /* tree keyboard navigation */
  const onTreeKey = (e: React.KeyboardEvent) => {
    const cur = (e.target as HTMLElement).closest<HTMLElement>("[data-key]");
    if (!cur) return;
    const i = flat.findIndex((x) => x.n.key === cur.dataset.key);
    if (i < 0) return;
    const it = flat[i];
    const go = (j: number) => { if (j >= 0 && j < flat.length) selectNode(flat[j].n.key, true); };
    switch (e.key) {
      case "ArrowDown": go(i + 1); break;
      case "ArrowUp": go(i - 1); break;
      case "Home": go(0); break;
      case "End": go(flat.length - 1); break;
      case "ArrowRight": if (it.hasKids && !it.open) toggle(it.n.key); else if (it.hasKids) go(i + 1); break;
      case "ArrowLeft": if (it.hasKids && it.open) toggle(it.n.key); else if (it.n.parent) selectNode(it.n.parent.key, true); break;
      case "Enter": case " ": if (it.hasKids) toggle(it.n.key); break;
      default: return;
    }
    e.preventDefault();
  };

  const toggle = (key: string) => setOpen((prev) => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });
  const selectNode = (key: string, focus?: boolean) => {
    setSel(key);
    setSelRoute(null);
    if (focus) requestAnimationFrame(() => {
      // node keys contain slashes/“?”, so match by dataset rather than a CSS selector
      treeRef.current?.querySelectorAll<HTMLElement>("[data-key]").forEach((el) => {
        if (el.dataset.key === key) el.focus({ preventScroll: false });
      });
    });
  };
  const expandAll = () => setOpen(() => { const n = new Set<string>(); map.nodes.forEach((v, k) => { if (v.children.length) n.add(k); }); return n; });
  const collapseAll = () => setOpen(new Set());

  const toggleCode = (k: string) => setCodes((prev) => { const n = new Set(prev); n.has(k) ? n.delete(k) : n.add(k); return n; });

  /* CSV export of the whole (filtered) site map */
  const exportCsv = () => {
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = ["host,path,methods,status,type,params,source,findings"];
    for (const rt of map.routes.filter(passRoute)) {
      lines.push([rt.host, rt.path, rt.methods.join("|"), rt.status ?? "", rt.type ?? "",
        rt.params.join("|"), rt.sources.join("|"), rt.findingIds.join("|")].map(esc).join(","));
    }
    const blob = new Blob([lines.join("\n")], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = `${activeId || "engagement"}-sitemap.csv`; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  };

  /* counts for the filter chips */
  const counts = useMemo(() => {
    const c: Record<string, number> = { all: map.routes.length, issues: 0, "2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, none: 0 };
    for (const rt of map.routes) { if (rt.findingIds.length) c.issues++; c[codeBucket(rt.status)]++; }
    return c;
  }, [map.routes]);

  const withFindings = map.routes.filter((r) => r.findingIds.length).length;

  if (map.routeCount === 0) {
    return (
      <>
        <ViewHead crumb="redstrike / site map" title="Site Map" sub={eng.name} />
        <Panel tall>
          <EmptyState
            icon={<ListTree size={28} />}
            title="No crawl surface yet"
            hint="The Site Map is built from content-discovery's content.json plus host-discovery and findings. Run content-discovery (or point scripts/console.py at an engagement that has), or drop content.json / host_discovery.json here."
          />
        </Panel>
      </>
    );
  }

  return (
    <>
      <ViewHead
        crumb="redstrike / site map"
        title="Site Map"
        live={eng.status === "running"}
        sub={`${map.hostCount} host${map.hostCount === 1 ? "" : "s"} · ${map.routeCount} URLs · ${withFindings} with findings${map.exchangeCount ? ` · ${map.exchangeCount} captured` : ""}`}
        actions={
          <>
            <button onClick={exportCsv} className="btn-ghost"><Download size={14} /> Export CSV</button>
          </>
        }
      />

      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
        <Kpi label="Hosts" value={map.hostCount} icon={<Globe size={16} />} note="in the site map" />
        <Kpi label="URLs" value={map.routeCount} icon={<Link2 size={16} />} note="discovered" />
        <Kpi label="With findings" value={withFindings} color={withFindings ? SEVERITY.high.color : undefined} icon={<Bug size={16} />} note="URLs linked to a finding" />
        {map.exchangeCount ? (
          <Kpi label="Captured" value={map.exchangeCount} icon={<Radio size={16} />} note={`proxy history${map.proxySource ? ` · ${map.proxySource}` : ""}`} />
        ) : (
          <Kpi label="Parameters" value={map.paramsDiscovered.length} icon={<Braces size={16} />} note="mined by recon" />
        )}
      </div>

      {map.crawlMethod && (
        <div className="mt-3 flex items-start gap-2 rounded-lg border border-line bg-card2 px-3 py-2 text-xs text-muted">
          <ScrollText size={13} className="mt-0.5 shrink-0 text-muted/80" />
          <span><span className="font-medium text-fg">Crawl method:</span> {map.crawlMethod}</span>
        </div>
      )}

      {/* filters */}
      <div className="mt-5 flex flex-wrap items-center gap-2.5">
        <Segmented
          value={show}
          onChange={setShow}
          options={[{ value: "all", label: `All (${counts.all})` }, { value: "issues", label: `With findings (${counts.issues})` }]}
        />
        <div className="inline-flex flex-wrap gap-1.5">
          {([["2xx", "#22c55e"], ["3xx", "#38bdf8"], ["4xx", "#facc15"], ["5xx", "#f43f5e"], ["none", "#64748b"]] as const).map(([k, c]) => (
            <button
              key={k}
              onClick={() => toggleCode(k)}
              aria-pressed={codes.has(k)}
              className={cx("inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 font-mono text-[11px] transition",
                codes.has(k) ? "border-line bg-card2 text-fg" : "border-line/60 text-faint opacity-60 hover:opacity-100")}
            >
              <span className="h-1.5 w-1.5 rounded-full" style={{ background: c }} />
              {k === "none" ? "no-status" : k}
              <span className="text-faint">{counts[k]}</span>
            </button>
          ))}
        </div>
        <button
          onClick={() => setHideStatic((v) => !v)}
          aria-pressed={hideStatic}
          className={cx("rounded-full border px-2.5 py-1 text-[11px] transition",
            hideStatic ? "border-brand/50 bg-brand/10 text-brand" : "border-line text-muted hover:text-fg")}
        >
          Hide static assets
        </button>
        <label className="relative ml-auto block w-full sm:w-64">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter URLs…"
            className="h-9 w-full rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40"
          />
        </label>
      </div>

      {/* main grid: tree | detail */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
        {/* tree */}
        <Panel tall>
          <PanelHeader
            title="Target"
            sub={`${map.hostCount} host${map.hostCount === 1 ? "" : "s"}`}
            actions={
              <>
                <button onClick={expandAll} title="Expand all" className="icon-btn"><ChevronsUpDown size={14} /></button>
                <button onClick={collapseAll} title="Collapse all" className="icon-btn"><ChevronsDownUp size={14} /></button>
              </>
            }
          />
          <div ref={treeRef} role="tree" aria-label="Site map" onKeyDown={onTreeKey} className="scroll-thin max-h-[560px] overflow-y-auto px-2 pb-3">
            {flat.length === 0 ? (
              <div className="py-10 text-center text-sm text-muted">No URLs match these filters.</div>
            ) : (
              flat.map((it, i) => (
                <TreeRow
                  key={it.n.key}
                  it={it}
                  a={agg.get(it.n.key) ?? { pass: 0, issues: 0, rank: 0 }}
                  selected={it.n.key === selKey}
                  tabbable={it.n.key === selKey || (!flat.some((x) => x.n.key === selKey) && i === 0)}
                  onSelect={() => selectNode(it.n.key)}
                  onToggle={() => toggle(it.n.key)}
                />
              ))
            )}
          </div>
          <div className="flex items-center gap-4 border-t border-line px-3 py-2 text-[11px] text-muted">
            <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: SEVERITY.critical.color }} /> worst finding on branch</span>
            <span className="inline-flex items-center gap-1.5 opacity-70"><FileText size={11} /> discovered URL</span>
          </div>
        </Panel>

        {/* right column */}
        <div className="flex min-w-0 flex-col gap-4">
          {/* contents table */}
          <Panel>
            <PanelHeader title="Contents" sub={selNode ? nodeUrl(selNode) : ""} actions={<span className="font-mono text-xs text-faint">{rows.length} item{rows.length === 1 ? "" : "s"}</span>} />
            <div className="scroll-thin max-h-[300px] overflow-auto">
              <table className="w-full border-collapse text-sm">
                <thead className="sticky top-0 z-[1] bg-card">
                  <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                    {COLS.map((c) => {
                      const on = sort.k === c.k;
                      return (
                        <th key={c.k} className="px-3 py-2.5 font-medium">
                          <button
                            onClick={() => setSort((s) => (s.k === c.k ? { k: c.k, dir: (s.dir * -1) as 1 | -1 } : { k: c.k, dir: c.k === "issue" || c.k === "status" ? -1 : 1 }))}
                            className="inline-flex items-center gap-1 hover:text-fg"
                          >
                            {c.label}
                            <span className="text-[9px]">{on ? (sort.dir < 0 ? "▼" : "▲") : ""}</span>
                          </button>
                        </th>
                      );
                    })}
                  </tr>
                </thead>
                <tbody>
                  {rows.map((rt) => (
                    <RouteRow key={rt.id} rt={rt} byId={byId} selected={rt.id === routeId} onPick={() => setSelRoute(rt.id)} />
                  ))}
                </tbody>
              </table>
              {rows.length === 0 && <div className="py-10 text-center text-sm text-muted">Nothing in this branch matches the filters.</div>}
            </div>
          </Panel>

          {/* route detail */}
          <Panel tall>
            <PanelHeader
              title="Request"
              sub={route ? `${route.method} ${route.path}` : ""}
              actions={route?.exchanges?.length ? <span className="inline-flex items-center gap-1 font-mono text-[11px] text-emerald-500"><Radio size={11} /> {route.exchanges.length} captured</span> : undefined}
            />
            <div className="scroll-thin max-h-[440px] overflow-y-auto px-[22px] pb-5">
              {route ? <RouteDetail key={route.id} rt={route} byId={byId} onHost={openHost} onFinding={(f) => openFinding(f)} sinks={map.notableSinks} /> : (
                <div className="py-10 text-center text-sm text-muted">Select a URL to inspect what recon discovered.</div>
              )}
            </div>
          </Panel>

          {/* findings in branch */}
          <Panel>
            <PanelHeader title="Findings" sub="in selection" actions={branchFindings.length ? <span className="font-mono text-xs text-faint">{branchFindings.length}</span> : undefined} />
            <div className="px-[22px] pb-4">
              {branchFindings.length === 0 ? (
                <div className="py-6 text-center text-xs text-muted">No findings linked to this branch.</div>
              ) : (
                <ul className="space-y-1.5">
                  {branchFindings.map((f) => (
                    <li key={f.id}>
                      <button onClick={() => openFinding(f)} className="flex w-full items-start gap-2 rounded-lg border border-line bg-card2 px-2.5 py-2 text-left transition hover:border-brand/40">
                        <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ background: sevMeta(f.severity).color }} />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm font-medium">{f.title}</span>
                          <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
                            <span className="font-mono">{f.id}</span>
                            <span className="uppercase" style={{ color: sevMeta(f.severity).color }}>{SEVERITY[f.severity]?.label ?? f.severity}</span>
                            {verdictOf(f) && <Pill label={VERDICT[verdictOf(f) as keyof typeof VERDICT].label} color={VERDICT[verdictOf(f) as keyof typeof VERDICT].color} />}
                          </span>
                        </span>
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          </Panel>
        </div>
      </div>

      {/* recon intel from content.json: notable sinks + the mined parameter list.
          Shown whole (not path-scoped) because these are engagement-level signals. */}
      {(map.notableSinks.length > 0 || map.paramsDiscovered.length > 0) && (
        <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
          {map.notableSinks.length > 0 && (
            <Panel>
              <PanelHeader title="Notable sinks" sub="content-discovery" icon={<AlertTriangle size={15} className="text-amber-500" />} />
              <div className="space-y-2 px-[22px] pb-4">
                {map.notableSinks.map((s) => (
                  <div key={s.category} className="rounded-lg border border-line bg-card2 px-3 py-2">
                    <div className="mb-1 text-[11px] font-semibold uppercase tracking-wide" style={{ color: s.category.includes("destructive") ? SEVERITY.critical.color : "#f59e0b" }}>
                      {s.category.replace(/_/g, " ")}
                    </div>
                    <div className="flex flex-wrap gap-1.5">
                      {s.items.map((it) => <code key={it} className="rounded bg-card px-1.5 py-0.5 font-mono text-[11px] text-muted">{it}</code>)}
                    </div>
                  </div>
                ))}
              </div>
            </Panel>
          )}
          {map.paramsDiscovered.length > 0 && (
            <Panel>
              <PanelHeader title="Discovered parameters" sub={`${map.paramsDiscovered.length} mined`} icon={<Braces size={15} className="text-muted" />} />
              <div className="px-[22px] pb-4">
                <div className="flex flex-wrap gap-1.5">
                  {map.paramsDiscovered.map((p) => <code key={p} className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[11px] text-muted">{p}</code>)}
                </div>
              </div>
            </Panel>
          )}
        </div>
      )}
    </>
  );
}

/* ── tree row ───────────────────────────────────────────────────────────── */
function TreeRow({
  it, a, selected, tabbable, onSelect, onToggle,
}: {
  it: { n: SiteNode; depth: number; hasKids: boolean; open: boolean };
  a: { pass: number; issues: number; rank: number };
  selected: boolean; tabbable: boolean; onSelect: () => void; onToggle: () => void;
}) {
  const { n, depth, hasKids, open } = it;
  const ghost = a.issues === 0 && n.routes.every((r) => r.findingIds.length === 0);
  const Icon = n.kind === "host" ? Globe : n.kind === "q" ? Braces : (n.children.length || n.dir) ? Folder : FileText;
  const sevKey = (["info", "low", "medium", "high", "critical"] as const)[a.rank - 1];
  return (
    <div
      role="treeitem"
      aria-level={depth + 1}
      aria-selected={selected}
      aria-expanded={hasKids ? open : undefined}
      data-key={n.key}
      tabIndex={tabbable ? 0 : -1}
      onClick={onSelect}
      title={nodeUrl(n)}
      className={cx(
        "group flex cursor-pointer items-center gap-1.5 rounded-md py-1.5 pr-2 text-sm outline-none transition",
        selected ? "bg-brand/10 text-fg-strong" : "hover:bg-fg/[0.04]",
        "focus-visible:ring-1 focus-visible:ring-brand/50",
      )}
      style={{ paddingLeft: 6 + depth * 14 }}
    >
      <span
        className={cx("grid h-4 w-4 shrink-0 place-items-center text-muted transition", hasKids ? "" : "opacity-0")}
        onClick={(e) => { if (hasKids) { e.stopPropagation(); onToggle(); } }}
      >
        <ChevronRight size={13} className={cx("transition", open && "rotate-90")} />
      </span>
      <Icon size={14} className={cx("shrink-0", n.kind === "host" ? "text-brand" : ghost ? "text-muted/60" : "text-muted")} />
      <span className={cx("min-w-0 flex-1 truncate font-mono text-[12.5px]", ghost && n.kind !== "host" && "text-muted")}>{n.label}</span>
      {a.rank > 0 && sevKey && (
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY[sevKey].color }} title={`${SEVERITY[sevKey].label} finding in this branch`} />
      )}
      {n.kind === "host" && <span className="shrink-0 font-mono text-[10px] text-faint">{a.pass}</span>}
    </div>
  );
}

/* ── contents table row ─────────────────────────────────────────────────── */
function RouteRow({ rt, byId, selected, onPick }: { rt: SiteRoute; byId: Map<string, Finding>; selected: boolean; onPick: () => void }) {
  const worst = rt.findingIds.map((id) => byId.get(id)).filter(Boolean) as Finding[];
  worst.sort((a, b) => (SEVERITY[b.severity]?.rank ?? 0) - (SEVERITY[a.severity]?.rank ?? 0));
  const top = worst[0];
  return (
    <tr
      onClick={onPick}
      className={cx("cursor-pointer border-t border-line/70 transition", selected ? "bg-brand/[0.08]" : "hover:bg-fg/[0.03]")}
    >
      <td className="px-3 py-2"><span className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[11px] font-medium">{rt.method}</span></td>
      <td className="px-3 py-2">
        <span className="block max-w-[320px] truncate font-mono text-[12.5px] text-fg" title={`https://${rt.host}${rt.path}`}>{rt.path}</span>
        {rt.params.length > 0 && <span className="text-[10px] text-faint">{rt.params.length} param{rt.params.length === 1 ? "" : "s"}</span>}
      </td>
      <td className="px-3 py-2">
        {rt.status != null ? (
          <span className="font-mono text-xs font-medium" style={{ color: codeColor(rt.status) }}>{rt.status}</span>
        ) : <span className="text-faint">—</span>}
      </td>
      <td className="px-3 py-2">{rt.type ? <Pill label={rt.type} color={typeColor(rt.type)} /> : <span className="text-faint">—</span>}</td>
      <td className="px-3 py-2"><span className="text-[11px] text-muted">{rt.sources.map((s) => SOURCE_LABEL[s] ?? s).join(", ")}</span></td>
      <td className="px-3 py-2">
        {top ? (
          <span className="inline-flex items-center gap-1.5 text-[11px]" style={{ color: sevMeta(top.severity).color }} title={top.title}>
            <span className="h-1.5 w-1.5 rounded-full" style={{ background: sevMeta(top.severity).color }} />
            {rt.findingIds.length}
          </span>
        ) : <span className="text-faint">—</span>}
      </td>
    </tr>
  );
}

/* ── route detail ───────────────────────────────────────────────────────── */
function CopyBtn({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text); setDone(true); setTimeout(() => setDone(false), 1200); }}
      className="btn-ghost"
      title={`Copy ${label}`}
    >
      {done ? <Check size={13} /> : <Copy size={13} />} {done ? "Copied" : label}
    </button>
  );
}

/* ── captured request/response viewer (real proxy history) ──────────────── */
const STATUS_TEXT: Record<number, string> = {
  200: "OK", 201: "Created", 202: "Accepted", 204: "No Content", 301: "Moved Permanently", 302: "Found",
  304: "Not Modified", 307: "Temporary Redirect", 308: "Permanent Redirect", 400: "Bad Request",
  401: "Unauthorized", 403: "Forbidden", 404: "Not Found", 405: "Method Not Allowed", 409: "Conflict",
  422: "Unprocessable Entity", 429: "Too Many Requests", 500: "Internal Server Error", 502: "Bad Gateway",
  503: "Service Unavailable",
};

/* Highlight ‹redacted› markers the feeder wrote so a viewer can't mistake a stripped
   secret for real content (and so nothing sensitive is ever shown). */
function Redacted({ text }: { text: string }) {
  return (
    <>
      {text.split(/(‹[^›]*›)/).filter(Boolean).map((p, i) =>
        /^‹.*›$/.test(p)
          ? <span key={i} className="rounded bg-amber-500/15 px-1 text-amber-500/90" title="redacted on export">{p}</span>
          : <span key={i}>{p}</span>,
      )}
    </>
  );
}

function RawHttp({ kind, ex }: { kind: "req" | "res"; ex: HttpExchange }) {
  const m = kind === "req" ? ex.req : ex.res;
  if (!m && kind === "res") return <div className="rounded-lg border border-dashed border-line px-3 py-3 text-xs text-muted">No response captured for this exchange.</div>;
  if (!m && kind === "req") return <div className="rounded-lg border border-dashed border-line px-3 py-3 text-xs text-muted">No request body captured for this exchange.</div>;
  const start = kind === "req"
    ? `${ex.method ?? "GET"} ${ex.path} HTTP/1.1`
    : `HTTP/1.1 ${ex.status ?? ""} ${ex.status != null ? (STATUS_TEXT[ex.status] ?? "") : ""}`.trim();
  const headers = m?.headers ?? [];
  // synthesize a Host header on requests that don't carry one (so the line reads like a real request)
  const hostH: [string, string][] = kind === "req" && !headers.some(([h]) => h.toLowerCase() === "host") ? [["Host", ex.host]] : [];
  const allH = [...hostH, ...headers];
  const body = m?.body ?? "";
  const text = [start, ...allH.map(([k, v]) => `${k}: ${v}`), "", body].join("\n").trimEnd();
  return (
    <div className="overflow-hidden rounded-lg border border-line bg-card2">
      <div className="flex items-center justify-between border-b border-line px-2.5 py-1.5">
        <span className="font-mono text-[10px] uppercase tracking-wide text-muted">{kind === "req" ? "raw request" : "raw response"}</span>
        <CopyBtn text={text} label="Copy" />
      </div>
      <pre className="scroll-thin max-h-60 overflow-auto px-3 py-2 font-mono text-[11.5px] leading-relaxed">
        <div className="font-medium" style={kind === "res" ? { color: codeColor(ex.status) } : { color: "rgb(var(--fg-strong))" }}>{start}</div>
        {allH.map(([k, v], i) => (
          <div key={i}><span className="text-sky-400/80">{k}</span><span className="text-muted">: </span><Redacted text={v} /></div>
        ))}
        {body && (
          <>
            <div className="h-2" />
            {body.split("\n").map((l, i) => <div key={i} className="whitespace-pre-wrap break-all text-fg"><Redacted text={l} /></div>)}
          </>
        )}
      </pre>
    </div>
  );
}

function CapturedExchange({ exchanges }: { exchanges: HttpExchange[] }) {
  const [idx, setIdx] = useState(0);
  const [tab, setTab] = useState<"req" | "res">("req");
  const ex = exchanges[Math.min(idx, exchanges.length - 1)];
  return (
    <DetailBlock icon={<Radio size={13} className="text-emerald-500" />} title="Captured exchange" count={exchanges.length > 1 ? exchanges.length : undefined}>
      {exchanges.length > 1 && (
        <div className="mb-2 flex flex-wrap gap-1.5">
          {exchanges.map((e, i) => (
            <button
              key={e.id ?? i}
              onClick={() => setIdx(i)}
              aria-pressed={i === idx}
              className={cx("rounded-full border px-2 py-0.5 font-mono text-[10px] transition",
                i === idx ? "border-brand/50 bg-brand/10 text-brand" : "border-line text-muted hover:text-fg")}
            >
              {e.method ?? "GET"} {e.status ?? "—"}
            </button>
          ))}
        </div>
      )}
      <div className="mb-2 inline-flex rounded-full border border-line bg-card2 p-0.5">
        {(["req", "res"] as const).map((k) => (
          <button
            key={k}
            onClick={() => setTab(k)}
            className={cx("rounded-full px-2.5 py-1 text-xs font-medium transition", tab === k ? "bg-brand text-brand-fg shadow-sm" : "text-muted hover:text-fg")}
          >
            {k === "req" ? "Request" : "Response"}
          </button>
        ))}
      </div>
      <RawHttp kind={tab} ex={ex} />
      {(ex.mime || ex.length != null || ex.ms != null) && (
        <div className="mt-1.5 flex flex-wrap gap-2 font-mono text-[10px] text-faint">
          {ex.mime && <span>{ex.mime}</span>}
          {ex.length != null && <span>{ex.length} B</span>}
          {ex.ms != null && <span>{ex.ms} ms</span>}
        </div>
      )}
    </DetailBlock>
  );
}

function RouteDetail({
  rt, byId, onHost, onFinding, sinks,
}: {
  rt: SiteRoute; byId: Map<string, Finding>;
  onHost: (h: string) => void; onFinding: (f: Finding) => void;
  sinks: { category: string; items: string[] }[];
}) {
  const url = `https://${rt.host}${rt.path}`;
  const curl = [`curl -X ${rt.method} '${url}'`, `  -H 'User-Agent: redstrike-console'`].join(" \\\n");
  const finds = rt.findingIds.map((id) => byId.get(id)).filter((f): f is Finding => !!f)
    .sort((a, b) => (SEVERITY[b.severity]?.rank ?? 0) - (SEVERITY[a.severity]?.rank ?? 0));
  // notable sinks whose identifier appears in this route's path (e.g. graphql field on /graphql)
  const related = sinks
    .map((s) => ({ category: s.category, items: s.items.filter((it) => rt.path.toLowerCase().includes(it.toLowerCase().replace(/\(.*$/, ""))) }))
    .filter((s) => s.items.length);

  return (
    <div className="space-y-4">
      {/* header line */}
      <div>
        <div className="flex flex-wrap items-center gap-2">
          {rt.methods.map((m) => <span key={m} className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[11px] font-medium text-fg-strong">{m}</span>)}
          {rt.status != null && <Pill label={`HTTP ${rt.status}`} color={codeColor(rt.status)} dot />}
          {rt.type && <Pill label={rt.type} color={typeColor(rt.type)} />}
          {rt.confirmed && <Pill label="confirmed" color="#22c55e" dot />}
          {rt.introspection && <Pill label="introspection on" color="#f472b6" />}
          {rt.sources.map((s) => <Pill key={s} label={SOURCE_LABEL[s] ?? s} color="#64748b" />)}
        </div>
        <div className="mt-2 break-all font-mono text-[12.5px] text-fg">{url}</div>
      </div>

      {/* actions */}
      <div className="flex flex-wrap items-center gap-1.5">
        <CopyBtn text={url} label="URL" />
        <CopyBtn text={curl} label="cURL" />
        <button onClick={() => onHost(rt.host)} className="btn-ghost"><Globe size={13} /> Inspect host</button>
      </div>

      {/* captured request/response (from the proxy history, when present) */}
      {rt.exchanges && rt.exchanges.length > 0 && <CapturedExchange exchanges={rt.exchanges} />}

      {/* recon notes */}
      {(rt.note || rt.js || rt.evidence) && (
        <DetailBlock icon={<ScrollText size={13} />} title="Recon notes">
          <dl className="space-y-1.5 text-sm">
            {rt.note && <DRow label="Note">{rt.note}</DRow>}
            {rt.js && <DRow label="JS origin">{rt.js}</DRow>}
            {rt.evidence && <DRow label="Evidence">{rt.evidence}</DRow>}
          </dl>
        </DetailBlock>
      )}

      {/* parameters */}
      {rt.params.length > 0 && (
        <DetailBlock icon={<Braces size={13} />} title="Parameters" count={rt.params.length}>
          <div className="flex flex-wrap gap-1.5">
            {rt.params.map((p) => <code key={p} className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[11px] text-muted">{p}</code>)}
          </div>
        </DetailBlock>
      )}

      {/* notable sinks that touch this route */}
      {related.length > 0 && (
        <DetailBlock icon={<AlertTriangle size={13} />} title="Notable sinks">
          <ul className="space-y-1.5">
            {related.map((s) => (
              <li key={s.category} className="rounded-lg border border-amber-500/30 bg-amber-500/[0.06] px-2.5 py-1.5 text-xs">
                <span className="font-medium uppercase tracking-wide text-amber-500">{s.category.replace(/_/g, " ")}</span>
                <div className="mt-0.5 flex flex-wrap gap-1.5">
                  {s.items.map((it) => <code key={it} className="font-mono text-[11px] text-muted">{it}</code>)}
                </div>
              </li>
            ))}
          </ul>
        </DetailBlock>
      )}

      {/* linked findings */}
      <DetailBlock icon={<Bug size={13} />} title="Findings on this URL" count={finds.length}>
        {finds.length === 0 ? (
          <div className="rounded-lg border border-dashed border-line px-3 py-3 text-xs text-muted">No findings linked to this URL.</div>
        ) : (
          <ul className="space-y-1.5">
            {finds.map((f) => (
              <li key={f.id}>
                <button onClick={() => onFinding(f)} className="flex w-full items-start gap-2 rounded-lg border border-line bg-card2 px-2.5 py-2 text-left transition hover:border-brand/40">
                  <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ background: sevMeta(f.severity).color }} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{f.title}</span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
                      <span className="font-mono">{f.id}</span>
                      {f.category?.owasp && <span>· {f.category.owasp}</span>}
                      {verdictOf(f) && <Pill label={VERDICT[verdictOf(f) as keyof typeof VERDICT].label} color={VERDICT[verdictOf(f) as keyof typeof VERDICT].color} />}
                    </span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </DetailBlock>
    </div>
  );
}

function DetailBlock({ icon, title, count, children }: { icon: React.ReactNode; title: string; count?: number; children: React.ReactNode }) {
  return (
    <section>
      <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
        <span className="text-muted/80">{icon}</span>
        {title}
        {count != null && <span className="rounded-full bg-card2 px-1.5 py-0.5 text-[10px] tabular-nums text-muted">{count}</span>}
      </div>
      {children}
    </section>
  );
}
function DRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <dt className="w-20 shrink-0 text-[11px] uppercase tracking-wide text-muted">{label}</dt>
      <dd className="min-w-0 flex-1 break-words">{children}</dd>
    </div>
  );
}

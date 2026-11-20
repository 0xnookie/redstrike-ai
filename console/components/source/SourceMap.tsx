"use client";

import { useEffect, useMemo, useState } from "react";
import {
  FolderTree, Folder, FileCode2, ChevronRight, Search, ShieldOff,
  Bug, Route, AlertTriangle, GitBranch, ListTree, Workflow,
} from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx, verdictOf } from "@/lib/format";
import { SEVERITY, sevMeta, verdictMeta } from "@/lib/theme";
import type { Finding, SourceStructural } from "@/lib/types";
import {
  buildSourceTree, subtreeRoutes, subtreeFindingIds, nodeWorstRank, groupSurfaces,
  parseSink, routeKindTone, repoLabel, type SourceNode,
} from "@/lib/sourceSurface";
import { Kpi, Pill, ViewHead, Panel, PanelHeader, EmptyState, Segmented } from "@/components/ui/primitives";

const SEV_KEYS = ["info", "low", "medium", "high", "critical"] as const;

/* flatten the tree respecting the open set; search force-opens every branch that matches */
function flatten(roots: SourceNode[], open: Set<string>, q: string) {
  const out: { n: SourceNode; depth: number; hasKids: boolean; open: boolean }[] = [];
  const needle = q.trim().toLowerCase();
  const matches = (n: SourceNode): boolean => {
    if (!needle) return true;
    if (n.path.toLowerCase().includes(needle)) return true;
    if (n.routes.some((r) => `${r.route_path ?? ""} ${r.handler ?? ""} ${r.method ?? ""}`.toLowerCase().includes(needle))) return true;
    return n.children.some(matches);
  };
  const rec = (list: SourceNode[], depth: number) => {
    for (const n of list) {
      if (!matches(n)) continue;
      const kids = n.children.filter(matches);
      const isOpen = kids.length > 0 && (!!needle || open.has(n.key));
      out.push({ n, depth, hasKids: kids.length > 0, open: isOpen });
      if (isOpen) rec(kids, depth + 1);
    }
  };
  rec(roots, 0);
  return out;
}

export default function SourceMap() {
  const { activeEngagement: eng, activeId, findings, surfaceLedger, sourceContext, openFinding } = useConsole();

  const byId = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);
  const tree = useMemo(() => buildSourceTree(sourceContext, findings), [sourceContext, findings]);
  const surfaces = useMemo(() => groupSurfaces(surfaceLedger), [surfaceLedger]);
  const routing = Array.isArray(sourceContext?.routing) ? sourceContext!.routing! : [];

  const [show, setShow] = useState<"all" | "unauth" | "issues">("all");
  const [q, setQ] = useState("");
  const [open, setOpen] = useState<Set<string>>(new Set());
  const [sel, setSel] = useState<string | null>(null);

  const rootKeys = tree.roots.map((r) => r.key).join("|");
  useEffect(() => {
    setOpen(new Set(tree.roots.map((r) => r.key)));
    setSel(null);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rootKeys, activeId]);

  const flat = useMemo(() => flatten(tree.roots, open, q), [tree, open, q]);
  const selKey = useMemo(() => (sel && flat.some((x) => x.n.key === sel) ? sel : flat[0]?.n.key ?? null), [sel, flat]);
  const selNode = selKey ? tree.nodes.get(selKey) ?? null : null;

  // routes in the selected subtree, filtered by the show mode + search
  const rows = useMemo(() => {
    if (!selNode) return [] as SourceStructural[];
    const needle = q.trim().toLowerCase();
    return subtreeRoutes(selNode).filter((r) => {
      if (show === "unauth" && (r.kind || "").toLowerCase() !== "unauth-route") return false;
      if (!needle) return true;
      return `${r.route_path ?? ""} ${r.handler ?? ""} ${r.method ?? ""} ${r.file ?? ""}`.toLowerCase().includes(needle);
    }).sort((a, b) => (a.route_path ?? "").localeCompare(b.route_path ?? "") || (a.method ?? "").localeCompare(b.method ?? ""));
  }, [selNode, show, q]);

  const branchFindings = useMemo(() => {
    if (!selNode) return [] as Finding[];
    return Array.from(subtreeFindingIds(selNode)).map((id) => byId.get(id)).filter((f): f is Finding => !!f)
      .sort((a, b) => (SEVERITY[b.severity]?.rank ?? 0) - (SEVERITY[a.severity]?.rank ?? 0));
  }, [selNode, byId]);

  const toggle = (key: string) => setOpen((prev) => { const n = new Set(prev); n.has(key) ? n.delete(key) : n.add(key); return n; });

  if (tree.routeCount === 0 && tree.nodes.size === 0 && surfaces.total === 0) {
    return (
      <>
        <ViewHead crumb="redstrike / source map" title="Source Map" sub={eng.name} />
        <Panel tall>
          <EmptyState
            icon={<FolderTree size={28} />}
            title="No source surface yet"
            hint="The Source Map is built from the white-box feeders' surface_ledger.json and source-audit/source_context.json. Run source-audit for this engagement (or point scripts/console.py at one that has)."
          />
        </Panel>
      </>
    );
  }

  const unauthFilterActive = show === "unauth";

  return (
    <>
      <ViewHead
        crumb="redstrike / source map"
        title="Source Map"
        live={eng.status === "running"}
        sub={`${repoLabel(eng.source?.repo_url) || eng.name}${eng.source?.commit ? ` @ ${eng.source.commit.slice(0, 10)}` : ""} · ${tree.routeCount} routes · ${tree.fileCount} files`}
      />

      {/* KPI strip — the white-box analog of the sitemap's host/URL/finding tiles */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
        <Kpi label="Routes" value={tree.routeCount} icon={<Route size={16} />} note={`across ${tree.fileCount} source files`} />
        <Kpi label="Unauth routes" value={tree.unauthCount} color={tree.unauthCount ? SEVERITY.high.color : undefined} icon={<ShieldOff size={16} />} note="no auth guard in source" />
        <Kpi label="With findings" value={tree.withFindings} color={tree.withFindings ? SEVERITY.high.color : undefined} icon={<Bug size={16} />} note="files linked to a finding" />
        <Kpi label="Attack surface" value={surfaces.total} icon={<ListTree size={16} />} note={`${surfaces.endpoints.length} endpoints · ${surfaces.forms.length} forms · ${surfaces.sinks.length} sinks`} />
      </div>

      {/* filters */}
      <div className="mt-5 flex flex-wrap items-center gap-2.5">
        <Segmented
          value={show}
          onChange={setShow}
          options={[
            { value: "all", label: `All routes (${tree.routeCount})` },
            { value: "unauth", label: `Unauth (${tree.unauthCount})` },
            { value: "issues", label: `With findings (${tree.withFindings})` },
          ]}
        />
        <label className="relative ml-auto block w-full sm:w-64">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Filter files / routes…"
            className="h-9 w-full rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40"
          />
        </label>
      </div>

      {/* main grid: module tree | detail */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-[minmax(0,360px)_minmax(0,1fr)]">
        {/* module / file tree */}
        <Panel tall>
          <PanelHeader title="Modules" sub={`${tree.roots.length} root${tree.roots.length === 1 ? "" : "s"}`} icon={<FolderTree size={15} className="text-brand" />} />
          <div className="scroll-thin max-h-[560px] overflow-y-auto px-2 pb-3">
            {flat.length === 0 ? (
              <div className="py-10 text-center text-sm text-muted">No files match this filter.</div>
            ) : (
              flat.map((it) => (
                <TreeRow
                  key={it.n.key}
                  it={it}
                  rank={nodeWorstRank(it.n, byId)}
                  routeCount={subtreeRoutes(it.n).length}
                  selected={it.n.key === selKey}
                  onSelect={() => setSel(it.n.key)}
                  onToggle={() => toggle(it.n.key)}
                />
              ))
            )}
          </div>
          <div className="flex items-center gap-4 border-t border-line px-3 py-2 text-[11px] text-muted">
            <span className="inline-flex items-center gap-1.5"><span className="h-2 w-2 rounded-full" style={{ background: SEVERITY.critical.color }} /> worst finding on branch</span>
            <span className="inline-flex items-center gap-1.5 opacity-70"><FileCode2 size={11} /> source file</span>
          </div>
        </Panel>

        {/* right column */}
        <div className="flex min-w-0 flex-col gap-4">
          <Panel tall>
            <PanelHeader
              title="Routes"
              sub={selNode ? selNode.path : ""}
              actions={<span className="font-mono text-xs text-faint">{rows.length} route{rows.length === 1 ? "" : "s"}</span>}
            />
            <div className="scroll-thin max-h-[360px] overflow-auto">
              <table className="w-full border-collapse text-sm">
                <thead className="sticky top-0 z-[1] bg-card">
                  <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                    <th className="px-3 py-2.5 font-medium">Method</th>
                    <th className="px-3 py-2.5 font-medium">Route</th>
                    <th className="px-3 py-2.5 font-medium">Kind</th>
                    <th className="px-3 py-2.5 font-medium">Handler</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => <RouteRow key={`${r.id ?? i}`} r={r} />)}
                </tbody>
              </table>
              {rows.length === 0 && <div className="py-10 text-center text-sm text-muted">{unauthFilterActive ? "No unauthenticated routes in this branch." : "No routes in this branch."}</div>}
            </div>
          </Panel>

          {/* findings in the selected branch */}
          <Panel>
            <PanelHeader title="Findings" sub="in selection" icon={<Bug size={15} className="text-muted" />} actions={branchFindings.length ? <span className="font-mono text-xs text-faint">{branchFindings.length}</span> : undefined} />
            <div className="px-[22px] pb-4">
              {branchFindings.length === 0 ? (
                <div className="py-6 text-center text-xs text-muted">No findings linked to this module.</div>
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
                            {verdictOf(f) && <Pill label={verdictMeta(verdictOf(f)).label} color={verdictMeta(verdictOf(f)).color} />}
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

      {/* routed attack surface + routing plan (engagement-level, like the sitemap's sinks/params) */}
      <div className="mt-4 grid grid-cols-1 gap-4 lg:grid-cols-2">
        {(surfaces.endpoints.length > 0 || surfaces.forms.length > 0) && (
          <Panel>
            <PanelHeader title="Routed attack surface" sub={`${surfaces.endpoints.length + surfaces.forms.length} endpoints & forms`} icon={<Route size={15} className="text-muted" />} />
            <div className="scroll-thin max-h-[320px] overflow-y-auto px-[22px] pb-4">
              <SurfaceList title="Endpoints" items={surfaces.endpoints} />
              <SurfaceList title="Forms" items={surfaces.forms} />
            </div>
          </Panel>
        )}
        <div className="flex flex-col gap-4">
          {surfaces.sinks.length > 0 && (
            <Panel>
              <PanelHeader title="Dangerous sinks" sub={`${surfaces.sinks.length} flagged`} icon={<AlertTriangle size={15} className="text-amber-500" />} />
              <div className="scroll-thin max-h-[220px] space-y-1.5 overflow-y-auto px-[22px] pb-4">
                {surfaces.sinks.slice(0, 60).map((s) => {
                  const p = parseSink(s.value);
                  return (
                    <div key={s.id} className="rounded-lg border border-amber-500/25 bg-amber-500/[0.05] px-2.5 py-1.5">
                      <div className="flex items-center justify-between gap-2">
                        <code className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-fg" title={p.expr}>{p.expr}</code>
                        {p.route && <Pill label={p.route} color="#f59e0b" />}
                      </div>
                      {p.file && <div className="mt-0.5 font-mono text-[10.5px] text-faint">{p.file}{p.line != null ? `:${p.line}` : ""}</div>}
                    </div>
                  );
                })}
                {surfaces.sinks.length > 60 && <div className="pt-1 text-center text-[11px] text-faint">+{surfaces.sinks.length - 60} more</div>}
              </div>
            </Panel>
          )}
          {routing.length > 0 && (
            <Panel>
              <PanelHeader title="Routing plan" sub="source-audit → executors" icon={<Workflow size={15} className="text-muted" />} />
              <div className="px-[22px] pb-4">
                <ul className="space-y-1">
                  {routing.map((r, i) => (
                    <li key={i} className="flex items-start gap-2 text-[12.5px] text-muted">
                      <GitBranch size={12} className="mt-0.5 shrink-0 text-muted/70" />
                      <span className="min-w-0 flex-1">{r}</span>
                    </li>
                  ))}
                </ul>
              </div>
            </Panel>
          )}
        </div>
      </div>
    </>
  );
}

/* ── tree row ───────────────────────────────────────────────────────────── */
function TreeRow({
  it, rank, routeCount, selected, onSelect, onToggle,
}: {
  it: { n: SourceNode; depth: number; hasKids: boolean; open: boolean };
  rank: number; routeCount: number; selected: boolean; onSelect: () => void; onToggle: () => void;
}) {
  const { n, depth, hasKids, open } = it;
  const unauth = n.routes.some((r) => (r.kind || "").toLowerCase() === "unauth-route");
  const Icon = n.isFile ? FileCode2 : Folder;
  const sevKey = rank > 0 ? SEV_KEYS[rank - 1] : null;
  return (
    <div
      onClick={onSelect}
      title={n.path}
      className={cx(
        "group flex cursor-pointer items-center gap-1.5 rounded-md py-1.5 pr-2 text-sm outline-none transition",
        selected ? "bg-brand/10 text-fg-strong" : "hover:bg-fg/[0.04]",
      )}
      style={{ paddingLeft: 6 + depth * 14 }}
    >
      <span
        className={cx("grid h-4 w-4 shrink-0 place-items-center text-muted transition", hasKids ? "" : "opacity-0")}
        onClick={(e) => { if (hasKids) { e.stopPropagation(); onToggle(); } }}
      >
        <ChevronRight size={13} className={cx("transition", open && "rotate-90")} />
      </span>
      <Icon size={14} className={cx("shrink-0", n.isFile ? "text-muted" : "text-brand")} />
      <span className="min-w-0 flex-1 truncate font-mono text-[12.5px]">{n.label}</span>
      {unauth && <ShieldOff size={12} className="shrink-0 text-rose-500" aria-label="contains an unauthenticated route" />}
      {sevKey && (
        <span className="h-2 w-2 shrink-0 rounded-full" style={{ background: SEVERITY[sevKey].color }} title={`${SEVERITY[sevKey].label} finding in this branch`} />
      )}
      {routeCount > 0 && <span className="shrink-0 font-mono text-[10px] text-faint">{routeCount}</span>}
    </div>
  );
}

/* ── route row ──────────────────────────────────────────────────────────── */
const METHOD_COLOR: Record<string, string> = { GET: "#22c55e", POST: "#f59e0b", PUT: "#38bdf8", PATCH: "#a855f7", DELETE: "#f43f5e" };
function RouteRow({ r }: { r: SourceStructural }) {
  const tone = routeKindTone(r.kind);
  const mc = r.method ? METHOD_COLOR[r.method.toUpperCase()] ?? "#94a3b8" : "#94a3b8";
  return (
    <tr className="border-t border-line/70 transition hover:bg-fg/[0.03]">
      <td className="px-3 py-2"><span className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[11px] font-medium" style={{ color: mc }}>{r.method || "-"}</span></td>
      <td className="px-3 py-2">
        <span className="block max-w-[320px] truncate font-mono text-[12.5px] text-fg" title={r.route_path}>{r.route_path || "—"}</span>
        {r.file && <span className="block truncate text-[10px] text-faint" title={`${r.file}${r.line != null ? `:${r.line}` : ""}`}>{r.file}{r.line != null ? `:${r.line}` : ""}</span>}
      </td>
      <td className="px-3 py-2"><Pill label={tone.label} color={tone.color} dot /></td>
      <td className="px-3 py-2"><span className="block max-w-[220px] truncate font-mono text-[11.5px] text-muted" title={r.handler}>{r.handler || "—"}</span></td>
    </tr>
  );
}

/* ── surface list (endpoints / forms) ──────────────────────────────────── */
function SurfaceList({ title, items }: { title: string; items: { id: string; value: string; routed_to?: string[] }[] }) {
  const [max, setMax] = useState(30);
  if (!items.length) return null;
  return (
    <div className="mb-3">
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">{title} <span className="text-faint">{items.length}</span></div>
      <ul className="space-y-1">
        {items.slice(0, max).map((s) => (
          <li key={s.id} className="flex items-center justify-between gap-2 rounded-md border border-line bg-card2 px-2.5 py-1.5">
            <code className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-fg" title={s.value}>{s.value}</code>
            <span className="flex shrink-0 flex-wrap gap-1">
              {(s.routed_to ?? []).slice(0, 4).map((t) => <span key={t} className="rounded bg-card px-1.5 py-0.5 font-mono text-[10px] text-muted">{t}</span>)}
            </span>
          </li>
        ))}
      </ul>
      {items.length > max && (
        <button onClick={() => setMax((m) => m + 50)} className="mt-1.5 text-[11px] text-brand hover:underline">Show more ({items.length - max})</button>
      )}
    </div>
  );
}

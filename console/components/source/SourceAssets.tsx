"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Boxes, Package, FileCode2, KeyRound, Crosshair, Search, GitBranch, Layers, FolderGit2,
} from "lucide-react";
import { useConsole } from "@/lib/store";
import { sevMeta } from "@/lib/theme";
import type { Severity, SourceCandidate } from "@/lib/types";
import {
  buildModules, repoLabel, confidenceColor, type SourceModule,
} from "@/lib/sourceSurface";
import { Kpi, Pill, Dot, ViewHead, Panel, PanelHeader, PanelBody, EmptyState, Select } from "@/components/ui/primitives";

const CONF_RANK: Record<string, number> = { high: 3, medium: 2, low: 1 };

export default function SourceAssets() {
  const { activeEngagement: eng, findings, sourceContext, setFindingsQuery } = useConsole();
  const router = useRouter();

  const sc = sourceContext;
  const languages = Array.isArray(sc?.languages) ? sc!.languages! : [];
  // memoized (stable identity) — these feed useMemo deps below, so a fresh [] each render would
  // needlessly recompute the filters.
  const dependencies = useMemo(() => (Array.isArray(sc?.dependencies) ? sc!.dependencies! : []), [sc]);
  const candidates = useMemo(() => (Array.isArray(sc?.candidates) ? sc!.candidates! : []), [sc]);
  const secrets = Array.isArray(sc?.secret_candidates) ? sc!.secret_candidates! : [];
  const filesScanned = sc?.coverage?.files_scanned;

  const modules = useMemo(() => buildModules(sc, findings), [sc, findings]);

  const [depQuery, setDepQuery] = useState("");
  const [leadQuery, setLeadQuery] = useState("");
  const [leadCat, setLeadCat] = useState<string>("all");

  const leadCats = useMemo(() => Array.from(new Set(candidates.map((c) => c.category).filter(Boolean))) as string[], [candidates]);

  const shownDeps = useMemo(() => {
    const q = depQuery.trim().toLowerCase();
    return dependencies
      .filter((d) => !q || `${d.name} ${d.version ?? ""} ${d.manifest ?? ""}`.toLowerCase().includes(q))
      .sort((a, b) => (a.name || "").localeCompare(b.name || ""));
  }, [dependencies, depQuery]);

  const shownLeads = useMemo(() => {
    const q = leadQuery.trim().toLowerCase();
    return candidates
      .filter((c) => leadCat === "all" || c.category === leadCat)
      .filter((c) => !q || `${c.file ?? ""} ${c.pattern ?? ""} ${c.route ?? ""} ${c.category ?? ""}`.toLowerCase().includes(q))
      .sort((a, b) => (CONF_RANK[(b.confidence || "").toLowerCase()] ?? 0) - (CONF_RANK[(a.confidence || "").toLowerCase()] ?? 0) || (a.file || "").localeCompare(b.file || ""));
  }, [candidates, leadQuery, leadCat]);

  const openModuleFindings = (m: SourceModule) => { setFindingsQuery(m.key); router.push("/findings"); };

  if (!sc && modules.length === 0) {
    return (
      <>
        <ViewHead crumb="redstrike / source assets" title="Source Assets" sub={eng.name} />
        <Panel tall>
          <EmptyState
            icon={<FolderGit2 size={28} />}
            title="No source inventory yet"
            hint="Source Assets is built from the white-box feeder's source-audit/source_context.json — the modules, dependencies, languages, sink leads and secret candidates it found. Run source-audit for this engagement."
          />
        </Panel>
      </>
    );
  }

  return (
    <>
      <ViewHead
        crumb="redstrike / source assets"
        title="Source Assets"
        live={eng.status === "running"}
        sub={`${repoLabel(eng.source?.repo_url) || eng.name}${eng.source?.branch ? ` · ${eng.source.branch}` : ""}${eng.source?.commit ? ` @ ${eng.source.commit.slice(0, 10)}` : ""}`}
      />

      {/* KPI tiles — the code-asset inventory, not fetched web assets */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
        <Kpi label="Dependencies" value={dependencies.length} icon={<Package size={16} />} note={depManifests(dependencies)} />
        <Kpi label="Files scanned" value={filesScanned != null ? filesScanned.toLocaleString() : "—"} icon={<FileCode2 size={16} />} note={sc?.coverage?.status ? `scan ${sc.coverage.status}` : "source files"} />
        <Kpi label="Sink leads" value={candidates.length} color={candidates.length ? "#f59e0b" : undefined} icon={<Crosshair size={16} />} note={`${leadCats.length} categor${leadCats.length === 1 ? "y" : "ies"}`} />
        <Kpi label="Secret candidates" value={secrets.length} color={secrets.length ? "#f59e0b" : undefined} icon={<KeyRound size={16} />} note="in-source fixtures/keys" />
      </div>

      {/* languages / stacks */}
      {languages.length > 0 && (
        <Panel className="mt-5">
          <PanelHeader title="Languages & stacks" sub={`${languages.length} detected`} icon={<Layers size={15} className="text-muted" />} />
          <PanelBody>
            <div className="flex flex-wrap gap-1.5">
              {languages.map((l) => <Pill key={l} label={l} color="#60a5fa" />)}
            </div>
          </PanelBody>
        </Panel>
      )}

      {/* modules — the "asset inventory" analog (risk-ranked code modules) */}
      <Panel tall className="mt-5">
        <PanelHeader title="Modules" sub={`${modules.length} · routes · sink leads · findings`} icon={<Boxes size={15} className="text-muted" />} />
        <div className="scroll-thin overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="px-5 py-3 font-medium">Module</th>
                <th className="px-5 py-3 font-medium">Routes</th>
                <th className="px-5 py-3 font-medium">Sink leads</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">Findings</th>
              </tr>
            </thead>
            <tbody>
              {modules.map((m) => <ModuleRow key={m.key} m={m} onFindings={openModuleFindings} />)}
            </tbody>
          </table>
          {modules.length === 0 && <div className="py-12 text-center text-sm text-muted">No modules.</div>}
        </div>
      </Panel>

      {/* sink / vuln leads + dependencies */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-2">
        <Panel tall>
          <div className="flex flex-col gap-3 px-[22px] pb-2 pt-[18px] sm:flex-row sm:items-center sm:justify-between">
            <div className="flex min-w-0 items-center gap-2.5">
              <Crosshair size={15} className="text-amber-500" />
              <span className="text-[15px] font-medium text-fg-strong">Sink / vuln leads</span>
              <span className="font-mono text-xs text-faint">{shownLeads.length} of {candidates.length}</span>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Select value={leadCat} onChange={(e) => setLeadCat(e.target.value)}>
                <option value="all">All categories</option>
                {leadCats.sort().map((c) => <option key={c} value={c}>{c}</option>)}
              </Select>
              <label className="relative block">
                <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  value={leadQuery}
                  onChange={(e) => setLeadQuery(e.target.value)}
                  placeholder="file / pattern"
                  className="h-9 w-full rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40 sm:w-44"
                />
              </label>
            </div>
          </div>
          <div className="scroll-thin max-h-[420px] overflow-auto">
            <table className="w-full border-collapse text-sm">
              <thead className="sticky top-0 z-[1] bg-card">
                <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                  <th className="px-4 py-2.5 font-medium">Location</th>
                  <th className="px-4 py-2.5 font-medium">Category</th>
                  <th className="px-4 py-2.5 font-medium">Conf.</th>
                  <th className="px-4 py-2.5 font-medium">Pattern</th>
                </tr>
              </thead>
              <tbody>
                {shownLeads.map((c, i) => <LeadRow key={c.id ?? i} c={c} />)}
              </tbody>
            </table>
            {shownLeads.length === 0 && <div className="py-12 text-center text-sm text-muted">No sink leads match.</div>}
          </div>
        </Panel>

        <div className="flex flex-col gap-5">
          <Panel tall>
            <div className="flex flex-col gap-3 px-[22px] pb-2 pt-[18px] sm:flex-row sm:items-center sm:justify-between">
              <div className="flex min-w-0 items-center gap-2.5">
                <Package size={15} className="text-muted" />
                <span className="text-[15px] font-medium text-fg-strong">Dependencies</span>
                <span className="font-mono text-xs text-faint">{shownDeps.length} of {dependencies.length}</span>
              </div>
              <label className="relative block">
                <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
                <input
                  value={depQuery}
                  onChange={(e) => setDepQuery(e.target.value)}
                  placeholder="package / version"
                  className="h-9 w-full rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40 sm:w-44"
                />
              </label>
            </div>
            <div className="scroll-thin max-h-[300px] overflow-auto">
              <table className="w-full border-collapse text-sm">
                <thead className="sticky top-0 z-[1] bg-card">
                  <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                    <th className="px-4 py-2.5 font-medium">Package</th>
                    <th className="px-4 py-2.5 font-medium">Version</th>
                    <th className="px-4 py-2.5 font-medium">Manifest</th>
                  </tr>
                </thead>
                <tbody>
                  {shownDeps.map((d, i) => (
                    <tr key={`${d.name}-${i}`} className="border-t border-line/70 transition hover:bg-fg/[0.03]">
                      <td className="px-4 py-2 font-mono text-[12.5px] text-fg">{d.name}</td>
                      <td className="px-4 py-2 font-mono text-xs text-muted">{d.version || "—"}</td>
                      <td className="px-4 py-2 text-xs text-faint">{d.manifest || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {shownDeps.length === 0 && <div className="py-10 text-center text-sm text-muted">No dependencies match.</div>}
            </div>
          </Panel>

          {secrets.length > 0 && (
            <Panel>
              <PanelHeader title="Secret candidates" sub={`${secrets.length} in source`} icon={<KeyRound size={15} className="text-amber-500" />} />
              <div className="scroll-thin max-h-[220px] space-y-1.5 overflow-y-auto px-[22px] pb-4">
                {secrets.map((s, i) => (
                  <div key={i} className="rounded-lg border border-amber-500/25 bg-amber-500/[0.05] px-2.5 py-1.5">
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-[12.5px] font-medium text-fg">{s.type || "secret"}</span>
                      {s.file && <code className="shrink-0 font-mono text-[10.5px] text-faint">{s.file}{s.line != null ? `:${s.line}` : ""}</code>}
                    </div>
                    {s.fingerprint && <div className="mt-0.5 break-all font-mono text-[11px] text-muted">{s.fingerprint}</div>}
                  </div>
                ))}
              </div>
            </Panel>
          )}
        </div>
      </div>

      {/* scope & rules (repo grant) */}
      <Panel className="mt-5">
        <PanelHeader title="Source grant & rules" sub={repoLabel(eng.source?.repo_url) || eng.target} icon={<GitBranch size={15} className="text-muted" />} />
        <PanelBody>
          <div className="space-y-2.5 text-sm">
            <GrantRow label="Repository">{eng.source?.repo_url || <span className="text-muted">—</span>}</GrantRow>
            {eng.source?.branch && <GrantRow label="Branch"><code className="font-mono text-[12.5px]">{eng.source.branch}</code></GrantRow>}
            {eng.source?.commit && <GrantRow label="Commit"><code className="font-mono text-[12.5px]">{eng.source.commit}</code></GrantRow>}
            {eng.source?.local_path && <GrantRow label="Local path"><code className="font-mono text-[12.5px]">{eng.source.local_path}</code></GrantRow>}
          </div>
          <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-3 text-[11px] text-muted">
            {eng.rules.no_dos && <span className="rounded-md bg-card2 px-2 py-1">No DoS</span>}
            {eng.rules.no_destructive && <span className="rounded-md bg-card2 px-2 py-1">No destructive actions</span>}
            {eng.rules.prod_touch_requires_approval && <span className="rounded-md bg-card2 px-2 py-1">Prod touch needs approval</span>}
            {(eng.rules.approval_required_phases || []).map((p) => (
              <span key={p} className="rounded-md bg-amber-500/10 px-2 py-1 font-medium text-amber-500">{p} gated</span>
            ))}
          </div>
        </PanelBody>
      </Panel>
    </>
  );
}

function depManifests(deps: { manifest?: string }[]): string {
  const set = Array.from(new Set(deps.map((d) => d.manifest).filter(Boolean)));
  return set.length ? set.join(" · ") : "declared";
}

/* ── module row ─────────────────────────────────────────────────────────── */
function ModuleRow({ m, onFindings }: { m: SourceModule; onFindings: (m: SourceModule) => void }) {
  const sev = m.worst;
  return (
    <tr className="border-t border-line/70 transition hover:bg-fg/[0.03]">
      <td className="px-5 py-3">
        <div className="flex items-center gap-3">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line text-muted"><Boxes size={15} /></span>
          <span className="truncate font-mono text-[13px] text-fg-strong">{m.key}</span>
        </div>
      </td>
      <td className="px-5 py-3 tabular-nums text-muted">{m.routes || <span className="text-faint">0</span>}</td>
      <td className="px-5 py-3 tabular-nums">{m.leads ? <span className="text-amber-500">{m.leads}</span> : <span className="text-faint">0</span>}</td>
      <td className="px-5 py-3"><RiskBar sev={sev} /></td>
      <td className="px-5 py-3 tabular-nums">
        {m.findings > 0 ? (
          <button onClick={() => onFindings(m)} className="inline-flex items-center gap-1.5 font-medium text-fg underline decoration-fg/30 underline-offset-2 hover:decoration-fg" title={`View findings in ${m.key}`}>
            <Dot color={sev ? sevMeta(sev).color : "rgb(var(--muted))"} /> {m.findings}
          </button>
        ) : <span className="text-faint">0</span>}
      </td>
    </tr>
  );
}

function RiskBar({ sev }: { sev: Severity | null }) {
  const meta = sev ? sevMeta(sev) : null;
  return (
    <div className="flex items-center gap-2" title={meta ? `Worst finding: ${meta.label}` : "No findings"}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-line">
        {meta && <div className="h-full rounded-full" style={{ width: `${(meta.rank / 5) * 100}%`, background: meta.color }} />}
      </div>
      <span className="font-mono text-[11px]" style={meta ? { color: meta.color } : undefined}>
        {meta ? meta.label : <span className="text-faint">none</span>}
      </span>
    </div>
  );
}

/* ── sink-lead row ──────────────────────────────────────────────────────── */
function LeadRow({ c }: { c: SourceCandidate }) {
  const reachable = c.taint?.reachable;
  return (
    <tr className="border-t border-line/70 align-top transition hover:bg-fg/[0.03]">
      <td className="px-4 py-2">
        <span className="block max-w-[260px] truncate font-mono text-[12px] text-fg" title={`${c.file ?? ""}${c.line != null ? `:${c.line}` : ""}`}>{c.file || "—"}{c.line != null ? <span className="text-faint">:{c.line}</span> : null}</span>
        {c.route && <span className="text-[10px] text-faint">→ {c.route}</span>}
      </td>
      <td className="px-4 py-2">{c.category ? <Pill label={c.category} color="#f59e0b" /> : <span className="text-faint">—</span>}</td>
      <td className="px-4 py-2">
        {c.confidence ? <Pill label={c.confidence} color={confidenceColor(c.confidence)} dot /> : <span className="text-faint">—</span>}
        {reachable != null && <div className="mt-0.5 text-[10px]" style={{ color: reachable ? "#f43f5e" : "#64748b" }}>{reachable ? "reachable" : "guarded"}</div>}
      </td>
      <td className="px-4 py-2"><span className="block max-w-[320px] break-words text-[11.5px] text-muted" title={c.pattern}>{c.pattern || "—"}</span></td>
    </tr>
  );
}

/* ── scope grant row ────────────────────────────────────────────────────── */
function GrantRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1 sm:flex-row sm:items-baseline sm:gap-3">
      <span className="w-28 shrink-0 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</span>
      <div className="min-w-0 flex-1 break-all">{children}</div>
    </div>
  );
}

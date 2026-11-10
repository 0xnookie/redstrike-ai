"use client";

import { useEffect, useMemo, useState } from "react";
import {
  NotebookPen, Download, Lightbulb, Radar, FileText, Globe, KeyRound,
  CheckCircle2, XCircle, Ban, ChevronRight, Users, ScrollText,
} from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx, fmtDate } from "@/lib/format";
import { SEVERITY, sevMeta } from "@/lib/theme";
import type { Finding, NotebookLead, NotebookAccount, LeadStatus } from "@/lib/types";
import { buildNotebook, fmtBytes, type LeadTab } from "@/lib/notebook";
import { Kpi, Pill, Dot, ViewHead, Panel, PanelHeader, EmptyState, Segmented } from "@/components/ui/primitives";

/* ── presentation maps ──────────────────────────────────────────────────── */
const LEAD_STATUS: Record<LeadStatus, { label: string; color: string; pulse?: boolean }> = {
  open: { label: "Open", color: "#94a3b8" },
  testing: { label: "Testing", color: "#38bdf8", pulse: true },
  promoted: { label: "Promoted", color: "#22c55e" },
  dead: { label: "Dead end", color: "#64748b" },
};
const SCOPE_TAG: Record<string, { label: string; color: string }> = {
  in: { label: "in scope", color: "#22c55e" },
  out: { label: "out", color: "#64748b" },
  takeover: { label: "takeover", color: "#f43f5e" },
  other: { label: "other", color: "#94a3b8" },
};
const DEF_KIND: Record<string, { label: string; color: string }> = {
  block: { label: "blocked", color: "#22c55e" },
  gap: { label: "gap", color: "#fb923c" },
  detect: { label: "detects", color: "#38bdf8" },
};
const ACCT_STATUS: Record<string, { label: string; color: string }> = {
  active: { label: "active", color: "#22c55e" },
  expired: { label: "expired", color: "#f43f5e" },
  pending: { label: "pending", color: "#facc15" },
  retired: { label: "retired", color: "#64748b" },
};
const SEV_COLOR = (s?: string): string => (s ? SEVERITY[s as keyof typeof SEVERITY]?.color ?? "#94a3b8" : "#94a3b8");
const leadTarget = (l: NotebookLead) => `${l.host ?? ""}${l.path ?? ""}` || "—";

/* ── page ───────────────────────────────────────────────────────────────── */
export default function NotebookPage() {
  const { activeEngagement: eng, activeId, notebook, findings, openFinding } = useConsole();
  const view = useMemo(() => buildNotebook(notebook), [notebook]);
  const byId = useMemo(() => new Map(findings.map((f) => [f.id, f])), [findings]);

  const [leadTab, setLeadTab] = useState<LeadTab>("active");
  const [leadSel, setLeadSel] = useState<string | null>(null);
  const [reconTab, setReconTab] = useState<"subdomains" | "dns" | "network" | "defenses" | "osint">("subdomains");
  useEffect(() => { setLeadSel(null); }, [activeId]);

  // keep the lead tab on something that has rows
  useEffect(() => {
    if (view.groups[leadTab].length === 0) {
      const next = (["active", "promoted", "dead"] as LeadTab[]).find((t) => view.groups[t].length > 0);
      if (next && next !== leadTab) setLeadTab(next);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [activeId, view]);

  const tabLeads = view.groups[leadTab];
  const selLead = useMemo(
    () => tabLeads.find((l) => l.id === leadSel) ?? tabLeads[0] ?? null,
    [tabLeads, leadSel],
  );

  if (view.empty) {
    return (
      <>
        <ViewHead crumb="redstrike / notebook" title="Notebook" sub={eng.name} />
        <Panel tall>
          <EmptyState
            icon={<NotebookPen size={28} />}
            title="Nothing in the notebook yet"
            hint="The notebook holds what an engagement gathers that isn't a finding yet — investigative leads, recon intel, evidence, RoE and test accounts. Run the engagement (scripts/notebook.py --plan builds it from recon), or drop a notebook.json here."
          />
        </Panel>
      </>
    );
  }

  const k = view.kpis;
  return (
    <>
      <ViewHead
        crumb="redstrike / notebook"
        title="Notebook"
        live={eng.status === "running"}
        sub={`${eng.name} · ${k.activeLeads} active lead${k.activeLeads === 1 ? "" : "s"} · ${view.reconCount} recon rows`}
        actions={<button onClick={() => exportMarkdown(view, eng.name, activeId, byId)} className="btn-ghost"><Download size={14} /> Export notes</button>}
      />

      {/* KPI strip */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
        <Kpi label="Active leads" value={k.activeLeads} suffix={k.p1 ? `${k.p1} P1` : undefined}
          color={k.activeLeads ? SEVERITY.high.color : undefined} icon={<Lightbulb size={16} />}
          note={`${k.testing} testing · ${k.promoted} promoted · ${k.dead} dead`} />
        <Kpi label="Hosts discovered" value={k.hosts} suffix={k.hostsInScope ? `${k.hostsInScope} in scope` : undefined}
          icon={<Globe size={16} />} note={k.takeover ? `${k.takeover} takeover risk` : "recon intel"} />
        <Kpi label="Test accounts" value={k.accountsTotal ? `${k.accountsActive}/${k.accountsTotal}` : 0}
          suffix={k.accountsTotal ? "active" : undefined} icon={<KeyRound size={16} />}
          note={`${k.tenants} tenant${k.tenants === 1 ? "" : "s"} · ${k.roles} role${k.roles === 1 ? "" : "s"}`} />
        <Kpi label="Evidence" value={k.evidence} suffix={k.evidenceBytes ? fmtBytes(k.evidenceBytes) : undefined}
          icon={<FileText size={16} />} note="collected" />
      </div>

      <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* LEFT: leads + recon + evidence */}
        <div className="flex min-w-0 flex-col gap-4 lg:col-span-2">
          {/* leads */}
          <Panel>
            <PanelHeader
              title="Leads & hypotheses"
              sub="what we're chasing that isn't a finding yet"
              actions={
                <Segmented
                  value={leadTab}
                  onChange={(v) => { setLeadTab(v); setLeadSel(null); }}
                  options={[
                    { value: "active", label: `Active (${view.groups.active.length})` },
                    { value: "promoted", label: `Promoted (${view.groups.promoted.length})` },
                    { value: "dead", label: `Dead (${view.groups.dead.length})` },
                  ]}
                />
              }
            />
            {tabLeads.length === 0 ? (
              <div className="px-[22px] py-10 text-center text-sm text-muted">No {leadTab} leads.</div>
            ) : (
              <div className="grid grid-cols-1 gap-0 lg:grid-cols-[minmax(0,340px)_minmax(0,1fr)]">
                <ul className="scroll-thin max-h-[460px] overflow-y-auto border-line lg:border-r">
                  {tabLeads.map((l) => (
                    <li key={l.id} className="border-t border-line/70 first:border-t-0">
                      <LeadRow lead={l} selected={selLead?.id === l.id} onSelect={() => setLeadSel(l.id)} finding={l.promoted_to ? byId.get(l.promoted_to) : undefined} />
                    </li>
                  ))}
                </ul>
                <div className="scroll-thin max-h-[460px] overflow-y-auto px-[22px] py-4">
                  {selLead ? <LeadDetail lead={selLead} byId={byId} onFinding={openFinding} /> : (
                    <div className="py-10 text-center text-sm text-muted">Select a lead.</div>
                  )}
                </div>
              </div>
            )}
          </Panel>

          {/* recon intel */}
          <Panel>
            <PanelHeader
              title="Recon intel"
              icon={<Radar size={15} className="text-muted" />}
              actions={
                <Segmented
                  value={reconTab}
                  onChange={setReconTab}
                  options={[
                    { value: "subdomains", label: `Subdomains (${view.recon.subdomains.length})` },
                    { value: "dns", label: `DNS (${view.recon.dns.length})` },
                    { value: "network", label: `Network (${view.recon.network.length})` },
                    { value: "defenses", label: `Defenses (${view.recon.defenses.length})` },
                    { value: "osint", label: `OSINT (${view.recon.osint.length})` },
                  ]}
                />
              }
            />
            <div className="scroll-thin max-h-[360px] overflow-auto">
              <ReconTable tab={reconTab} recon={view.recon} />
            </div>
          </Panel>

          {/* evidence */}
          <Panel>
            <PanelHeader title="Evidence locker" sub={`${view.evidence.length} artefact${view.evidence.length === 1 ? "" : "s"}`} icon={<FileText size={15} className="text-muted" />} />
            <div className="scroll-thin max-h-[300px] overflow-auto">
              {view.evidence.length === 0 ? (
                <div className="px-[22px] py-8 text-center text-xs text-muted">No evidence collected.</div>
              ) : (
                <table className="w-full border-collapse text-sm">
                  <thead className="sticky top-0 z-[1] bg-card">
                    <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                      <th className="px-4 py-2.5 font-medium">Artefact</th>
                      <th className="px-3 py-2.5 font-medium">Finding</th>
                      <th className="px-3 py-2.5 font-medium">SHA-256</th>
                      <th className="px-3 py-2.5 font-medium">Size</th>
                      <th className="px-3 py-2.5 font-medium">Captured</th>
                    </tr>
                  </thead>
                  <tbody>
                    {view.evidence.map((e, i) => (
                      <tr key={e.id ?? i} className="border-t border-line/70">
                        <td className="px-4 py-2">
                          <span className="block truncate font-mono text-[12.5px] text-fg" title={e.name}>{e.name}</span>
                          <span className="text-[10px] text-faint">{[e.kind, e.by].filter(Boolean).join(" · ")}</span>
                        </td>
                        <td className="px-3 py-2">{e.finding_id ? <span className="font-mono text-[11px] text-muted">{e.finding_id}</span> : <span className="text-faint">—</span>}</td>
                        <td className="px-3 py-2"><span className="font-mono text-[11px] text-faint">{e.sha256 ? e.sha256.slice(0, 12) + "…" : "—"}</span></td>
                        <td className="px-3 py-2 font-mono text-[11px] text-muted">{fmtBytes(e.size)}</td>
                        <td className="px-3 py-2 font-mono text-[11px] text-faint">{e.captured_at ? fmtDate(e.captured_at) : "—"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </Panel>
        </div>

        {/* RIGHT: RoE + test accounts */}
        <div className="flex min-w-0 flex-col gap-4">
          <RoePanel view={view} />
          <AccountsPanel accounts={view.accounts} />
        </div>
      </div>
    </>
  );
}

/* ── lead row + detail ──────────────────────────────────────────────────── */
function LeadRow({ lead, selected, onSelect, finding }: { lead: NotebookLead; selected: boolean; onSelect: () => void; finding?: Finding }) {
  const st = LEAD_STATUS[lead.status] ?? LEAD_STATUS.open;
  return (
    <button onClick={onSelect} aria-pressed={selected}
      className={cx("flex w-full items-start gap-2.5 px-[22px] py-3 text-left transition hover:bg-fg/[0.03]", selected && "bg-brand/[0.06]")}>
      <Dot color={finding ? sevMeta(finding.severity).color : st.color} pulse={st.pulse} />
      <span className="min-w-0 flex-1">
        <span className="block truncate text-sm font-medium text-fg">{lead.title}</span>
        <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
          <span className="font-mono">{lead.id}</span>
          <span className="truncate font-mono text-faint">{leadTarget(lead)}</span>
          {lead.owner && <span className="text-faint">· {lead.owner}</span>}
        </span>
      </span>
      {finding ? (
        <Pill label={finding.id} color={sevMeta(finding.severity).color} />
      ) : lead.priority && lead.priority < 3 ? (
        <span className="shrink-0 rounded-full border border-line px-1.5 py-0.5 font-mono text-[10px] text-faint">P{lead.priority}</span>
      ) : null}
    </button>
  );
}

function LeadDetail({ lead, byId, onFinding }: { lead: NotebookLead; byId: Map<string, Finding>; onFinding: (f: Finding) => void }) {
  const st = LEAD_STATUS[lead.status] ?? LEAD_STATUS.open;
  const rel = Array.from(new Set([lead.promoted_to, ...(lead.related ?? [])].filter(Boolean) as string[]))
    .map((id) => ({ id, f: byId.get(id) }));
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-1.5">
        <Pill label={st.label} color={st.color} dot />
        {lead.priority && <span className="rounded-full border border-line px-2 py-0.5 font-mono text-[11px] text-faint">P{lead.priority}</span>}
        {lead.discovered_by && <Pill label={lead.discovered_by} color="#64748b" />}
      </div>
      <div>
        <div className="text-[15px] font-medium text-fg-strong">{lead.title}</div>
        <dl className="mt-2 space-y-1 font-mono text-[11px] text-faint">
          <div className="flex gap-2"><dt className="w-16 shrink-0 uppercase">Target</dt><dd className="min-w-0 break-all text-muted">{leadTarget(lead)}</dd></div>
          {lead.owner && <div className="flex gap-2"><dt className="w-16 shrink-0 uppercase">Owner</dt><dd className="text-muted">{lead.owner}</dd></div>}
          {lead.updated_at && <div className="flex gap-2"><dt className="w-16 shrink-0 uppercase">Updated</dt><dd className="text-muted">{fmtDate(lead.updated_at)}</dd></div>}
        </dl>
      </div>
      {lead.hypothesis && <DSec title="Hypothesis"><p className="text-sm leading-relaxed text-muted">{lead.hypothesis}</p></DSec>}
      {lead.verdict && (
        <DSec title="Verdict">
          <div className="flex items-start gap-2 rounded-lg border border-line bg-card2 px-3 py-2 text-sm text-muted">
            <Ban size={14} className="mt-0.5 shrink-0 text-faint" /><span>{lead.verdict}</span>
          </div>
        </DSec>
      )}
      {lead.observations && lead.observations.length > 0 && <DSec title="Observations"><Bullets items={lead.observations} /></DSec>}
      {lead.next_steps && lead.next_steps.length > 0 && (lead.status === "open" || lead.status === "testing") && <DSec title="Next steps"><Bullets items={lead.next_steps} /></DSec>}
      {rel.length > 0 && (
        <DSec title="Related findings">
          <ul className="space-y-1.5">
            {rel.map(({ id, f }) => f ? (
              <li key={id}>
                <button onClick={() => onFinding(f)} className="flex w-full items-start gap-2 rounded-lg border border-line bg-card2 px-2.5 py-2 text-left transition hover:border-brand/40">
                  <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ background: sevMeta(f.severity).color }} />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium">{f.title}</span>
                    <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
                      <span className="font-mono">{f.id}</span>
                      {id === lead.promoted_to && <span className="text-emerald-500">promoted from this lead</span>}
                    </span>
                  </span>
                </button>
              </li>
            ) : (
              <li key={id} className="rounded-lg border border-dashed border-line px-2.5 py-2 font-mono text-[11px] text-faint">{id} <span className="not-italic">· not in loaded findings</span></li>
            ))}
          </ul>
        </DSec>
      )}
    </div>
  );
}

function DSec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">{title}</div>
      {children}
    </section>
  );
}
function Bullets({ items }: { items: string[] }) {
  return (
    <ul className="space-y-1">
      {items.map((t, i) => (
        <li key={i} className="flex gap-2 text-sm text-muted"><ChevronRight size={13} className="mt-1 shrink-0 text-faint" /><span>{t}</span></li>
      ))}
    </ul>
  );
}

/* ── recon table ────────────────────────────────────────────────────────── */
function Th({ children }: { children: React.ReactNode }) {
  return <th className="px-3 py-2.5 text-left font-medium">{children}</th>;
}
function ReconTable({ tab, recon }: { tab: string; recon: ReturnType<typeof buildNotebook>["recon"] }) {
  const head = (cols: string[]) => (
    <thead className="sticky top-0 z-[1] bg-card">
      <tr className="border-b border-line text-[11px] uppercase tracking-wider text-faint">{cols.map((c) => <Th key={c}>{c}</Th>)}</tr>
    </thead>
  );
  const empty = (msg: string) => <div className="px-[22px] py-8 text-center text-xs text-muted">{msg}</div>;
  const td = "px-3 py-2 align-top";

  if (tab === "subdomains") {
    if (!recon.subdomains.length) return empty("No subdomains recorded.");
    return (
      <table className="w-full border-collapse text-sm">
        {head(["Host", "Found via", "Resolves to", "HTTP", "Scope"])}
        <tbody>
          {recon.subdomains.map((s, i) => {
            const sc = SCOPE_TAG[s.scope ?? "other"] ?? SCOPE_TAG.other;
            return (
              <tr key={i} className="border-t border-line/70">
                <td className={td}><span className="font-mono text-[12.5px] text-fg">{s.host}</span>{s.note && <span className="block text-[10px] text-faint">{s.note}</span>}</td>
                <td className={cx(td, "text-[11px] text-muted")}>{s.source ?? "—"}</td>
                <td className={cx(td, "font-mono text-[11px] text-muted")}>{s.resolves_to ?? "—"}</td>
                <td className={cx(td, "font-mono text-[11px]")}>{s.http_status != null ? s.http_status : <span className="text-faint">—</span>}</td>
                <td className={td}><Pill label={sc.label} color={sc.color} dot /></td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }
  if (tab === "dns") {
    if (!recon.dns.length) return empty("No DNS records recorded.");
    return (
      <table className="w-full border-collapse text-sm">
        {head(["Type", "Name", "Value", "Note"])}
        <tbody>
          {recon.dns.map((d, i) => (
            <tr key={i} className="border-t border-line/70">
              <td className={td}><span className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[11px] font-medium">{d.type}</span></td>
              <td className={cx(td, "font-mono text-[12px] text-fg")}>{d.name}</td>
              <td className={cx(td, "min-w-0 break-all font-mono text-[11px] text-muted")}>{d.value}</td>
              <td className={cx(td, "text-[11px] text-muted")}>{d.note ? <span className="inline-flex items-center gap-1.5">{d.severity && <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEV_COLOR(d.severity) }} />}{d.note}</span> : "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (tab === "network") {
    if (!recon.network.length) return empty("No network ranges recorded.");
    return (
      <table className="w-full border-collapse text-sm">
        {head(["Range", "Owner", "Hosts", "Ports"])}
        <tbody>
          {recon.network.map((n, i) => (
            <tr key={i} className="border-t border-line/70">
              <td className={cx(td, "font-mono text-[12px] text-fg")}>{n.range}</td>
              <td className={cx(td, "text-[11px] text-muted")}>{n.owner ?? "—"}</td>
              <td className={cx(td, "text-[11px] text-muted")}>{n.hosts ?? "—"}</td>
              <td className={td}><span className="flex flex-wrap gap-1">{(n.ports ?? []).map((p) => <code key={p} className="rounded bg-card2 px-1 py-0.5 font-mono text-[10px] text-muted">{p}</code>)}</span></td>
            </tr>
          ))}
        </tbody>
      </table>
    );
  }
  if (tab === "defenses") {
    if (!recon.defenses.length) return empty("No defenses observed.");
    return (
      <table className="w-full border-collapse text-sm">
        {head(["Control", "Observed", "Result"])}
        <tbody>
          {recon.defenses.map((d, i) => {
            const kind = d.kind ? DEF_KIND[d.kind] : undefined;
            return (
              <tr key={i} className="border-t border-line/70">
                <td className={td}><span className="text-[12.5px] text-fg">{d.control}</span>{d.where && <span className="block text-[10px] text-faint">{d.where}</span>}</td>
                <td className={cx(td, "text-[11px] text-muted")}>{d.observed ?? d.effect ?? "—"}</td>
                <td className={td}>{kind ? <Pill label={kind.label} color={kind.color} dot /> : <span className="text-faint">—</span>}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    );
  }
  // osint
  if (!recon.osint.length) return empty("No OSINT recorded.");
  return (
    <table className="w-full border-collapse text-sm">
      {head(["Source", "What we saw", "How it was used"])}
      <tbody>
        {recon.osint.map((o, i) => (
          <tr key={i} className="border-t border-line/70">
            <td className={cx(td, "text-[11px] font-medium text-fg")}>{o.source}</td>
            <td className={cx(td, "text-[12px] text-muted")}>{o.fact}</td>
            <td className={cx(td, "text-[11px] text-muted")}>{o.use ?? "—"}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

/* ── RoE panel ──────────────────────────────────────────────────────────── */
function RoePanel({ view }: { view: ReturnType<typeof buildNotebook> }) {
  const r = view.roe;
  return (
    <Panel>
      <PanelHeader title="Rules of engagement" icon={<ScrollText size={15} className="text-muted" />} />
      <div className="space-y-4 px-[22px] pb-5">
        {!r ? (
          <p className="py-4 text-center text-xs text-muted">No RoE recorded.</p>
        ) : (
          <>
            {(r.window?.from || r.window?.to) && (
              <MetaRow label="Window" value={`${r.window?.from ? fmtDate(r.window.from) : "—"} → ${r.window?.to ? fmtDate(r.window.to) : "open"}`} />
            )}
            {r.approach && <MetaRow label="Approach" value={r.approach} />}
            {r.authorization && <MetaRow label="Authorization" value={r.authorization} />}
            {r.rate_limit != null && <MetaRow label="Rate budget" value={String(r.rate_limit)} />}
            {r.in_scope && r.in_scope.length > 0 && (
              <ChipSec title="In scope">{r.in_scope.map((v) => <code key={v} className="rounded-full border border-emerald-500/30 bg-emerald-500/[0.07] px-2 py-0.5 font-mono text-[11px] text-emerald-500">{v}</code>)}</ChipSec>
            )}
            {r.out_of_scope && r.out_of_scope.length > 0 && (
              <ChipSec title="Out of scope">{r.out_of_scope.map((v) => <code key={v} className="rounded-full border border-line bg-card2 px-2 py-0.5 font-mono text-[11px] text-muted">{v}</code>)}</ChipSec>
            )}
            {r.rules && r.rules.length > 0 && (
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">Rules</div>
                <ul className="space-y-1">
                  {r.rules.map((rule, i) => (
                    <li key={i} className="flex items-start gap-2 text-[13px]">
                      {rule.allowed ? <CheckCircle2 size={14} className="mt-0.5 shrink-0 text-emerald-500" /> : <XCircle size={14} className="mt-0.5 shrink-0 text-rose-500" />}
                      <span className={rule.allowed ? "text-muted" : "text-fg"}>{rule.text}</span>
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {r.egress && r.egress.length > 0 && (
              <ChipSec title="Egress">{r.egress.map((v) => <code key={v} className="rounded bg-card2 px-1.5 py-0.5 font-mono text-[11px] text-muted">{v}</code>)}</ChipSec>
            )}
            {r.contacts && r.contacts.length > 0 && (
              <div>
                <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">Contacts</div>
                <dl className="space-y-1">
                  {r.contacts.map((c, i) => (
                    <div key={i} className="flex gap-3 text-[13px]"><dt className="w-24 shrink-0 text-muted">{c.label}</dt><dd className="min-w-0 break-all text-fg">{c.value}</dd></div>
                  ))}
                </dl>
              </div>
            )}
          </>
        )}
      </div>
    </Panel>
  );
}
function MetaRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-3 text-[13px]">
      <span className="w-24 shrink-0 text-[11px] uppercase tracking-wide text-muted">{label}</span>
      <span className="min-w-0 flex-1 break-words text-fg">{value}</span>
    </div>
  );
}
function ChipSec({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <div className="mb-1.5 text-[11px] font-semibold uppercase tracking-wide text-muted">{title}</div>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

/* ── test accounts ──────────────────────────────────────────────────────── */
function AccountsPanel({ accounts }: { accounts: NotebookAccount[] }) {
  const tenants = Array.from(new Set(accounts.map((a) => a.tenant).filter(Boolean))) as string[];
  const roles = Array.from(new Set(accounts.map((a) => a.role).filter(Boolean))) as string[];
  const showMatrix = tenants.length > 0 && roles.length > 0;
  return (
    <Panel>
      <PanelHeader title="Test accounts" sub={`${accounts.length}`} icon={<Users size={15} className="text-muted" />} />
      <div className="space-y-3 px-[22px] pb-5">
        {accounts.length === 0 ? (
          <p className="py-4 text-center text-xs text-muted">No test accounts recorded.</p>
        ) : (
          <>
            {showMatrix && (
              <div className="overflow-x-auto">
                <table className="border-collapse text-[11px]">
                  <thead>
                    <tr><th className="px-2 py-1 text-left font-medium text-muted">Role</th>{tenants.map((t) => <th key={t} className="px-2 py-1 text-center font-mono font-medium text-muted">{t}</th>)}</tr>
                  </thead>
                  <tbody>
                    {roles.map((role) => (
                      <tr key={role}>
                        <td className="px-2 py-1 text-muted">{role}</td>
                        {tenants.map((t) => {
                          const a = accounts.find((x) => x.role === role && x.tenant === t);
                          const sc = a?.status ? ACCT_STATUS[a.status] : undefined;
                          return <td key={t} className="px-2 py-1 text-center">{a ? <span className="inline-block h-2.5 w-2.5 rounded-full" style={{ background: sc?.color ?? "#64748b" }} title={`${a.id}${sc ? " · " + sc.label : ""}`} /> : <span className="text-faint">·</span>}</td>;
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
            <ul className="space-y-1.5">
              {accounts.map((a) => {
                const sc = a.status ? ACCT_STATUS[a.status] : undefined;
                return (
                  <li key={a.id} className="rounded-lg border border-line bg-card2 px-2.5 py-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className="min-w-0">
                        <span className="block truncate text-sm font-medium text-fg">{a.id}</span>
                        <span className="text-[11px] text-muted">{[a.role, a.auth].filter(Boolean).join(" · ") || "—"}</span>
                      </span>
                      {sc && <Pill label={sc.label} color={sc.color} dot />}
                    </div>
                    {(a.identity || a.used_for || a.used_on) && (
                      <div className="mt-1 space-y-0.5 text-[11px] text-faint">
                        {a.identity && <div className="truncate font-mono">{a.identity}</div>}
                        {a.used_on && <div>used on {a.used_on}</div>}
                        {a.used_for && <div>{a.used_for}</div>}
                      </div>
                    )}
                  </li>
                );
              })}
            </ul>
          </>
        )}
      </div>
    </Panel>
  );
}

/* ── markdown export (port of the dashboard's nbExport section order) ──────── */
function exportMarkdown(view: ReturnType<typeof buildNotebook>, name: string, id: string, byId: Map<string, Finding>) {
  const L: string[] = [];
  L.push(`# ${id} · ${name}: engagement notebook`, "", `Exported ${new Date().toISOString()}`, "");
  const r = view.roe;
  if (r) {
    L.push("## Rules of engagement", "");
    if (r.approach) L.push(`- Approach: ${r.approach}`);
    if (r.window?.from || r.window?.to) L.push(`- Window: ${r.window?.from ?? "—"} → ${r.window?.to ?? "open"}`);
    if (r.authorization) L.push(`- Authorization: ${r.authorization}`);
    if (r.in_scope?.length) L.push(`- In scope: ${r.in_scope.join(", ")}`);
    if (r.out_of_scope?.length) L.push(`- Out of scope: ${r.out_of_scope.join(", ")}`);
    (r.rules ?? []).forEach((rule) => L.push(`- ${rule.allowed ? "✔ Allowed" : "✘ Not allowed"}: ${rule.text}`));
    (r.contacts ?? []).forEach((c) => L.push(`- ${c.label}: ${c.value}`));
    L.push("");
  }
  const leadTable = (rows: NotebookLead[]) => {
    L.push("| ID | Lead | Target | Status | Pri | Owner | Notes |", "|---|---|---|---|---|---|---|");
    rows.forEach((l) => {
      const status = l.status === "promoted" && l.promoted_to ? `promoted → ${l.promoted_to}` : l.status;
      L.push(`| ${l.id} | ${esc(l.title)} | ${esc(leadTarget(l))} | ${status} | ${l.priority ?? ""} | ${l.owner ?? ""} | ${esc(l.verdict || l.hypothesis || "")} |`);
    });
    L.push("");
  };
  (["active", "promoted", "dead"] as LeadTab[]).forEach((t) => {
    if (view.groups[t].length) { L.push(`## Leads: ${t}`, ""); leadTable(view.groups[t]); }
  });
  if (view.recon.subdomains.length) {
    L.push("## Recon: subdomains", "", "| Host | Found via | Resolves to | HTTP | Scope | Note |", "|---|---|---|---|---|---|");
    view.recon.subdomains.forEach((s) => L.push(`| ${s.host} | ${s.source ?? ""} | ${s.resolves_to ?? ""} | ${s.http_status ?? ""} | ${s.scope ?? ""} | ${esc(s.note || "")} |`));
    L.push("");
  }
  if (view.recon.dns.length) {
    L.push("## Recon: DNS & mail", "", "| Type | Name | Value | Note |", "|---|---|---|---|");
    view.recon.dns.forEach((d) => L.push(`| ${d.type} | ${d.name} | ${esc(d.value)} | ${esc(d.note || "")} |`));
    L.push("");
  }
  if (view.recon.network.length) {
    L.push("## Recon: network", "", "| Range | Owner | Hosts | Ports | Note |", "|---|---|---|---|---|");
    view.recon.network.forEach((n) => L.push(`| ${n.range} | ${n.owner ?? ""} | ${esc(n.hosts || "")} | ${(n.ports ?? []).join(" ")} | ${esc(n.note || "")} |`));
    L.push("");
  }
  if (view.recon.defenses.length) {
    L.push("## Defenses observed", "", "| Control | Where | Observed | Result |", "|---|---|---|---|");
    view.recon.defenses.forEach((d) => L.push(`| ${esc(d.control)} | ${d.where ?? ""} | ${esc(d.observed || d.effect || "")} | ${d.kind ?? ""} |`));
    L.push("");
  }
  if (view.recon.osint.length) {
    L.push("## OSINT", "", "| Source | What we saw | How it was used |", "|---|---|---|");
    view.recon.osint.forEach((o) => L.push(`| ${o.source} | ${esc(o.fact)} | ${esc(o.use || "")} |`));
    L.push("");
  }
  if (view.accounts.length) {
    L.push("## Test accounts", "", "| Account | Tenant | Role | Sign-in | Used on | Status |", "|---|---|---|---|---|---|");
    view.accounts.forEach((a) => L.push(`| ${a.id} | ${a.tenant ?? ""} | ${a.role ?? ""} | ${a.auth ?? ""} | ${a.used_on ?? ""} | ${a.status ?? ""} |`));
    L.push("");
  }
  if (view.evidence.length) {
    L.push("## Evidence", "", "| ID | File | Type | Finding | SHA-256 | Size |", "|---|---|---|---|---|---|");
    view.evidence.forEach((e) => L.push(`| ${e.id ?? ""} | ${esc(e.name)} | ${e.kind ?? ""} | ${e.finding_id ?? ""} | ${e.sha256 ?? ""} | ${e.size ?? ""} |`));
    L.push("");
  }
  const blob = new Blob([L.join("\n")], { type: "text/markdown" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `${id || "engagement"}-notebook.md`; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
const esc = (s: string) => (s || "").replace(/\|/g, "\\|").replace(/\n/g, " ");

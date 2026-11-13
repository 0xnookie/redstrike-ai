"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Plus, Search, Star, Check, ArrowUpRight, ExternalLink, Bug, ShieldCheck, Workflow, Network, Gauge } from "lucide-react";
import { useConsole } from "@/lib/store";
import { ENGAGEMENT_STATUS, SEVERITY, sevMeta } from "@/lib/theme";
import { reportable, severityCounts, maxCvss } from "@/lib/stats";
import { cx, fmtDate } from "@/lib/format";
import { cvssScore } from "@/lib/cvss";
import type { Engagement, EngagementStatus, Severity, Finding } from "@/lib/types";
import { Panel, PanelHeader, PanelBody, Kpi, ViewHead, Pill, SeverityBadge } from "@/components/ui/primitives";
import { Progress } from "@/components/ui/charts";
import { LaunchDrawer } from "@/components/control/LaunchDrawer";
import { LiveRun } from "@/components/control/LiveRun";
import { DeleteEngagementButton } from "@/components/control/DeleteEngagementButton";

// status → stepper position; the simple scoping → running → completed lifecycle
const PHASE_STEPS = ["Scoping", "Running", "Completed"];
const STATUS_ORDER: EngagementStatus[] = ["running", "paused", "completed", "scoping"];
const statusStep = (s: EngagementStatus) => (s === "completed" ? 2 : s === "scoping" ? 0 : 1);

type Counts = { findings: number; critical: number; high: number; medium: number; low: number };

export default function EngagementsPage() {
  const { engagements, activeEngagement, activeId, setActiveId, findings, chains, assets, openFinding, reloadEngagements } = useConsole();
  const [status, setStatus] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [launchOpen, setLaunchOpen] = useState(false);

  // live severity roll-up for the ACTIVE engagement; the stored summary for the rest
  const rep = reportable(findings);
  const liveCounts = severityCounts(rep);
  const countsFor = (e: Engagement): Counts =>
    e.id === activeId
      ? { findings: rep.length, critical: liveCounts.critical, high: liveCounts.high, medium: liveCounts.medium, low: liveCounts.low }
      : {
          findings: e.summary?.findings ?? 0,
          critical: e.summary?.critical ?? 0,
          high: e.summary?.high ?? 0,
          medium: e.summary?.medium ?? 0,
          low: e.summary?.low ?? 0,
        };

  const running = engagements.filter((e) => e.status === "running").length;
  const completed = engagements.filter((e) => e.status === "completed").length;

  const tabs = useMemo(() => {
    const present = STATUS_ORDER.filter((s) => engagements.some((e) => e.status === s));
    return [
      { k: "all", label: "All", n: engagements.length },
      ...present.map((s) => ({ k: s, label: ENGAGEMENT_STATUS[s].label, n: engagements.filter((e) => e.status === s).length })),
    ];
  }, [engagements]);

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return engagements.filter((e) => {
      if (status !== "all" && e.status !== status) return false;
      if (q && ![e.name, e.target, e.goal, e.id].join(" ").toLowerCase().includes(q)) return false;
      return true;
    });
  }, [engagements, status, query]);

  return (
    <>
      <ViewHead
        crumb="redstrike / engagements"
        title="Engagements"
        live={running > 0}
        sub={`${engagements.length} authorized · ${running} running · ${completed} completed`}
        actions={
          <button
            onClick={() => setLaunchOpen(true)}
            className="inline-flex h-10 items-center gap-2 rounded-full bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110"
          >
            <Plus size={15} /> New engagement
          </button>
        }
      />

      {/* status filter (segmented) + search */}
      <div className="mt-6 flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap gap-1.5 rounded-full border border-line p-1">
          {tabs.map((t) => (
            <button
              key={t.k}
              onClick={() => setStatus(t.k)}
              aria-pressed={status === t.k}
              className={cx(
                "inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-[13px] transition",
                status === t.k ? "bg-card2 text-fg-strong" : "text-muted hover:text-fg",
              )}
            >
              {t.label}
              <span className="font-mono text-[11px] text-faint">{t.n}</span>
            </button>
          ))}
        </div>
        <div className="relative sm:ml-auto">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search name / target / id…"
            className="h-9 w-full rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40 sm:w-64"
          />
        </div>
      </div>

      <div className="mt-5 grid gap-5 lg:grid-cols-5">
        {/* LEFT — all engagements */}
        <Panel tall className="lg:col-span-2">
          <PanelHeader title="All engagements" sub={`${rows.length} shown`} />
          <ul className="flex-1">
            {rows.length === 0 && (
              <li className="border-t border-line/70 px-5 py-10 text-center text-xs text-muted">No engagements in this state.</li>
            )}
            {rows.map((e) => {
              const st = ENGAGEMENT_STATUS[e.status];
              const c = countsFor(e);
              const isActive = e.id === activeId;
              const prog = e.phase_progress;
              return (
                <li key={e.id} className="border-t border-line/70">
                  <button
                    onClick={() => setActiveId(e.id)}
                    aria-pressed={isActive}
                    className={cx(
                      "flex w-full flex-col gap-1.5 px-5 py-3 text-left transition hover:bg-fg/[0.03]",
                      isActive && "bg-fg/[0.04]",
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="flex min-w-0 items-center gap-1.5">
                        {e.starred && <Star size={12} className="shrink-0 fill-amber-400 text-amber-400" />}
                        <span className="truncate text-sm font-medium text-fg-strong">{e.name}</span>
                      </span>
                      <Pill label={st.label} color={st.color} dot pulse={e.status === "running"} />
                    </div>
                    <div className="truncate font-mono text-[11px] text-faint">{e.id} · {e.target}</div>
                    <div className="mt-0.5 flex items-center justify-between gap-3">
                      {(e.status === "running" || e.status === "paused") && prog ? (
                        <span className="flex min-w-0 flex-1 items-center gap-2" title="coverage categories no longer pending">
                          <Progress value={prog.done} max={prog.total} color={st.color} className="max-w-[120px]" animated={e.status === "running"} />
                          <span className="shrink-0 font-mono text-[11px] text-faint tabular-nums">{prog.done}/{prog.total}</span>
                        </span>
                      ) : (
                        <span className="font-mono text-[11px] text-faint">{c.findings} findings</span>
                      )}
                      <SevDots counts={c} />
                    </div>
                  </button>
                </li>
              );
            })}
          </ul>
        </Panel>

        {/* RIGHT — selected engagement detail */}
        <EngagementDetail
          e={activeEngagement}
          rep={rep}
          totalFindings={findings.length}
          chains={chains.length}
          inScopeAssets={assets.filter((a) => a.scope === "in").length}
          openFinding={openFinding}
          onLaunch={() => setLaunchOpen(true)}
        />
      </div>

      <LaunchDrawer open={launchOpen} onClose={() => { setLaunchOpen(false); void reloadEngagements(); }} />
    </>
  );
}

/* ---------- right-hand detail ---------- */
function EngagementDetail({
  e, rep, totalFindings, chains, inScopeAssets, openFinding, onLaunch,
}: {
  e: Engagement;
  rep: Finding[];
  totalFindings: number;
  chains: number;
  inScopeAssets: number;
  openFinding: (f: Finding) => void;
  onLaunch: () => void;
}) {
  const st = ENGAGEMENT_STATUS[e.status];
  const cur = statusStep(e.status);
  const maxScore = maxCvss(rep);
  const cvssColor =
    maxScore >= 9 ? SEVERITY.critical.color
    : maxScore >= 7 ? SEVERITY.high.color
    : maxScore >= 4 ? SEVERITY.medium.color
    : maxScore > 0 ? SEVERITY.low.color
    : undefined;

  const scope = [
    ...e.in_scope.domains.map((v) => ({ v, t: "domain" })),
    ...e.in_scope.cidrs.map((v) => ({ v, t: "cidr" })),
    ...e.in_scope.urls.map((v) => ({ v, t: "url" })),
  ];

  const recent = useMemo(
    () => [...rep].sort((a, b) => (cvssScore(b.cvss_vector) ?? 0) - (cvssScore(a.cvss_vector) ?? 0)).slice(0, 6),
    [rep],
  );

  const last = PHASE_STEPS.length - 1;
  const paused = e.status === "paused";
  // a run that ended short of a full pass: say what's missing instead of a bare "Completed"
  const prog = e.phase_progress;
  const pending = prog ? prog.total - prog.done : 0;
  const runNote =
    e.status === "completed" && e.run?.log && (pending > 0 || !e.report)
      ? [
          "Run ended",
          prog ? `${prog.done}/${prog.total} categories covered${pending ? ` · ${pending} never ran` : ""}` : null,
          e.report ? null : "no consolidated report yet",
        ].filter(Boolean).join(" · ")
      : paused
        ? `Run stopped${prog ? ` at ${prog.done}/${prog.total} categories` : ""} — resume to continue`
        : null;

  return (
    <Panel tall className="lg:col-span-3">
      <PanelHeader
        title={e.name}
        sub={e.id}
        actions={
          <>
            <Pill label={st.label} color={st.color} dot />
            <DeleteEngagementButton id={e.id} />
            <Link
              href="/"
              className="inline-flex h-8 items-center gap-1.5 rounded-full border border-line px-3 text-xs font-medium text-fg transition hover:border-fg/30"
            >
              <ExternalLink size={13} /> Open overview
            </Link>
          </>
        }
      />
      <PanelBody>
        {e.goal && <p className="text-sm leading-relaxed text-muted">{e.goal}</p>}
        <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-faint">
          <span>target {e.target}</span>
          <span>window {fmtDate(e.window.start)} → {fmtDate(e.window.end)}</span>
        </div>
        {e.authorized_by && (
          <div className="mt-1 truncate font-mono text-[11px] text-faint" title={e.authorized_by}>
            authorized {e.authorized_by}
          </div>
        )}

        {/* live run steering */}
        <div className="mt-5">
          <BlockTitle>Live run</BlockTitle>
          <LiveRun engagementId={e.id} onLaunch={onLaunch} />
        </div>

        {/* scope */}
        <div className="mt-5">
          <BlockTitle>Scope</BlockTitle>
          {scope.length === 0 ? (
            <p className="text-xs text-muted">No in-scope assets defined.</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {scope.map((s) => (
                <span
                  key={`${s.t}:${s.v}`}
                  title={s.t}
                  className="inline-flex items-center gap-1.5 rounded-full border border-line bg-card2 px-2.5 py-1 font-mono text-[11px] text-muted"
                >
                  <span className="h-1.5 w-1.5 rounded-full bg-fg/40" />
                  {s.v}
                </span>
              ))}
            </div>
          )}
        </div>

        {/* progress stepper */}
        <div className="mt-5">
          <BlockTitle>Progress</BlockTitle>
          <div className="flex items-center">
            {PHASE_STEPS.map((p, i) => {
              const done = e.status === "completed" || i < cur;
              const current = !done && i === cur;
              return (
                <div key={p} className={cx("flex items-center gap-2", i < last && "flex-1")}>
                  <span
                    className={cx(
                      "grid h-6 w-6 shrink-0 place-items-center rounded-full border text-[11px] font-medium tabular-nums",
                      done ? "border-emerald-500 bg-emerald-500 text-[#00110a]"
                      : current ? "border-fg/60 text-fg-strong shadow-[0_0_0_4px_rgb(var(--fg)/0.06)]"
                      : "border-line text-faint",
                    )}
                  >
                    {/* done → check; current → a blinking "you are here" dot; ahead → its number */}
                    {done ? <Check size={12} strokeWidth={3} />
                      : current && paused ? <span className="h-[7px] w-[7px] rounded-sm bg-amber-500" />
                      : current ? <span className="pulse-dot h-[7px] w-[7px] rounded-full bg-fg-strong" />
                      : i + 1}
                  </span>
                  <span className={cx("whitespace-nowrap text-xs", done || current ? "text-fg" : "text-faint", paused && current && "text-amber-500")}>
                    {paused && current ? "Paused" : p}
                  </span>
                  {i < last && <span className={cx("mx-1 h-px flex-1", done ? "bg-emerald-500" : "bg-line")} />}
                </div>
              );
            })}
          </div>
          {runNote && (
            <p className={cx("mt-2.5 font-mono text-[11.5px]", paused ? "text-amber-500" : "text-faint")}>{runNote}</p>
          )}
        </div>

        {/* metrics */}
        <div className="mt-5">
          <BlockTitle>Metrics</BlockTitle>
          <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3">
            <Kpi label="Findings" value={totalFindings} icon={<Bug size={16} />} note="total" />
            <Kpi label="Reportable" value={rep.length} icon={<ShieldCheck size={16} />} note="accepted + limited" />
            <Kpi label="Chains" value={chains} icon={<Workflow size={16} />} note="validated paths" />
            <Kpi label="In-scope assets" value={inScopeAssets} icon={<Network size={16} />} note="discovered" />
            <Kpi label="Max CVSS" value={maxScore ? maxScore.toFixed(1) : "—"} color={cvssColor} icon={<Gauge size={16} />} note="highest base" />
          </div>
        </div>

        {/* recent findings */}
        <div className="mt-5">
          <BlockTitle
            right={
              <Link href="/findings" className="inline-flex items-center gap-1 text-[11px] text-faint transition hover:text-fg">
                View all <ArrowUpRight size={12} />
              </Link>
            }
          >
            Recent findings
          </BlockTitle>
          <ul className="-mx-[22px]">
            {recent.length === 0 && (
              <li className="border-t border-line/70 px-[22px] py-8 text-center text-xs text-muted">
                No reportable findings for this engagement yet.
              </li>
            )}
            {recent.map((f) => {
              const score = cvssScore(f.cvss_vector);
              return (
                <li key={f.id} className="border-t border-line/70">
                  <button
                    onClick={() => openFinding(f)}
                    className="flex w-full items-center gap-3 px-[22px] py-2.5 text-left transition hover:bg-fg/[0.03]"
                  >
                    <SeverityBadge severity={f.severity} dot />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm text-fg">{f.title}</div>
                      <div className="truncate font-mono text-[11px] text-faint">{f.id} · {f.asset}</div>
                    </div>
                    {score !== null && (
                      <span className="shrink-0 tabular-nums text-sm" style={{ color: sevMeta(f.severity).color }}>
                        {score.toFixed(1)}
                      </span>
                    )}
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      </PanelBody>
    </Panel>
  );
}

/* ---------- small helpers (local to this view) ---------- */
function BlockTitle({ children, right }: { children: React.ReactNode; right?: React.ReactNode }) {
  return (
    <div className="mb-2 flex items-center justify-between">
      <span className="text-[11px] font-medium uppercase tracking-wide text-faint">{children}</span>
      {right}
    </div>
  );
}

function SevDots({ counts }: { counts: Counts }) {
  const items: [Severity, number][] = [
    ["critical", counts.critical],
    ["high", counts.high],
    ["medium", counts.medium],
    ["low", counts.low],
  ];
  const active = items.filter(([, n]) => n > 0);
  if (active.length === 0) return <span className="font-mono text-[11px] text-faint">—</span>;
  return (
    <span className="flex shrink-0 items-center gap-1.5">
      {active.map(([k, n]) => (
        <span key={k} className="inline-flex items-center gap-0.5">
          <span className="h-1.5 w-1.5 rounded-full" style={{ background: SEVERITY[k].color }} />
          <span className="font-mono text-[10px] tabular-nums text-faint">{n}</span>
        </span>
      ))}
    </span>
  );
}

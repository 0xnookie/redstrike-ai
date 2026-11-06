"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Plus, ArrowUpRight, Bug, Workflow, Network, ShieldCheck } from "lucide-react";
import { useConsole } from "@/lib/store";
import { reportable, severityCounts, severityChartData, groupByCategory, groupByAsset, verificationStats, maxCvss } from "@/lib/stats";
import { SEVERITY, VERDICT, sevMeta } from "@/lib/theme";
import { fmtDate, relTime, cx } from "@/lib/format";
import { cvssScore } from "@/lib/cvss";
import { Panel, PanelHeader, PanelBody, Kpi, ViewHead, LivePill, SeverityBadge, Pill } from "@/components/ui/primitives";
import { AreaLine, Donut, Legend, Progress } from "@/components/ui/charts";
import { CyberFeed } from "@/components/dashboard/CyberFeed";

export default function DashboardPage() {
  const { activeEngagement, findings, chains, assets, activity, cveFeed, cveLive, openFinding } = useConsole();
  const [range, setRange] = useState<"all" | "window">("all");

  const rep = reportable(findings);
  const counts = severityCounts(rep);
  const sevData = severityChartData(rep);
  const vstats = verificationStats(findings.filter((f) => !f.composite));
  const inScopeAssets = assets.filter((a) => a.scope === "in").length;
  const running = activeEngagement.status === "running";

  // cumulative reportable findings by reviewer-acceptance date
  const cumulative = useMemo(() => {
    const byDay = new Map<string, number>();
    rep.forEach((f) => {
      const d = fmtDate(f.review?.reviewed_at);
      if (d === "—") return;
      byDay.set(d, (byDay.get(d) || 0) + 1);
    });
    let run = 0;
    return [...byDay.entries()].sort().map(([, v]) => (run += v));
  }, [rep]);

  const topIssues = useMemo(
    () => [...rep].sort((a, b) => (cvssScore(b.cvss_vector) ?? 0) - (cvssScore(a.cvss_vector) ?? 0)).slice(0, 6),
    [rep],
  );
  const exposed = useMemo(() => groupByAsset(rep).slice(0, 6), [rep]);
  const cats = useMemo(() => groupByCategory(rep).slice(0, 5), [rep]);
  const feed = useMemo(() => activity.slice().reverse().slice(0, 7), [activity]);

  return (
    <>
      <ViewHead
        crumb={`redstrike / ${activeEngagement.target || "security"}`}
        title="Security Overview"
        live={running}
        sub={`${activeEngagement.name} · ${rep.length} reportable · ${chains.length} chains · ${inScopeAssets} assets in scope`}
        actions={
          <>
            <Segmentedish value={range} onChange={setRange} />
            <Link
              href="/engagements"
              className="inline-flex h-10 items-center gap-2 rounded-full bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110"
            >
              <Plus size={15} /> New engagement
            </Link>
          </>
        }
      />

      {/* KPI tiles */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-5">
        <Kpi label="Reportable" value={rep.length} icon={<Bug size={16} />} note={`${vstats.accepted} accepted · ${vstats.blocked} limited`} />
        <Kpi label="Critical" value={counts.critical} color={SEVERITY.critical.color} note="open" />
        <Kpi label="High" value={counts.high} color={SEVERITY.high.color} note="open" />
        <Kpi label="Attack chains" value={chains.length} icon={<Workflow size={16} />} note="validated paths" />
        <Kpi label="Assets" value={inScopeAssets} icon={<Network size={16} />} note="in scope" />
      </div>

      {/* findings-over-time · severity · review outcomes */}
      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <Panel>
          <PanelHeader title="Findings over time" sub="cumulative, reportable" />
          <PanelBody>
            <div className="mb-2 flex items-end justify-between gap-3">
              <div className="flex items-baseline gap-2">
                <span className="text-[30px] font-semibold leading-none tracking-tight tabular-nums text-fg-strong">{rep.length}</span>
                <span className="text-[13px] text-faint">reportable</span>
              </div>
              <span className="font-mono text-xs text-faint">max CVSS {maxCvss(rep).toFixed(1)}</span>
            </div>
            <div className="text-fg">
              <AreaLine points={cumulative} />
            </div>
          </PanelBody>
        </Panel>

        <Panel>
          <PanelHeader title="Severity breakdown" sub="open" />
          <PanelBody>
            <div className="flex items-center gap-4">
              <Donut data={sevData} centerSub="findings" />
              <Legend data={sevData} />
            </div>
          </PanelBody>
        </Panel>

        <Panel>
          <PanelHeader title="Two-altitude review" icon={<ShieldCheck size={15} className="text-brand" />} />
          <PanelBody>
            <p className="mb-3 text-xs text-muted">Every finding re-judged by an independent reviewer agent.</p>
            <div className="space-y-3 text-sm">
              <OutcomeRow label="Accepted" value={vstats.accepted} total={vstats.total} color={VERDICT.accepted.color} />
              <OutcomeRow label="Demonstration-limited" value={vstats.blocked} total={vstats.total} color={VERDICT.blocked.color} />
              <OutcomeRow label="Rejected" value={vstats.rejected} total={vstats.total} color={VERDICT.rejected.color} />
            </div>
            <div className="mt-3 flex items-center justify-between border-t border-line pt-3 text-xs text-muted">
              <span>{vstats.total} findings judged</span>
              <span className="tabular-nums">{cats.length} categories</span>
            </div>
          </PanelBody>
        </Panel>
      </div>

      {/* top issues · most exposed assets · agent activity */}
      <div className="mt-5 grid gap-5 lg:grid-cols-3">
        <Panel>
          <PanelHeader
            title="Top issues"
            actions={<Link href="/findings" className="inline-flex items-center gap-1 text-[13px] text-faint transition hover:text-fg">View all <ArrowUpRight size={13} /></Link>}
          />
          <ul className="flex-1">
            {topIssues.length === 0 && <li className="px-5 py-10 text-center text-xs text-muted">No reportable findings yet.</li>}
            {topIssues.map((f) => {
              const score = cvssScore(f.cvss_vector);
              return (
                <li key={f.id} className="border-t border-line/70">
                  <button onClick={() => openFinding(f)} className="flex w-full items-center gap-3 px-5 py-3 text-left transition hover:bg-fg/[0.03]">
                    <SeverityBadge severity={f.severity} dot />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm text-fg">{f.title}</div>
                      <div className="truncate font-mono text-[11px] text-faint">{f.id} · {f.asset}</div>
                    </div>
                    {score !== null && <span className="shrink-0 tabular-nums text-sm" style={{ color: sevMeta(f.severity).color }}>{score.toFixed(1)}</span>}
                  </button>
                </li>
              );
            })}
          </ul>
        </Panel>

        <Panel>
          <PanelHeader
            title="Most exposed assets"
            actions={<Link href="/assets" className="inline-flex items-center gap-1 text-[13px] text-faint transition hover:text-fg">View all <ArrowUpRight size={13} /></Link>}
          />
          <ul className="flex-1">
            {exposed.length === 0 && <li className="px-5 py-10 text-center text-xs text-muted">No asset findings yet.</li>}
            {exposed.map((a) => {
              const max = exposed[0]?.value || 1;
              return (
                <li key={a.label} className="flex items-center gap-3 border-t border-line/70 px-5 py-3">
                  <Network size={15} className="shrink-0 text-muted" />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-fg">{a.label}</div>
                    <div className="mt-1.5 h-1 w-full overflow-hidden rounded-full bg-line">
                      <div className="h-full rounded-full bg-fg/60" style={{ width: `${(a.value / max) * 100}%` }} />
                    </div>
                  </div>
                  <span className="shrink-0 font-mono text-xs text-muted">{a.value}</span>
                </li>
              );
            })}
          </ul>
        </Panel>

        <Panel>
          <PanelHeader title="Agent activity" actions={running ? <LivePill /> : undefined} />
          <ul className="flex-1">
            {feed.length === 0 && <li className="px-5 py-10 text-center text-xs text-muted">No activity yet.</li>}
            {feed.map((e) => (
              <li key={e.id} className="border-t border-line/70 px-5 py-2.5">
                <div className="flex items-center justify-between gap-2">
                  <span className="inline-flex items-center gap-2 font-mono text-[12.5px] text-fg">
                    <span className="h-1.5 w-1.5 rounded-full" style={{ background: e.severity ? sevMeta(e.severity).color : "rgb(var(--muted))" }} />
                    {e.kind}
                  </span>
                  <time className="font-mono text-[11px] text-faint">{relTime(e.ts)}</time>
                </div>
                <div className="mt-0.5 flex items-center justify-between gap-2">
                  <span className="truncate text-[13px] text-muted">{e.title}</span>
                  {e.verdict ? (
                    <Pill label={VERDICT[e.verdict].label} color={VERDICT[e.verdict].color} />
                  ) : (
                    <span className="shrink-0 font-mono text-[11px] text-faint">{e.actor}</span>
                  )}
                </div>
              </li>
            ))}
          </ul>
        </Panel>
      </div>

      {/* what's new in cyber — global CVE feed + spinning globe */}
      <div className="mt-5">
        <CyberFeed feed={cveFeed} live={cveLive} />
      </div>
    </>
  );
}

function OutcomeRow({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="flex items-center gap-2 text-xs"><span className="h-2 w-2 rounded-full" style={{ background: color }} />{label}</span>
        <span className="tabular-nums text-xs text-muted">{value}</span>
      </div>
      <Progress value={value} max={Math.max(1, total)} color={color} />
    </div>
  );
}

/* pill-style range toggle matching the strix segmented control */
function Segmentedish({ value, onChange }: { value: "all" | "window"; onChange: (v: "all" | "window") => void }) {
  const opts: { v: "all" | "window"; label: string }[] = [
    { v: "all", label: "All time" },
    { v: "window", label: "Window" },
  ];
  return (
    <div className="inline-flex rounded-full border border-line bg-card2 p-0.5">
      {opts.map((o) => (
        <button
          key={o.v}
          onClick={() => onChange(o.v)}
          className={cx(
            "rounded-full px-3 py-1.5 text-[13px] font-medium transition",
            value === o.v ? "bg-brand text-brand-fg" : "text-muted hover:text-fg",
          )}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

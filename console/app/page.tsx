"use client";

import { useState } from "react";
import Link from "next/link";
import { Plus, ArrowUpRight, Bug, ShieldCheck, Workflow, Network } from "lucide-react";
import { useConsole } from "@/lib/store";
import { reportable, severityCounts, severityChartData, groupByCategory, groupByAsset, verificationStats, maxCvss } from "@/lib/stats";
import { SEVERITY, SEVERITY_ORDER, VERDICT, sevMeta } from "@/lib/theme";
import { fmtDate, relTime, cx, verdictOf } from "@/lib/format";
import { cvssScore } from "@/lib/cvss";
import type { Finding } from "@/lib/types";
import { Card, Kpi, PageHeader, SeverityBadge, Pill, Segmented } from "@/components/ui/primitives";
import { Donut, Legend, HBars, StackedBars, Progress } from "@/components/ui/charts";
import { FindingDrawer } from "@/components/findings/FindingDrawer";
import { ACTIVITY_ICON } from "@/components/activityIcons";

export default function DashboardPage() {
  const { activeEngagement, findings, chains, assets, activity } = useConsole();
  const [selected, setSelected] = useState<Finding | null>(null);
  const [range, setRange] = useState<"all" | "window">("all");

  const rep = reportable(findings);
  const counts = severityCounts(rep);
  const sevData = severityChartData(rep);
  const vstats = verificationStats(findings.filter((f) => !f.composite));
  const inScopeAssets = assets.filter((a) => a.scope === "in").length;

  // findings-over-time (by reviewer date), stacked by severity
  const byDay = new Map<string, Record<string, number>>();
  rep.forEach((f) => {
    const d = fmtDate(f.review?.reviewed_at) ;
    if (d === "—") return;
    const row = byDay.get(d) || {};
    row[f.severity] = (row[f.severity] || 0) + 1;
    byDay.set(d, row);
  });
  const timeGroups = [...byDay.entries()].sort().map(([label, values]) => ({ label: label.slice(5), values }));

  return (
    <>
      <PageHeader
        title="Dashboard"
        subtitle={`${activeEngagement.name} · global status`}
        actions={
          <Link href="/engagements" className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-line bg-card px-3 text-sm font-medium transition hover:border-brand/40">
            <Plus size={15} /> New engagement
          </Link>
        }
      />

      {/* KPI row */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7">
        <Kpi label="Reportable" value={rep.length} sub={`${vstats.accepted} accepted · ${vstats.blocked} limited`} icon={<Bug size={15} />} />
        {SEVERITY_ORDER.map((k) => (
          <Kpi key={k} label={SEVERITY[k].label} value={counts[k]} color={SEVERITY[k].color} />
        ))}
        <Kpi label="Chains" value={chains.length} icon={<Workflow size={15} />} />
      </div>

      {/* over-time + donut */}
      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card className="p-4 lg:col-span-2">
          <div className="mb-3 flex items-center justify-between">
            <div>
              <h2 className="text-sm font-semibold">Findings over time</h2>
              <p className="text-xs text-muted">By reviewer acceptance date, stacked by severity</p>
            </div>
            <Segmented
              value={range}
              onChange={setRange}
              options={[{ value: "all", label: "All" }, { value: "window", label: "Window" }]}
            />
          </div>
          {timeGroups.length ? (
            <StackedBars
              groups={timeGroups}
              series={SEVERITY_ORDER.map((k) => ({ key: k, color: SEVERITY[k].color, label: SEVERITY[k].label }))}
            />
          ) : (
            <p className="py-10 text-center text-xs text-muted">No dated findings yet.</p>
          )}
        </Card>

        <Card className="p-4">
          <h2 className="text-sm font-semibold">Severity</h2>
          <p className="mb-3 text-xs text-muted">Reportable findings</p>
          <div className="flex items-center gap-4">
            <Donut data={sevData} centerSub="findings" />
            <Legend data={sevData} />
          </div>
          <div className="mt-3 flex items-center justify-between border-t border-line pt-3 text-xs">
            <span className="text-muted">Highest CVSS</span>
            <span className="font-semibold tabular-nums" style={{ color: sevMeta(rep[0]?.severity).color }}>{maxCvss(rep).toFixed(1)}</span>
          </div>
        </Card>
      </div>

      {/* activity + recent findings */}
      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-2">
        <Card className="p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold">Activity</h2>
            <Link href="/activity" className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg">
              View all <ArrowUpRight size={13} />
            </Link>
          </div>
          <ul className="space-y-3">
            {activity.slice().reverse().slice(0, 6).map((e) => {
              const I = ACTIVITY_ICON[e.kind];
              return (
                <li key={e.id} className="flex gap-3">
                  <div className="mt-0.5 grid h-7 w-7 shrink-0 place-items-center rounded-lg border border-line bg-card2 text-muted">
                    <I size={14} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center justify-between gap-2">
                      <span className="truncate text-sm">{e.title}</span>
                      <span className="shrink-0 text-[11px] text-muted">{relTime(e.ts)}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-[11px] text-muted">{e.actor}</span>
                      {e.severity && <SeverityBadge severity={e.severity} dot={false} />}
                      {e.verdict && <Pill label={VERDICT[e.verdict].label} color={VERDICT[e.verdict].color} />}
                    </div>
                  </div>
                </li>
              );
            })}
          </ul>
        </Card>

        <Card className="p-4">
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-sm font-semibold">Top findings</h2>
            <Link href="/findings" className="inline-flex items-center gap-1 text-xs text-muted hover:text-fg">
              View all <ArrowUpRight size={13} />
            </Link>
          </div>
          <ul className="divide-y divide-line">
            {[...rep].sort((a, b) => (cvssScore(b.cvss_vector) ?? 0) - (cvssScore(a.cvss_vector) ?? 0)).slice(0, 6).map((f) => {
              const score = cvssScore(f.cvss_vector);
              return (
                <li key={f.id}>
                  <button onClick={() => setSelected(f)} className="flex w-full items-center gap-3 py-2.5 text-left transition hover:opacity-80">
                    <SeverityBadge severity={f.severity} dot />
                    <div className="min-w-0 flex-1">
                      <div className="truncate text-sm font-medium">{f.title}</div>
                      <div className="truncate font-mono text-[11px] text-muted">{f.id} · {f.asset}</div>
                    </div>
                    {score !== null && <span className="shrink-0 tabular-nums text-sm" style={{ color: sevMeta(f.severity).color }}>{score.toFixed(1)}</span>}
                  </button>
                </li>
              );
            })}
          </ul>
        </Card>
      </div>

      {/* breakdowns */}
      <div className="mt-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold">By category</h2>
          <HBars data={groupByCategory(rep)} />
        </Card>
        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold">By asset</h2>
          <HBars data={groupByAsset(rep)} />
        </Card>
        <Card className="p-4">
          <div className="mb-1 flex items-center gap-2">
            <ShieldCheck size={15} className="text-brand" />
            <h2 className="text-sm font-semibold">Two-altitude review</h2>
          </div>
          <p className="mb-3 text-xs text-muted">Every finding re-judged by an independent reviewer agent.</p>
          <div className="space-y-3 text-sm">
            <Row label="Accepted" value={vstats.accepted} total={vstats.total} color={VERDICT.accepted.color} />
            <Row label="Demonstration-limited" value={vstats.blocked} total={vstats.total} color={VERDICT.blocked.color} />
            <Row label="Rejected" value={vstats.rejected} total={vstats.total} color={VERDICT.rejected.color} />
          </div>
          <div className="mt-3 flex items-center justify-between border-t border-line pt-3 text-xs text-muted">
            <span className="flex items-center gap-1.5"><Network size={13} /> {inScopeAssets} assets in scope</span>
            <span>{vstats.total} findings judged</span>
          </div>
        </Card>
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </>
  );
}

function Row({ label, value, total, color }: { label: string; value: number; total: number; color: string }) {
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

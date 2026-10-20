"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Star, ArrowRight, Search, Plus } from "lucide-react";
import { useConsole } from "@/lib/store";
import { ENGAGEMENT_STATUS, SEVERITY } from "@/lib/theme";
import { reportable, severityCounts } from "@/lib/stats";
import { cx, fmtDate } from "@/lib/format";
import type { Engagement } from "@/lib/types";
import { Card, PageHeader, Pill, Dot } from "@/components/ui/primitives";
import { Progress } from "@/components/ui/charts";

export default function EngagementsPage() {
  const { engagements, findings, activeId, setActiveId } = useConsole();
  const router = useRouter();
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState<string>("all");

  // live counts for the active engagement; summary for the rest
  const liveCounts = severityCounts(reportable(findings));
  const countsFor = (e: Engagement) =>
    e.id === activeId
      ? { findings: reportable(findings).length, ...liveCounts, chains: 0 }
      : e.summary ?? { findings: 0, critical: 0, high: 0, medium: 0, low: 0, chains: 0 };

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    return engagements.filter((e) => {
      if (status !== "all" && e.status !== status) return false;
      if (q && ![e.name, e.target, e.goal, e.id].join(" ").toLowerCase().includes(q)) return false;
      return true;
    });
  }, [engagements, query, status]);

  const enter = (id: string) => { setActiveId(id); router.push("/"); };

  return (
    <>
      <PageHeader
        title="Engagements"
        subtitle="Authorized assessments — select one to make it the active context across the console."
        actions={
          <button className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-3 text-sm font-medium text-brand-fg transition hover:brightness-110">
            <Plus size={15} /> New engagement
          </button>
        }
      />

      <Card>
        <div className="flex flex-col gap-2 border-b border-line p-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="relative">
            <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search name / target / id…"
              className="h-9 w-full rounded-lg border border-line bg-card2 pl-8 pr-2 text-sm outline-none placeholder:text-muted focus:border-brand/50 sm:w-72" />
          </div>
          <div className="flex items-center gap-1.5">
            {["all", "running", "paused", "completed"].map((s) => (
              <button key={s} onClick={() => setStatus(s)}
                className={cx("rounded-full border px-2.5 py-1 text-xs font-medium capitalize transition", status === s ? "border-brand/60 bg-brand/10 text-brand" : "border-line text-muted hover:text-fg")}>
                {s}
              </button>
            ))}
          </div>
        </div>

        <div className="scroll-thin overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-4 py-2.5 font-medium">Engagement</th>
                <th className="px-4 py-2.5 font-medium">Target</th>
                <th className="px-4 py-2.5 font-medium">Status</th>
                <th className="px-4 py-2.5 font-medium">Phase</th>
                <th className="px-4 py-2.5 font-medium">Findings</th>
                <th className="px-4 py-2.5 font-medium">Window</th>
                <th className="px-4 py-2.5" />
              </tr>
            </thead>
            <tbody>
              {rows.map((e) => {
                const st = ENGAGEMENT_STATUS[e.status];
                const c = countsFor(e);
                const prog = e.phase_progress;
                const isActive = e.id === activeId;
                return (
                  <tr key={e.id} className={cx("border-t border-line transition hover:bg-card2", isActive && "bg-brand/[0.04]")}>
                    <td className="px-4 py-3">
                      <div className="flex items-start gap-2">
                        {e.starred && <Star size={13} className="mt-1 shrink-0 fill-amber-400 text-amber-400" />}
                        <div>
                          <div className="flex items-center gap-2 font-medium leading-tight">
                            {e.name}
                            {isActive && <Pill label="Active" color="#3b82f6" dot />}
                          </div>
                          <div className="mt-0.5 line-clamp-1 max-w-md text-xs text-muted">{e.goal}</div>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3"><code className="text-xs text-muted">{e.target}</code></td>
                    <td className="px-4 py-3"><span className="inline-flex items-center gap-1.5 text-xs"><Dot color={st.color} pulse={e.status === "running"} />{st.label}</span></td>
                    <td className="px-4 py-3">
                      {prog ? (
                        <div className="w-24">
                          <div className="mb-1 text-[11px] text-muted">{prog.done}/{prog.total}</div>
                          <Progress value={prog.done} max={prog.total} color={st.color} />
                        </div>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="tabular-nums">{c.findings}</span>
                        <span className="flex items-center gap-1">
                          {c.critical > 0 && <Dot color={SEVERITY.critical.color} />}
                          {c.high > 0 && <Dot color={SEVERITY.high.color} />}
                          {c.medium > 0 && <Dot color={SEVERITY.medium.color} />}
                        </span>
                      </div>
                    </td>
                    <td className="whitespace-nowrap px-4 py-3 text-xs text-muted">{fmtDate(e.window.start)} → {fmtDate(e.window.end)}</td>
                    <td className="px-4 py-3 text-right">
                      <button onClick={() => enter(e.id)} className="inline-flex items-center gap-1 rounded-lg border border-line bg-card px-2.5 py-1.5 text-xs font-medium transition hover:border-brand/40">
                        Enter <ArrowRight size={13} />
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

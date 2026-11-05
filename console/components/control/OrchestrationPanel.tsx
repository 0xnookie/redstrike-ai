"use client";

import { useMemo } from "react";
import { Workflow, CircleCheck, Circle, Loader2, Bot, ShieldCheck, Layers, Cpu } from "lucide-react";
import { useControl } from "./ControlProvider";
import type { RunTask, RunAgent, CoverageCategory } from "@/lib/control";
import { Card } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

function StepIcon({ status }: { status: RunTask["status"] }) {
  if (status === "done") return <CircleCheck size={14} className="mt-0.5 shrink-0 text-emerald-400" />;
  if (status === "running") return <Loader2 size={14} className="mt-0.5 shrink-0 animate-spin text-cyan-400" />;
  if (status === "error") return <Circle size={14} className="mt-0.5 shrink-0 text-amber-400" />;
  return <Circle size={14} className="mt-0.5 shrink-0 text-muted/40" />;
}

const ROLE_ICON = { reviewer: ShieldCheck, orchestrator: Cpu, executor: Bot, skill: Bot } as const;

function AgentRow({ a, live }: { a: RunAgent; live?: boolean }) {
  const Icon = ROLE_ICON[a.role] ?? Bot;
  return (
    <li className="flex items-start gap-2 text-xs">
      {live ? (
        <Loader2 size={13} className="mt-0.5 shrink-0 animate-spin text-cyan-400" />
      ) : (
        <CircleCheck size={13} className="mt-0.5 shrink-0 text-emerald-400/60" />
      )}
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-1.5">
          <Icon size={12} className={cx("shrink-0", a.role === "reviewer" ? "text-brand" : "text-muted")} />
          <span className={cx("truncate font-mono", live ? "text-fg" : "text-muted")}>{a.name}</span>
          {a.role === "reviewer" && <span className="shrink-0 rounded bg-brand/10 px-1 py-0.5 text-[9px] font-medium text-brand">reviewer</span>}
          {a.role === "orchestrator" && <span className="shrink-0 rounded bg-cyan-500/10 px-1 py-0.5 text-[9px] font-medium text-cyan-400">orchestrator</span>}
        </div>
        {a.task && live && <div className="mt-0.5 truncate text-[11px] text-muted">{a.task}</div>}
      </div>
    </li>
  );
}

const COV_TONE: Record<string, string> = {
  ran: "text-emerald-400", done: "text-emerald-400", attempted: "text-emerald-300", complete: "text-emerald-400", completed: "text-emerald-400",
  running: "text-cyan-400", in_progress: "text-cyan-400",
  skipped: "text-muted", pending: "text-muted/60",
};
const isRan = (s?: string) => /ran|done|attempt|complete/i.test(s || "");

export function OrchestrationPanel() {
  const { orch, coverage, running, activeId } = useControl();
  const { tasks, agents } = orch;

  // current step: the first one running, else (while live) the latest not-done
  const currentIdx = useMemo(() => {
    const r = tasks.findIndex((t) => t.status === "running");
    if (r >= 0) return r;
    if (running) for (let i = tasks.length - 1; i >= 0; i--) if (tasks[i].status !== "done") return i;
    return -1;
  }, [tasks, running]);

  const activeAgents = agents.filter((a) => a.status === "running");
  const doneAgents = agents.filter((a) => a.status !== "running");

  const phases = useMemo(() => {
    const m = new Map<string, CoverageCategory[]>();
    for (const c of coverage?.categories ?? []) {
      const p = c.phase || "other";
      if (!m.has(p)) m.set(p, []);
      m.get(p)!.push(c);
    }
    return [...m.entries()];
  }, [coverage]);

  const covCount = coverage?.categories?.length ?? 0;
  const idle = !running && tasks.length === 0 && agents.length === 0 && covCount === 0;

  return (
    <Card className="p-4">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-semibold">
          <Workflow size={15} className="text-brand" /> Orchestration
          {running && (
            <span className="inline-flex items-center gap-1 text-[11px] font-medium text-emerald-400">
              <Loader2 size={11} className="animate-spin" /> running
            </span>
          )}
        </h2>
        {activeId && <span className="font-mono text-[11px] text-muted">{activeId}</span>}
      </div>

      {idle ? (
        <p className="py-6 text-center text-xs text-muted">
          No active run. Launch an engagement from the panel on the left — steps, agents, and coverage track here live.
        </p>
      ) : (
        <div className="grid grid-cols-1 gap-x-6 gap-y-4 lg:grid-cols-2">
          {/* STEPS */}
          <section className="min-w-0">
            <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted">Steps</h3>
            {tasks.length === 0 ? (
              <p className="text-xs text-muted">Waiting for the engine to plan steps…</p>
            ) : (
              <ol className="space-y-1">
                {tasks.map((t, i) => {
                  const shown = i === currentIdx && t.status === "pending" ? "running" : t.status;
                  return (
                    <li
                      key={t.uid}
                      className={cx(
                        "flex items-start gap-2 rounded-lg px-2 py-1.5 text-xs",
                        i === currentIdx && "bg-cyan-500/[0.07] ring-1 ring-cyan-500/20",
                      )}
                    >
                      <StepIcon status={shown} />
                      <div className="min-w-0 flex-1">
                        <div className={cx("truncate", shown === "done" ? "text-muted" : "text-fg")}>{t.subject}</div>
                        {i === currentIdx && t.activeForm && (
                          <div className="truncate text-[11px] text-cyan-400">{t.activeForm}…</div>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ol>
            )}
          </section>

          {/* AGENTS */}
          <section className="min-w-0">
            <h3 className="mb-2 text-[11px] font-medium uppercase tracking-wide text-muted">Agents at work</h3>
            {agents.length === 0 ? (
              <p className="text-xs text-muted">No sub-agents spawned yet — the orchestrator plans first.</p>
            ) : (
              <ul className="space-y-1.5">
                {activeAgents.map((a) => (
                  <AgentRow key={a.uid} a={a} live />
                ))}
                {doneAgents.slice(-5).map((a) => (
                  <AgentRow key={a.uid} a={a} />
                ))}
              </ul>
            )}
          </section>

          {/* COVERAGE */}
          {phases.length > 0 && (
            <section className="min-w-0 lg:col-span-2">
              <h3 className="mb-2 flex items-center gap-1.5 text-[11px] font-medium uppercase tracking-wide text-muted">
                <Layers size={12} /> Coverage
              </h3>
              <div className="space-y-1.5">
                {phases.map(([phase, cats]) => {
                  const ran = cats.filter((c) => isRan(c.status)).length;
                  return (
                    <div key={phase} className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <span className="w-16 shrink-0 text-[11px] font-medium capitalize text-fg">{phase}</span>
                      <span className="shrink-0 text-[10px] tabular-nums text-muted">
                        {ran}/{cats.length}
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {cats.map((c) => (
                          <span
                            key={c.id}
                            title={c.reason || c.status || c.name}
                            className={cx(
                              "rounded bg-card2 px-1.5 py-0.5 text-[10px] font-medium",
                              COV_TONE[(c.status || "").toLowerCase()] ?? "text-muted/60",
                            )}
                          >
                            {c.id}
                            {(c.findings_count ?? 0) > 0 ? ` ·${c.findings_count}` : ""}
                          </span>
                        ))}
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
          )}
        </div>
      )}
    </Card>
  );
}

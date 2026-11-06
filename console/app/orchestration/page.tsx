"use client";

import { useMemo } from "react";
import Link from "next/link";
import { Cpu, Bot, ShieldCheck, Terminal, Rocket, Bot as BotIcon, ListChecks, Activity, Layers } from "lucide-react";
import { useControl } from "@/components/control/ControlProvider";
import type { RunAgent, RunTask, RunEvent } from "@/lib/control";
import { Panel, PanelHeader, PanelBody, Kpi, ViewHead, LivePill } from "@/components/ui/primitives";
import { cx } from "@/lib/format";

/* ---------------------------------------------------------------- graph ---- */
const ROLE_ICON: Record<RunAgent["role"], typeof Bot> = {
  orchestrator: Cpu, reviewer: ShieldCheck, executor: Bot, skill: Bot,
};
const STATUS_COLOR: Record<RunAgent["status"], string> = {
  running: "#22c55e", done: "rgb(var(--faint))", error: "#f59e0b",
};

const VB_W = 1000, VB_H = 620, CX = 500, CY = 300, RX = 384, RY = 224, NODE_R = 34, MAX_NODES = 16;

function OrchestrationGraph({ agents, running }: { agents: RunAgent[]; running: boolean }) {
  // the orchestrator is always Redstrike (the center) — never a peripheral node.
  // show running agents first, then the most recent others, capped for layout.
  const nodes = useMemo(() => {
    const peripheral = agents.filter((a) => a.role !== "orchestrator");
    const live = peripheral.filter((a) => a.status === "running");
    const rest = peripheral.filter((a) => a.status !== "running").slice(-(MAX_NODES - Math.min(live.length, MAX_NODES)));
    return [...live, ...rest].slice(0, MAX_NODES);
  }, [agents]);

  const n = nodes.length;
  return (
    <div className="px-2 pb-1">
      <svg viewBox={`0 0 ${VB_W} ${VB_H}`} className="block w-full" style={{ maxHeight: 620 }} role="img" aria-label="Orchestrator dispatching to agents">
        {/* edges */}
        {nodes.map((a, i) => {
          const ang = -Math.PI / 2 + ((i + 0.5) * 2 * Math.PI) / Math.max(1, n);
          const ax = CX + RX * Math.cos(ang), ay = CY + RY * Math.sin(ang);
          const dx = ax - CX, dy = ay - CY, d = Math.hypot(dx, dy) || 1, ux = dx / d, uy = dy / d;
          const sx = CX + ux * 58, sy = CY + uy * 58, ex = ax - ux * (NODE_R + 6), ey = ay - uy * (NODE_R + 6);
          const mx = (sx + ex) / 2 - uy * 24, my = (sy + ey) / 2 + ux * 24;
          const hot = a.status === "running";
          return (
            <path
              key={`e-${a.uid}`}
              d={`M${sx.toFixed(1)},${sy.toFixed(1)} Q${mx.toFixed(1)},${my.toFixed(1)} ${ex.toFixed(1)},${ey.toFixed(1)}`}
              fill="none"
              className={cx(hot && "edge-flow")}
              stroke={hot ? "rgb(214 235 253 / 0.5)" : "rgb(214 235 253 / 0.12)"}
              strokeWidth={1.3}
            />
          );
        })}

        {/* agent nodes */}
        {nodes.map((a, i) => {
          const ang = -Math.PI / 2 + ((i + 0.5) * 2 * Math.PI) / Math.max(1, n);
          const ax = CX + RX * Math.cos(ang), ay = CY + RY * Math.sin(ang);
          const up = ay < CY - 10;
          const Icon = ROLE_ICON[a.role] ?? Bot;
          const col = STATUS_COLOR[a.status];
          const C = 2 * Math.PI * NODE_R;
          return (
            <g key={a.uid}>
              <circle cx={ax} cy={ay} r={NODE_R} fill="none" className="stroke-line" strokeWidth={2.5} />
              {/* progress ring: full for done, rotating arc for running, partial for error */}
              <circle
                cx={ax} cy={ay} r={NODE_R} fill="none" stroke={col} strokeWidth={2.5} strokeLinecap="round"
                strokeDasharray={a.status === "running" ? `${(C * 0.28).toFixed(1)} ${C.toFixed(1)}` : a.status === "error" ? `${(C * 0.5).toFixed(1)} ${C.toFixed(1)}` : C.toFixed(1)}
                transform={`rotate(-90 ${ax} ${ay})`}
                className={a.status === "running" ? "ring-indeterminate" : undefined}
                opacity={a.status === "done" ? 0.5 : 1}
              />
              <circle cx={ax} cy={ay} r={NODE_R - 7} style={{ fill: "rgb(var(--card))", stroke: "rgb(255 255 255 / 0.12)" }} strokeWidth={1} />
              <g style={{ color: a.status === "running" ? "rgb(var(--fg-strong))" : a.role === "reviewer" ? "rgb(var(--brand))" : "rgb(var(--faint))" }}>
                <Icon x={ax - 10} y={ay - 10} width={20} height={20} color="currentColor" />
              </g>
              <circle cx={ax + 24} cy={ay - 24} r={4.5} fill={col} style={{ stroke: "rgb(var(--bg))" }} strokeWidth={2.5} />
              <text x={ax} y={up ? ay - 52 : ay + 50} textAnchor="middle" className="fill-fg" style={{ font: "500 12px var(--font-mono)" }}>
                {a.name.length > 20 ? a.name.slice(0, 19) + "…" : a.name}
              </text>
              <text x={ax} y={up ? ay - 38 : ay + 64} textAnchor="middle" className="fill-faint" style={{ font: "11px var(--font-sans)" }}>
                {a.role}
              </text>
            </g>
          );
        })}

        {/* center orchestrator core */}
        <g>
          {running && <circle cx={CX} cy={CY} r={54} className="orch-pulse" />}
          {/* ambient ring: dashed always, but only SPINS while a run is live */}
          <circle cx={CX} cy={CY} r={68} className={cx("orch-ring", running && "orch-spin")} />
          <circle cx={CX} cy={CY} r={54} style={{ fill: "rgb(var(--card))", stroke: "rgb(214 235 253 / 0.45)" }} strokeWidth={1.4} />
          <g style={{ color: "rgb(var(--fg-strong))" }}>
            <Cpu x={CX - 13} y={CY - 28} width={26} height={26} color="currentColor" />
          </g>
          <text x={CX} y={CY + 10} textAnchor="middle" className="fill-fg" style={{ font: "600 13px var(--font-sans)" }}>Redstrike</text>
          <text x={CX} y={CY + 26} textAnchor="middle" className="fill-faint" style={{ font: "11px var(--font-mono)" }}>orchestrator</text>
        </g>
      </svg>

      <div className="flex flex-wrap gap-4 px-5 pb-1 pt-1 text-[12.5px] text-muted">
        <LegendDot color="#22c55e" label="Running" />
        <LegendDot color="rgb(var(--faint))" label="Returned" />
        <LegendDot color="#f59e0b" label="Error" />
        <span className="inline-flex items-center gap-2"><span className="h-px w-5" style={{ background: "rgb(214 235 253 / 0.5)" }} /> Active dispatch</span>
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return <span className="inline-flex items-center gap-2"><span className="h-2 w-2 rounded-full" style={{ background: color }} />{label}</span>;
}

/* --------------------------------------------------------------- queue ---- */
const TASK_TONE: Record<RunTask["status"], string> = {
  pending: "text-muted", running: "text-emerald-500", done: "text-faint", error: "text-amber-500",
};

function TaskQueue({ tasks }: { tasks: RunTask[] }) {
  const queued = tasks.filter((t) => t.status === "pending" || t.status === "running").slice(0, 8);
  return (
    <ul className="flex-1">
      {queued.length === 0 && <li className="px-5 py-8 text-center text-xs text-muted">Queue is empty.</li>}
      {queued.map((t, i) => (
        <li key={t.uid} className="flex items-center gap-3 border-t border-line/70 px-5 py-2.5">
          <span className={cx("shrink-0 rounded-md border border-line px-1.5 font-mono text-[11px] leading-5", t.status === "running" ? "text-emerald-500" : "text-faint")}>
            {t.status === "running" ? "run" : i + 1}
          </span>
          <div className="min-w-0 flex-1">
            <div className="truncate text-[13px] text-fg">{t.subject}</div>
            {t.activeForm && <div className="truncate font-mono text-[11px] text-faint">{t.activeForm}…</div>}
          </div>
          <span className={cx("shrink-0 font-mono text-[11px]", TASK_TONE[t.status])}>{t.status}</span>
        </li>
      ))}
    </ul>
  );
}

/* ----------------------------------------------------------- dispatch log -- */
const TONE_COLOR: Record<string, string> = {
  ok: "#22c55e", warn: "#f59e0b", cyan: "#38bdf8", muted: "rgb(var(--faint))",
};
function DispatchLog({ events, running }: { events: RunEvent[]; running: boolean }) {
  const rows = events.slice(-22).reverse();
  return (
    <div className="scroll-thin max-h-[330px] overflow-auto px-5 pb-4 font-mono text-[12px] leading-[1.75]">
      {rows.length === 0 && <p className="py-8 text-center text-xs text-muted">No dispatch events yet.</p>}
      {running && rows.length > 0 && (
        <div className="grid grid-cols-[52px_14px_1fr] gap-2">
          <span className="text-faint/60" />
          <span />
          <span className="text-muted"><span className="caret" /></span>
        </div>
      )}
      {rows.map((e) => (
        <div key={e.key} className="grid grid-cols-[52px_14px_1fr] gap-2" title={`${e.text}${e.detail ? " · " + e.detail : ""}`}>
          <span className="text-faint/70">{e.kind}</span>
          <span style={{ color: TONE_COLOR[e.tone ?? "muted"] }}>{e.kind === "result" ? "✓" : e.kind === "error" ? "!" : "›"}</span>
          <span className="truncate text-muted">
            <span className="text-fg">{e.text}</span>
            {e.detail ? ` · ${e.detail}` : ""}
          </span>
        </div>
      ))}
    </div>
  );
}

/* -------------------------------------------------------------- the view --- */
function OrchestrationInner() {
  const { conn, orch, coverage, running, activeId, events } = useControl();
  const { agents, tasks } = orch;

  const agentsRunning = agents.filter((a) => a.status === "running").length;
  const queueDepth = tasks.filter((t) => t.status === "pending" || t.status === "running").length;
  const stepsDone = tasks.filter((t) => t.status === "done").length;
  const covRan = (coverage?.categories ?? []).filter((c) => /ran|done|attempt|complete/i.test(c.status || "")).length;
  const covTotal = coverage?.categories?.length ?? 0;

  const offline = conn !== "ready";
  // everything here is folded from the real run stream — nothing is simulated.
  const idle = !offline && !running && agents.length === 0 && tasks.length === 0;

  return (
    <>
      <ViewHead
        crumb="redstrike / orchestration"
        title="Orchestration"
        live={running}
        sub={offline ? "Control plane not connected" : running ? `Live task routing · ${activeId}` : `${activeId || "no engagement"} · idle`}
        actions={
          <Link href="/engagements" className="inline-flex h-10 items-center gap-2 rounded-full border border-line px-4 text-sm font-medium text-fg transition hover:border-fg/30">
            <Rocket size={15} /> Launch a run
          </Link>
        }
      />

      {offline ? (
        <Panel className="mx-auto max-w-2xl">
          <PanelBody className="flex flex-col items-center gap-3 py-14 text-center">
            <span className="tile-ico text-muted"><Terminal size={18} /></span>
            <p className="text-sm font-medium text-fg">The control plane isn’t connected</p>
            <p className="max-w-md text-xs text-muted">
              Live orchestration streams from a running engagement. Connect the opt-in control plane in Settings → Agent
              runtimes, then launch a run from Engagements — steps, agents and dispatch events animate here in real time.
            </p>
            <Link href="/engagements" className="mt-1 inline-flex h-9 items-center gap-2 rounded-full bg-brand px-4 text-sm font-medium text-brand-fg transition hover:brightness-110">
              <Rocket size={15} /> Launch a run
            </Link>
          </PanelBody>
        </Panel>
      ) : (
        <>
          <div className="grid grid-cols-2 gap-3.5 lg:grid-cols-4">
            <Kpi label="Agents working" value={agentsRunning} suffix={`/ ${agents.length}`} color="#22c55e" icon={<BotIcon size={16} />} note={`${agents.length - agentsRunning} returned`} />
            <Kpi label="Queue depth" value={queueDepth} suffix="tasks" icon={<ListChecks size={16} />} note={`${tasks.length} steps total`} />
            <Kpi label="Steps done" value={stepsDone} suffix={`/ ${tasks.length}`} icon={<Activity size={16} />} note="this run" />
            <Kpi label="Coverage" value={covTotal ? `${covRan}/${covTotal}` : "—"} icon={<Layers size={16} />} note="categories exercised" />
          </div>

          <div className="mt-5 grid gap-5 xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]">
            <Panel tall>
              <PanelHeader title="Task flow" sub="orchestrator → agents" actions={running ? <LivePill /> : undefined} />
              {idle ? (
                <PanelBody className="flex flex-col items-center gap-2 py-16 text-center">
                  <p className="text-sm font-medium text-fg">No active run</p>
                  <p className="max-w-sm text-xs text-muted">Launch or resume an engagement from Engagements — the orchestrator and its agents animate here as they work.</p>
                </PanelBody>
              ) : (
                <OrchestrationGraph agents={agents} running={running} />
              )}
            </Panel>

            <div className="flex flex-col gap-5">
              <Panel>
                <PanelHeader title="Task queue" sub={`${queueDepth} pending`} />
                <TaskQueue tasks={tasks} />
              </Panel>
              <Panel tall>
                <PanelHeader title="Dispatch log" sub="newest first" />
                <DispatchLog events={events} running={running} />
              </Panel>
            </div>
          </div>
        </>
      )}
    </>
  );
}

export default function OrchestrationPage() {
  return <OrchestrationInner />;
}

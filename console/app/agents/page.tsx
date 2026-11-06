"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Bot, ShieldCheck, Lock, Share2, Cpu } from "lucide-react";
import { useConsole } from "@/lib/store";
import { useControl } from "@/components/control/ControlProvider";
import type { RunAgent } from "@/lib/control";
import { AGENT_STATUS } from "@/lib/theme";
import { cx } from "@/lib/format";
import type { Agent, AgentTier } from "@/lib/types";
import { Kpi, ViewHead, Pill, Dot, Panel, PanelHeader, LivePill } from "@/components/ui/primitives";

const TIER_COLOR: Record<AgentTier, string> = {
  "Tier-1": "#f43f5e", "Tier-2": "#fb923c", "Tier-3": "#a78bfa", Feeder: "#38bdf8", Capability: "#22c55e",
};
const ROLE_ICON: Record<RunAgent["role"], typeof Bot> = {
  orchestrator: Cpu, reviewer: ShieldCheck, executor: Bot, skill: Bot,
};

export default function AgentsPage() {
  const { agents } = useConsole();
  const { conn, orch } = useControl();
  const [family, setFamily] = useState<string>("all");

  // live "working now" from the control-plane run stream (real time).
  // the orchestrator (redstrike) is the hub, not a worker — it's the centre of the
  // orchestration graph, so it's excluded from the agent roster/count here.
  const liveWorkers = orch.agents.filter((a) => a.status === "running" && a.role !== "orchestrator");
  const runningCount = liveWorkers.length;
  const runningSlugs = useMemo(() => new Set(liveWorkers.map((a) => a.name)), [orch.agents]); // eslint-disable-line react-hooks/exhaustive-deps

  const families = useMemo(() => Array.from(new Set(agents.map((a) => a.family))), [agents]);
  const shown = agents.filter((a) => family === "all" || a.family === family);

  const produced = agents.reduce((a, x) => a + x.produced, 0);
  const accepted = agents.reduce((a, x) => a + x.accepted, 0);

  const tabs = [{ k: "all", label: "All", n: agents.length }, ...families.map((f) => ({ k: f, label: f, n: agents.filter((a) => a.family === f).length }))];

  return (
    <>
      <ViewHead
        crumb="redstrike / agents"
        title="Agents"
        live={runningCount > 0}
        sub={`${agents.length} executors + reviewers · ${runningCount} working now · ${families.length} families`}
        actions={
          <Link href="/orchestration" className="inline-flex h-10 items-center gap-2 rounded-full border border-line px-4 text-sm font-medium text-fg transition hover:border-fg/30">
            <Share2 size={15} /> Live orchestration
          </Link>
        }
      />

      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-5">
        <Kpi label="Agents" value={agents.length} icon={<Bot size={16} />} note="in the pool" />
        <Kpi label="Families" value={families.length} note="skill groups" />
        <Kpi label="Working now" value={runningCount} color="#22c55e" icon={<Cpu size={16} />} note="live" />
        <Kpi label="Findings produced" value={produced} note="all time" />
        <Kpi label="Accepted" value={accepted} color="#22c55e" note="after review" />
      </div>

      {/* live working-now strip — real time from the control plane */}
      <div className="mt-5">
        <Panel>
          <PanelHeader title="Working now" sub="live from the control plane" actions={runningCount > 0 ? <LivePill /> : undefined} />
          <div className="panel-body">
            {conn !== "ready" ? (
              <p className="rounded-lg border border-dashed border-line bg-card2 px-3 py-2.5 text-xs text-muted">
                Connect the control plane in{" "}
                <Link href="/settings" className="text-fg underline-offset-2 hover:underline">Settings → Agent runtimes</Link>{" "}
                to see which agents are working in real time.
              </p>
            ) : liveWorkers.length === 0 ? (
              <p className="py-6 text-center text-xs text-muted">
                No agents working right now. Launch a run from{" "}
                <Link href="/engagements" className="text-fg underline-offset-2 hover:underline">Engagements</Link>.
              </p>
            ) : (
              <div className="grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
                {liveWorkers.map((a) => <LiveAgentCard key={a.uid} a={a} />)}
              </div>
            )}
          </div>
        </Panel>
      </div>

      {/* family tabs (segmented) */}
      <div className="mt-6 flex flex-wrap gap-1.5 rounded-full border border-line p-1">
        {tabs.map((t) => (
          <button
            key={t.k}
            onClick={() => setFamily(t.k)}
            aria-pressed={family === t.k}
            className={cx(
              "inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-[13px] transition",
              family === t.k ? "bg-card2 text-fg-strong" : "text-muted hover:text-fg",
            )}
          >
            {t.label}
            <span className="font-mono text-[11px] text-faint">{t.n}</span>
          </button>
        ))}
      </div>

      <div className="mt-5 grid grid-cols-1 gap-3.5 sm:grid-cols-2 lg:grid-cols-3">
        {shown.map((a) => (
          <AgentCard key={a.slug} agent={a} live={runningSlugs.has(a.slug)} />
        ))}
      </div>
    </>
  );
}

// a live, working agent — rendered as the dashboard's busy agent-card: green hairline across
// the top, role icon, Running pill, current task, and an animated bar. There's no per-agent
// progress % in the run stream, so the bar is an honest indeterminate "working" sweep.
function LiveAgentCard({ a }: { a: RunAgent }) {
  const Icon = ROLE_ICON[a.role] ?? Bot;
  return (
    <div className="busy-top relative flex flex-col gap-3.5 rounded-[18px] border border-emerald-500/40 bg-emerald-500/[0.03] p-4">
      <div className="flex items-center gap-3">
        <span className="grid h-9 w-9 shrink-0 place-items-center rounded-lg border border-emerald-500/30 text-emerald-400">
          <Icon size={16} />
        </span>
        <div className="min-w-0 flex-1">
          <div className="truncate font-mono text-sm font-medium text-fg-strong">{a.name}</div>
          <div className="truncate text-[12.5px] capitalize text-faint">{a.role}</div>
        </div>
        <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-400">
          <span className="live-dot" /> Running
        </span>
      </div>

      <div>
        <div className="mb-1.5 text-[10.5px] font-medium uppercase tracking-[0.08em] text-faint">Current task</div>
        <div className="line-clamp-2 min-h-[2.4em] text-[13px] leading-relaxed text-fg">{a.task || "Working…"}</div>
      </div>

      <div className="h-1 w-full overflow-hidden rounded-full bg-emerald-500/15">
        <div className="progress-live h-full w-full rounded-full bg-emerald-500/40" />
      </div>
    </div>
  );
}

function AgentCard({ agent: a, live = false }: { agent: Agent; live?: boolean }) {
  const isRunning = live || a.status === "running";
  const st = isRunning ? { color: "#22c55e", label: "Running" } : AGENT_STATUS[a.status];
  const ratio = a.produced > 0 ? a.accepted / a.produced : 0;
  return (
    <div className={cx("group relative flex flex-col gap-3.5 rounded-[18px] border border-fg/10 p-4 transition hover:border-fg/25", isRunning && "border-emerald-500/40 bg-emerald-500/[0.03]")}>
      <div className="flex items-center gap-3">
        <span className="tile-ico text-muted"><Bot size={16} /></span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 font-mono text-sm font-medium text-fg-strong">
            <span className="truncate">{a.name}</span>
            {a.approvalGated && <Lock size={12} className="shrink-0 text-amber-500" />}
          </div>
          <div className="truncate text-xs text-faint">{a.family} · {a.tier}</div>
        </div>
        <Pill label={a.tier} color={TIER_COLOR[a.tier]} />
      </div>

      <p className="line-clamp-2 min-h-[2.4em] flex-1 text-xs leading-relaxed text-muted">{a.summary}</p>

      <div className="flex items-center gap-1.5 text-[11px] text-muted">
        <ShieldCheck size={13} className="shrink-0 text-brand" />
        <span className="truncate font-mono">{a.reviewer}</span>
      </div>

      {/* accepted / produced ratio */}
      <div>
        <div className="mb-1 flex items-center justify-between font-mono text-[11px] text-faint">
          <span>accepted / produced</span>
          <span>{a.accepted}/{a.produced}</span>
        </div>
        <div className="h-1 w-full overflow-hidden rounded-full bg-line">
          <div className="h-full rounded-full" style={{ width: `${Math.round(ratio * 100)}%`, background: "#22c55e" }} />
        </div>
      </div>

      <div className="flex items-center justify-between border-t border-line pt-3 font-mono text-[11px] text-faint">
        <span className="inline-flex items-center gap-1.5 text-muted"><Dot color={st.color} pulse={isRunning} /> {st.label}</span>
        <span className="flex items-center gap-2.5">
          {a.accepted > 0 && <span style={{ color: "#22c55e" }}>{a.accepted} ✓</span>}
          {a.rejected > 0 && <span style={{ color: "#ef4444" }}>{a.rejected} ✕</span>}
        </span>
      </div>
    </div>
  );
}

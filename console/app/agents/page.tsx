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
import { Kpi, ViewHead, Pill, Dot } from "@/components/ui/primitives";

const TIER_COLOR: Record<AgentTier, string> = {
  "Tier-1": "#f43f5e", "Tier-2": "#fb923c", "Tier-3": "#a78bfa", Feeder: "#38bdf8", Capability: "#22c55e",
};

// map a live run-stream agent name to a roster slug, so a working agent lights up its OWN
// roster card. Skills stream as "redstrike-<slug>"; reviewers as "<slug>-verify".
function liveSlug(name: string): string {
  let s = name;
  if (s.startsWith("redstrike-")) s = s.slice("redstrike-".length);
  return s.replace(/-verify$/, "");
}

export default function AgentsPage() {
  const { agents } = useConsole();
  const { conn, orch } = useControl();
  const [family, setFamily] = useState<string>("all");

  // live "working now" from the control-plane run stream (real time). The orchestrator
  // (redstrike) is the hub, not a worker, so it's excluded. Each running worker is keyed to
  // its roster slug so it lights up its OWN card (no separate panel).
  const liveBySlug = useMemo(() => {
    const m = new Map<string, RunAgent>();
    for (const a of orch.agents) {
      if (a.status === "running" && a.role !== "orchestrator") m.set(liveSlug(a.name), a);
    }
    return m;
  }, [orch.agents]);
  const runningCount = liveBySlug.size;

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
        sub={conn === "ready"
          ? `${agents.length} executors + reviewers · ${runningCount} working now · ${families.length} families`
          : `${agents.length} executors + reviewers · ${families.length} families · control plane offline`}
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
          <AgentCard key={a.slug} agent={a} live={liveBySlug.get(a.slug)} />
        ))}
      </div>
    </>
  );
}

// The roster card. When the control plane reports this agent running (matched by slug), the
// card itself takes the dashboard's busy treatment — green hairline, Running pill, its current
// task, and an animated bar — instead of a separate "working now" panel.
function AgentCard({ agent: a, live }: { agent: Agent; live?: RunAgent }) {
  const isRunning = !!live || a.status === "running";
  const st = isRunning ? { color: "#22c55e", label: "Running" } : AGENT_STATUS[a.status];
  const ratio = a.produced > 0 ? a.accepted / a.produced : 0;
  return (
    <div className={cx("group relative flex flex-col gap-3.5 rounded-[18px] border border-fg/10 p-4 transition hover:border-fg/25", isRunning && "busy-top border-emerald-500/40 bg-emerald-500/[0.03]")}>
      <div className="flex items-center gap-3">
        <span className={cx("tile-ico", isRunning ? "text-emerald-400" : "text-muted")}><Bot size={16} /></span>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5 font-mono text-sm font-medium text-fg-strong">
            <span className="truncate">{a.name}</span>
            {a.approvalGated && <Lock size={12} className="shrink-0 text-amber-500" />}
          </div>
          <div className="truncate text-xs text-faint">{a.family} · {a.tier}</div>
        </div>
        {isRunning ? (
          <span className="inline-flex shrink-0 items-center gap-1.5 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-2 py-0.5 text-[11px] font-medium text-emerald-400">
            <span className="live-dot" /> Running
          </span>
        ) : (
          <Pill label={a.tier} color={TIER_COLOR[a.tier]} />
        )}
      </div>

      {isRunning ? (
        <div className="flex-1">
          <div className="mb-1.5 text-[10.5px] font-medium uppercase tracking-[0.08em] text-faint">Current task</div>
          <div className="line-clamp-2 min-h-[2.4em] text-[13px] leading-relaxed text-fg">{live?.task || "Working…"}</div>
          <div className="mt-2.5 h-1 w-full overflow-hidden rounded-full bg-emerald-500/15">
            <div className="progress-live h-full w-full rounded-full bg-emerald-500/40" />
          </div>
        </div>
      ) : (
        <p className="line-clamp-2 min-h-[2.4em] flex-1 text-xs leading-relaxed text-muted">{a.summary}</p>
      )}

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

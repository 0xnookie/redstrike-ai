"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { Bot, ShieldCheck, Lock, Share2 } from "lucide-react";
import { useConsole } from "@/lib/store";
import { AGENT_STATUS } from "@/lib/theme";
import { cx } from "@/lib/format";
import type { Agent, AgentTier } from "@/lib/types";
import { Kpi, ViewHead, Pill, Dot } from "@/components/ui/primitives";

const TIER_COLOR: Record<AgentTier, string> = {
  "Tier-1": "#f43f5e", "Tier-2": "#fb923c", "Tier-3": "#a78bfa", Feeder: "#38bdf8", Capability: "#22c55e",
};

export default function AgentsPage() {
  const { agents } = useConsole();
  const [family, setFamily] = useState<string>("all");

  const families = useMemo(() => Array.from(new Set(agents.map((a) => a.family))), [agents]);
  const shown = agents.filter((a) => family === "all" || a.family === family);

  const produced = agents.reduce((a, x) => a + x.produced, 0);
  const accepted = agents.reduce((a, x) => a + x.accepted, 0);
  const running = agents.filter((a) => a.status === "running").length;

  const tabs = [{ k: "all", label: "All", n: agents.length }, ...families.map((f) => ({ k: f, label: f, n: agents.filter((a) => a.family === f).length }))];

  return (
    <>
      <ViewHead
        crumb="redstrike / agents"
        title="Agents"
        live={running > 0}
        sub={`${agents.length} executors + reviewers · ${running} running · ${families.length} families`}
        actions={
          <Link href="/orchestration" className="inline-flex h-10 items-center gap-2 rounded-full border border-line px-4 text-sm font-medium text-fg transition hover:border-fg/30">
            <Share2 size={15} /> Live orchestration
          </Link>
        }
      />

      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-3 lg:grid-cols-5">
        <Kpi label="Agents" value={agents.length} icon={<Bot size={16} />} note="in the pool" />
        <Kpi label="Families" value={families.length} note="skill groups" />
        <Kpi label="Running" value={running} color="#3b82f6" note="active now" />
        <Kpi label="Findings produced" value={produced} note="all time" />
        <Kpi label="Accepted" value={accepted} color="#22c55e" note="after review" />
      </div>

      {/* role tabs (segmented) */}
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
          <AgentCard key={a.slug} agent={a} />
        ))}
      </div>
    </>
  );
}

function AgentCard({ agent: a }: { agent: Agent }) {
  const st = AGENT_STATUS[a.status];
  const ratio = a.produced > 0 ? a.accepted / a.produced : 0;
  return (
    <div className={cx("group relative flex flex-col gap-3.5 rounded-[18px] border border-fg/10 p-4 transition hover:border-fg/25", a.status === "running" && "border-emerald-500/30")}>
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
        <span className="inline-flex items-center gap-1.5 text-muted"><Dot color={st.color} pulse={a.status === "running"} /> {st.label}</span>
        <span className="flex items-center gap-2.5">
          {a.accepted > 0 && <span style={{ color: "#22c55e" }}>{a.accepted} ✓</span>}
          {a.rejected > 0 && <span style={{ color: "#ef4444" }}>{a.rejected} ✕</span>}
        </span>
      </div>
    </div>
  );
}

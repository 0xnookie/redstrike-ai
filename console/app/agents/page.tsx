"use client";

import { useMemo, useState } from "react";
import { Bot, ShieldCheck, Lock } from "lucide-react";
import { useConsole } from "@/lib/store";
import { AGENT_STATUS } from "@/lib/theme";
import { cx } from "@/lib/format";
import type { Agent, AgentTier } from "@/lib/types";
import { Card, PageHeader, Kpi, Pill, Dot } from "@/components/ui/primitives";

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

  return (
    <>
      <PageHeader
        title="Agents"
        subtitle="Every skill ships an executor and an independent reviewer that re-judges each finding against its evidence."
      />

      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
        <Kpi label="Agents" value={agents.length} icon={<Bot size={15} />} />
        <Kpi label="Families" value={families.length} />
        <Kpi label="Running" value={running} color="#3b82f6" />
        <Kpi label="Findings produced" value={produced} />
        <Kpi label="Accepted" value={accepted} color="#22c55e" />
      </div>

      <div className="mb-4 flex flex-wrap items-center gap-1.5">
        <Chip active={family === "all"} onClick={() => setFamily("all")} label={`All (${agents.length})`} />
        {families.map((f) => (
          <Chip key={f} active={family === f} onClick={() => setFamily(f)} label={`${f} (${agents.filter((a) => a.family === f).length})`} />
        ))}
      </div>

      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {shown.map((a) => (
          <AgentCard key={a.slug} agent={a} />
        ))}
      </div>
    </>
  );
}

function AgentCard({ agent: a }: { agent: Agent }) {
  const st = AGENT_STATUS[a.status];
  return (
    <Card className="flex flex-col p-4">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2">
          <div className="grid h-8 w-8 place-items-center rounded-lg bg-card2 text-muted"><Bot size={16} /></div>
          <div>
            <div className="flex items-center gap-1.5 text-sm font-semibold leading-tight">
              {a.name}
              {a.approvalGated && <Lock size={12} className="text-amber-500" />}
            </div>
            <div className="font-mono text-[11px] text-muted">{a.slug}</div>
          </div>
        </div>
        <Pill label={a.tier} color={TIER_COLOR[a.tier]} />
      </div>

      <p className="mt-2.5 flex-1 text-xs leading-relaxed text-muted">{a.summary}</p>

      <div className="mt-3 flex items-center gap-1.5 text-[11px] text-muted">
        <ShieldCheck size={13} className="text-brand" />
        <span className="font-mono">{a.reviewer}</span>
      </div>

      <div className="mt-3 flex items-center justify-between border-t border-line pt-3">
        <div className="flex items-center gap-1.5 text-[11px] text-muted">
          <Dot color={st.color} pulse={a.status === "running"} /> {st.label}
        </div>
        <div className="flex items-center gap-3 text-[11px] text-muted">
          <span title="produced">{a.produced} produced</span>
          {a.accepted > 0 && <span style={{ color: "#22c55e" }}>{a.accepted} ✓</span>}
          {a.rejected > 0 && <span style={{ color: "#ef4444" }}>{a.rejected} ✕</span>}
        </div>
      </div>
    </Card>
  );
}

function Chip({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button
      onClick={onClick}
      className={cx(
        "rounded-full border px-2.5 py-1 text-xs font-medium transition",
        active ? "border-brand/60 bg-brand/10 text-brand" : "border-line text-muted hover:text-fg"
      )}
    >
      {label}
    </button>
  );
}

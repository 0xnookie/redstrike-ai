"use client";

import { useMemo, useState } from "react";
import { Workflow } from "lucide-react";
import { useConsole } from "@/lib/store";
import { cvssScore, cvssRating } from "@/lib/cvss";
import { FEASIBILITY, ROLE_COLOR } from "@/lib/theme";
import { cx } from "@/lib/format";
import type { Finding } from "@/lib/types";
import { Card, PageHeader, Pill, EmptyState } from "@/components/ui/primitives";
import { ChainGraph } from "@/components/chains/ChainGraph";
import { FindingDrawer } from "@/components/findings/FindingDrawer";

export default function ChainsPage() {
  const { chains, findings } = useConsole();
  const findingsById = useMemo(() => Object.fromEntries(findings.map((f) => [f.id, f])), [findings]);
  const [activeId, setActiveId] = useState(chains[0]?.id);
  const [selected, setSelected] = useState<Finding | null>(null);

  const chain = chains.find((c) => c.id === activeId) ?? chains[0];

  if (!chains.length) {
    return (
      <>
        <PageHeader title="Attack chains" subtitle="Kill chains composed from accepted findings." />
        <Card className="p-6"><EmptyState icon={<Workflow size={28} />} title="No attack chains" hint="Load an attack_chains.json, or run the attack-chain-discovery capability." /></Card>
      </>
    );
  }

  const score = chain?.cvss ? cvssScore(chain.cvss) : null;

  return (
    <>
      <PageHeader title="Attack chains" subtitle="Kill chains composed from accepted findings — excluded from severity counts (non-additive)." />

      <div className="grid grid-cols-1 gap-3 lg:grid-cols-[280px_1fr]">
        {/* chain list */}
        <div className="space-y-2">
          {chains.map((c) => {
            const active = c.id === chain?.id;
            const fe = c.feasibility ? FEASIBILITY[c.feasibility] : null;
            return (
              <button
                key={c.id}
                onClick={() => setActiveId(c.id)}
                className={cx(
                  "w-full rounded-xl border bg-card p-3 text-left shadow-card transition",
                  active ? "border-brand/60 ring-1 ring-brand/30" : "border-line hover:border-brand/30"
                )}
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-muted">{c.id}</span>
                  {fe && <Pill label={fe.label} color={fe.color} />}
                </div>
                <div className="mt-1 text-sm font-medium leading-tight">{c.title}</div>
                <div className="mt-1 text-xs text-muted">{c.steps.length} steps</div>
              </button>
            );
          })}
        </div>

        {/* graph + meta */}
        <div className="space-y-3">
          {chain && <ChainGraph chain={chain} findingsById={findingsById} onSelectFinding={setSelected} />}

          {/* role legend */}
          <div className="flex flex-wrap items-center gap-3 text-xs text-muted">
            {Object.entries(ROLE_COLOR).map(([role, col]) => (
              <span key={role} className="flex items-center gap-1.5">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: col }} />
                {role}
              </span>
            ))}
            <span className="flex items-center gap-1.5">
              <svg width="20" height="8"><line x1="0" y1="4" x2="20" y2="4" stroke="rgb(var(--muted))" strokeWidth="1.5" strokeDasharray="4 4" /></svg>
              enables →
            </span>
          </div>

          {chain && (
            <Card className="p-4">
              <div className="flex items-start justify-between gap-3">
                <h2 className="text-sm font-semibold">{chain.title}</h2>
                {chain.feasibility && <Pill label={FEASIBILITY[chain.feasibility].label} color={FEASIBILITY[chain.feasibility].color} dot />}
              </div>
              {chain.impact && <p className="mt-2 text-sm">{chain.impact}</p>}
              <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
                {chain.cvss && (
                  <div>
                    <div className="text-[11px] font-medium uppercase tracking-wide text-muted">Chain CVSS</div>
                    <div className="mt-0.5 text-sm">
                      <span className="font-semibold tabular-nums">{score?.toFixed(1)}</span>
                      <span className="ml-1 text-muted">{cvssRating(score)}</span>
                      <code className="ml-2 break-all text-xs text-muted">{chain.cvss}</code>
                    </div>
                  </div>
                )}
                {chain.preconditions && chain.preconditions.length > 0 && (
                  <div>
                    <div className="text-[11px] font-medium uppercase tracking-wide text-muted">Preconditions</div>
                    <ul className="mt-0.5 list-inside list-disc text-sm text-muted">
                      {chain.preconditions.map((p, i) => <li key={i}>{p}</li>)}
                    </ul>
                  </div>
                )}
              </div>
            </Card>
          )}
        </div>
      </div>

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </>
  );
}

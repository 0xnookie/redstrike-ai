"use client";

import { useMemo, useState } from "react";
import { ChevronLeft, ChevronRight, ShieldAlert, Workflow } from "lucide-react";
import { useConsole } from "@/lib/store";
import { cvssScore, cvssRating } from "@/lib/cvss";
import { FEASIBILITY, SEVERITY, roleColor, sevMeta } from "@/lib/theme";
import { assetHosts, cx } from "@/lib/format";
import type { Finding, Severity } from "@/lib/types";
import { Panel, PanelHeader, PanelBody, ViewHead, Pill, SeverityBadge, EmptyState } from "@/components/ui/primitives";
import { ChainGraph } from "@/components/chains/ChainGraph";

/* CVSS base score → severity color, for the blast-radius tile. */
const scoreColor = (sc: number | null): string | undefined => {
  if (sc === null) return undefined;
  if (sc >= 9) return SEVERITY.critical.color;
  if (sc >= 7) return SEVERITY.high.color;
  if (sc >= 4) return SEVERITY.medium.color;
  if (sc > 0) return SEVERITY.low.color;
  return SEVERITY.info.color;
};

export default function ChainsPage() {
  const { chains, findings, openFinding } = useConsole();
  const findingsById = useMemo<Record<string, Finding>>(
    () => Object.fromEntries(findings.map((f) => [f.id, f])),
    [findings],
  );
  const [activeId, setActiveId] = useState(chains[0]?.id);
  const [stepIdx, setStepIdx] = useState(0);

  const chain = chains.find((c) => c.id === activeId) ?? chains[0];

  // unique affected hosts across every step's linked finding
  const assetCount = useMemo(() => {
    const hosts = new Set<string>();
    chain?.steps.forEach((s) => {
      const f = findingsById[s.finding_id];
      if (f) assetHosts(f.asset).forEach((h) => hosts.add(h));
    });
    return hosts.size;
  }, [chain, findingsById]);

  // highest severity reached along the chain
  const maxSev = useMemo<Severity | null>(() => {
    let best: Severity | null = null;
    chain?.steps.forEach((s) => {
      const f = findingsById[s.finding_id];
      if (f && (best === null || SEVERITY[f.severity].rank > SEVERITY[best].rank)) best = f.severity;
    });
    return best;
  }, [chain, findingsById]);

  if (!chains.length || !chain) {
    return (
      <>
        <ViewHead crumb="redstrike / attack-chains" title="Attack chains" sub="Kill chains composed from accepted findings." />
        <Panel>
          <PanelBody>
            <EmptyState
              icon={<Workflow size={28} />}
              title="No attack chains"
              hint="Load an attack_chains.json, or run the attack-chain-discovery capability."
            />
          </PanelBody>
        </Panel>
      </>
    );
  }

  const selectChain = (id: string) => { setActiveId(id); setStepIdx(0); };
  const curStep = Math.min(stepIdx, chain.steps.length - 1);
  const step = chain.steps[curStep];
  const stepF = step ? findingsById[step.finding_id] : undefined;
  const stepScore = stepF?.cvss_vector ? cvssScore(stepF.cvss_vector) : null;

  const fe = chain.feasibility ? FEASIBILITY[chain.feasibility] : null;
  const chainScore = chain.cvss ? cvssScore(chain.cvss) : null;
  const rolesPresent = [...new Set(chain.steps.map((s) => s.role))];

  return (
    <>
      <ViewHead
        crumb="redstrike / attack-chains"
        title="Attack chains"
        sub={`${chains.length} validated ${chains.length === 1 ? "path" : "paths"} · entry → business impact · non-additive to severity counts`}
      />

      {/* chain picker */}
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {chains.map((c) => {
          const active = c.id === chain.id;
          const cfe = c.feasibility ? FEASIBILITY[c.feasibility] : null;
          return (
            <button
              key={c.id}
              type="button"
              onClick={() => selectChain(c.id)}
              aria-pressed={active}
              className={cx(
                "flex flex-col gap-2.5 rounded-2xl border p-4 text-left transition",
                active ? "border-fg/30 bg-card2" : "border-line hover:border-fg/20",
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-xs text-faint">{c.id}</span>
                {cfe && <Pill label={cfe.label} color={cfe.color} dot />}
              </div>
              <div className="text-sm font-medium leading-snug text-fg-strong">{c.title}</div>
              <div className="font-mono text-[11px] text-faint">
                {c.steps.length} {c.steps.length === 1 ? "step" : "steps"}
                {c.feasibility ? ` · ${c.feasibility} feasibility` : ""}
              </div>
            </button>
          );
        })}
      </div>

      {/* horizontal step flow */}
      <Panel className="mt-5">
        <PanelHeader title={chain.title} sub={chain.id} actions={fe ? <Pill label={fe.label} color={fe.color} dot /> : undefined} />
        <PanelBody>
          <ChainGraph chain={chain} findingsById={findingsById} activeStep={curStep} onSelectStep={setStepIdx} />
          <div className="mt-4 flex flex-wrap items-center gap-4 text-xs text-muted">
            {rolesPresent.map((role) => (
              <span key={role} className="inline-flex items-center gap-2">
                <span className="h-2 w-2 rounded-sm" style={{ background: roleColor(role) }} />
                {role}
              </span>
            ))}
            <span className="inline-flex items-center gap-2 text-faint">
              <ChevronRight size={13} /> enables next step
            </span>
          </div>
        </PanelBody>
      </Panel>

      {/* step detail · blast radius */}
      <div className="mt-5 grid gap-5 lg:grid-cols-2">
        <Panel>
          <PanelHeader
            title="Step detail"
            sub={`Step ${curStep + 1} of ${chain.steps.length}`}
            actions={step ? <Pill label={step.role} color={roleColor(step.role)} dot /> : undefined}
          />
          <PanelBody className="space-y-4">
            <div>
              <div className="text-base font-medium text-fg-strong">{stepF ? stepF.title : step?.finding_id}</div>
              {stepF?.impact && <p className="mt-1.5 text-sm leading-relaxed text-muted">{stepF.impact}</p>}
            </div>

            <dl className="grid grid-cols-1 gap-x-6 gap-y-2.5 sm:grid-cols-2">
              <Meta label="Role" value={step?.role} />
              <Meta label="Finding" value={step?.finding_id} mono />
              {stepF && <Meta label="Asset" value={stepF.asset} mono />}
              {stepF && (
                <Meta
                  label="Severity"
                  value={<span style={{ color: sevMeta(stepF.severity).color }}>{sevMeta(stepF.severity).label}</span>}
                />
              )}
              {stepF && <Meta label="Confidence" value={stepF.confidence} />}
              {step?.enables && <Meta label="Enables" value={step.enables} />}
            </dl>

            {stepF && (
              <div>
                <div className="mb-2 text-[11px] font-medium uppercase tracking-wide text-faint">Linked finding</div>
                <button
                  type="button"
                  onClick={() => openFinding(stepF)}
                  className="flex w-full items-center gap-3 rounded-xl border border-line p-3 text-left transition hover:border-fg/25"
                >
                  <SeverityBadge severity={stepF.severity} dot />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm text-fg">{stepF.title}</div>
                    <div className="truncate font-mono text-[11px] text-faint">{stepF.id} · {stepF.asset}</div>
                  </div>
                  {stepScore !== null && (
                    <span className="shrink-0 tabular-nums text-sm" style={{ color: sevMeta(stepF.severity).color }}>
                      {stepScore.toFixed(1)}
                    </span>
                  )}
                </button>
              </div>
            )}

            <div className="flex items-center justify-between gap-2 pt-1">
              <button
                type="button"
                disabled={curStep === 0}
                onClick={() => setStepIdx(curStep - 1)}
                className={cx(
                  "inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[13px] text-fg transition hover:border-fg/30",
                  curStep === 0 && "pointer-events-none opacity-40",
                )}
              >
                <ChevronLeft size={14} /> Previous
              </button>
              <button
                type="button"
                disabled={curStep >= chain.steps.length - 1}
                onClick={() => setStepIdx(curStep + 1)}
                className={cx(
                  "inline-flex items-center gap-1.5 rounded-full border border-line px-3 py-1.5 text-[13px] text-fg transition hover:border-fg/30",
                  curStep >= chain.steps.length - 1 && "pointer-events-none opacity-40",
                )}
              >
                Next <ChevronRight size={14} />
              </button>
            </div>
          </PanelBody>
        </Panel>

        <Panel>
          <PanelHeader title="Blast radius" sub="chain impact" icon={<ShieldAlert size={15} className="text-muted" />} />
          <PanelBody className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <Stat value={chain.steps.length} label="Steps" />
              <Stat value={assetCount || "—"} label="Affected assets" />
              <Stat value={fe ? fe.label : "—"} label="Feasibility" color={fe?.color} />
              {chainScore !== null ? (
                <Stat value={chainScore.toFixed(1)} label={`CVSS · ${cvssRating(chainScore)}`} color={scoreColor(chainScore)} />
              ) : (
                <Stat value={maxSev ? sevMeta(maxSev).label : "—"} label="Max severity" color={maxSev ? sevMeta(maxSev).color : undefined} />
              )}
            </div>

            {chain.cvss && (
              <div className="font-mono text-[11px] text-faint break-all">{chain.cvss}</div>
            )}

            {chain.impact && (
              <div>
                <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-faint">Impact</div>
                <p className="text-sm leading-relaxed text-muted">{chain.impact}</p>
              </div>
            )}

            {chain.preconditions && chain.preconditions.length > 0 && (
              <div>
                <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-faint">Preconditions</div>
                <ul className="space-y-1.5 text-sm text-muted">
                  {chain.preconditions.map((p, i) => (
                    <li key={i} className="flex gap-2">
                      <span className="mt-[7px] h-1 w-1 shrink-0 rounded-full bg-fg/30" />
                      {p}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {chain.notes && (
              <div>
                <div className="mb-1.5 text-[11px] font-medium uppercase tracking-wide text-faint">Notes</div>
                <p className="text-sm leading-relaxed text-muted">{chain.notes}</p>
              </div>
            )}
          </PanelBody>
        </Panel>
      </div>
    </>
  );
}

function Meta({ label, value, mono }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div>
      <dt className="text-[11px] font-medium uppercase tracking-wide text-faint">{label}</dt>
      <dd className={cx("mt-0.5 text-sm text-fg", mono && "break-all font-mono text-[13px]")}>{value ?? "—"}</dd>
    </div>
  );
}

function Stat({ value, label, color }: { value: React.ReactNode; label: string; color?: string }) {
  return (
    <div className="rounded-2xl border border-line p-3.5">
      <div
        className="text-[19px] font-semibold leading-none tracking-tight tabular-nums text-fg-strong"
        style={color ? { color } : undefined}
      >
        {value}
      </div>
      <div className="mt-1.5 text-xs text-faint">{label}</div>
    </div>
  );
}

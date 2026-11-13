"use client";

import { Fragment } from "react";
import { GitBranch, LogIn, TrendingUp, Upload, Workflow, type LucideIcon } from "lucide-react";
import type { AttackChain, Finding } from "@/lib/types";
import { cvssScore } from "@/lib/cvss";
import { hexA, roleColor, sevMeta } from "@/lib/theme";
import { cx } from "@/lib/format";

/* step-role → icon (data role colors still come from lib/theme roleColor) */
const ROLE_ICON: Record<string, LucideIcon> = {
  entry: LogIn,
  pivot: GitBranch,
  escalation: TrendingUp,
  exfil: Upload,
};

const pad2 = (n: number) => String(n).padStart(2, "0");

/**
 * Horizontal kill-chain flow: a row of step "nodes" (role-colored icon chip,
 * step kicker, finding title, id/asset, severity+CVSS) joined by animated
 * arrow connectors. Scrolls horizontally when the chain is long. Clicking a node
 * selects that step (drives the Step detail panel on the page).
 */
export function ChainGraph({
  chain, findingsById, activeStep, onSelectStep,
}: {
  chain: AttackChain;
  findingsById: Record<string, Finding>;
  activeStep: number;
  onSelectStep: (i: number) => void;
}) {
  return (
    <div className="scroll-thin flex items-stretch overflow-x-auto pb-2">
      {chain.steps.map((s, i) => {
        const f = findingsById[s.finding_id];
        const col = roleColor(s.role);
        const Icon = ROLE_ICON[s.role] ?? Workflow;
        const sev = f ? sevMeta(f.severity) : null;
        const score = f?.cvss_vector ? cvssScore(f.cvss_vector) : null;
        const active = i === activeStep;
        return (
          <Fragment key={s.finding_id + i}>
            {i > 0 && (
              // link to the next step — a light pulse travels toward the arrowhead
              <div className="flex shrink-0 select-none items-center self-center px-1.5" aria-hidden>
                <span className="chain-conn" />
              </div>
            )}
            <button
              type="button"
              onClick={() => onSelectStep(i)}
              aria-pressed={active}
              className={cx(
                "flex min-w-[180px] max-w-[260px] flex-1 flex-col gap-1.5 rounded-[18px] border bg-card2 p-4 text-left transition",
                !active && "border-line hover:border-fg/25",
              )}
              style={active ? { borderColor: hexA(col, "aa"), boxShadow: `0 0 0 4px ${hexA(col, "14")}` } : undefined}
            >
              <span
                className="grid h-8 w-8 place-items-center rounded-xl border"
                style={{ color: col, borderColor: hexA(col, "55") }}
              >
                <Icon size={15} />
              </span>
              <span className="font-mono text-[10.5px] uppercase tracking-[0.08em] text-faint">
                {pad2(i + 1)} · {s.role}
              </span>
              <span className="text-sm font-medium leading-snug text-fg-strong">
                {f ? f.title : "(finding not in set)"}
              </span>
              <span className="break-words font-mono text-[11px] text-muted">
                {s.finding_id}{f?.asset ? ` · ${f.asset}` : ""}
              </span>
              {(sev || score !== null) && (
                <span className="mt-auto flex items-center gap-2.5 pt-1.5 font-mono text-[11px] text-faint">
                  {sev && (
                    <span className="inline-flex items-center gap-1.5" style={{ color: sev.color }}>
                      <span className="h-1.5 w-1.5 rounded-full" style={{ background: sev.color }} />
                      {sev.label}
                    </span>
                  )}
                  {score !== null && <span className="tabular-nums">CVSS {score.toFixed(1)}</span>}
                </span>
              )}
            </button>
          </Fragment>
        );
      })}
    </div>
  );
}

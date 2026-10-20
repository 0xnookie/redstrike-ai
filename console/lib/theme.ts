// Data palette for the console. The CHROME (bg/card/sidebar/buttons/nav) stays
// neutral black & white via Tailwind tokens; these colors encode DATA only —
// severity, verdict, coverage, status — so the console reads like a real pentest
// console: calm monochrome shell, meaningful color where it carries information.

import type { Severity, Verdict, Confidence, ChainFeasibility, AgentStatus, EngagementStatus } from "./types";

/** foreground at a given alpha — for neutral, theme-adaptive accents. */
export const ink = (a: number) => `rgb(var(--fg) / ${a})`;
/** 6-digit hex + 2-digit alpha for translucent fills/borders. */
export const hexA = (hex: string, alpha: string) => hex + alpha;

export const SEVERITY: Record<Severity, { label: string; color: string; rank: number }> = {
  critical: { label: "Critical", color: "#f43f5e", rank: 5 },
  high: { label: "High", color: "#fb923c", rank: 4 },
  medium: { label: "Medium", color: "#facc15", rank: 3 },
  low: { label: "Low", color: "#38bdf8", rank: 2 },
  info: { label: "Info", color: "#94a3b8", rank: 1 },
};
export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const VERDICT: Record<Verdict, { label: string; color: string }> = {
  accepted: { label: "Accepted", color: "#22c55e" },
  blocked: { label: "Blocked", color: "#f59e0b" },
  rejected: { label: "Rejected", color: "#ef4444" },
  "needs-evidence": { label: "Needs evidence", color: "#a78bfa" },
};

export const CONFIDENCE: Record<Confidence, { label: string; color: string }> = {
  confirmed: { label: "Confirmed", color: "#34d399" },
  probable: { label: "Probable", color: "#fbbf24" },
  tentative: { label: "Tentative", color: "#9ca3af" },
};

export const FEASIBILITY: Record<ChainFeasibility, { label: string; color: string }> = {
  demonstrated: { label: "Demonstrated", color: "#22c55e" },
  plausible: { label: "Plausible", color: "#f59e0b" },
  theoretical: { label: "Theoretical", color: "#9ca3af" },
};

export const AGENT_STATUS: Record<AgentStatus, { label: string; color: string }> = {
  running: { label: "Running", color: "#3b82f6" },
  done: { label: "Done", color: "#22c55e" },
  blocked: { label: "Blocked", color: "#f59e0b" },
  idle: { label: "Idle", color: "#9ca3af" },
};

export const ENGAGEMENT_STATUS: Record<EngagementStatus, { label: string; color: string }> = {
  running: { label: "Running", color: "#3b82f6" },
  paused: { label: "Paused", color: "#f59e0b" },
  completed: { label: "Completed", color: "#22c55e" },
  scoping: { label: "Scoping", color: "#9ca3af" },
};

/** coverage of an asset (used by the asset map + assets table). */
export const COVERAGE = {
  tested: { label: "Tested", color: "#22c55e" },
  "in-progress": { label: "In progress", color: "#f59e0b" },
  untested: { label: "Untested", color: "#64748b" },
} as const;

/** kill-chain step roles (used by the chain graph). */
export const ROLE_COLOR: Record<string, string> = {
  entry: "#3b82f6", pivot: "#a78bfa", escalation: "#f43f5e", exfil: "#f59e0b",
};
export const roleColor = (r: string) => ROLE_COLOR[r] ?? "#9ca3af";

export function sevMeta(s?: string) {
  return SEVERITY[(s as Severity) ?? "info"] ?? SEVERITY.info;
}

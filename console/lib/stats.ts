import type { Finding, Agent, Severity } from "./types";
import { SEVERITY_ORDER, SEVERITY } from "./theme";
import { cvssScore } from "./cvss";
import { isReportable, verdictOf, hostOf } from "./format";

export function reportable(findings: Finding[]): Finding[] {
  return findings.filter(isReportable);
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  findings.forEach((f) => { c[f.severity] = (c[f.severity] || 0) + 1; });
  return c;
}

export function severityChartData(findings: Finding[]) {
  const c = severityCounts(findings);
  return SEVERITY_ORDER.map((k) => ({ label: SEVERITY[k].label, value: c[k], color: SEVERITY[k].color, key: k }));
}

export interface VerificationStats {
  accepted: number; blocked: number; rejected: number; needsEvidence: number; other: number; total: number;
}
export function verificationStats(findings: Finding[]): VerificationStats {
  const s: VerificationStats = { accepted: 0, blocked: 0, rejected: 0, needsEvidence: 0, other: 0, total: findings.length };
  findings.forEach((f) => {
    const v = verdictOf(f);
    if (v === "accepted") s.accepted++;
    else if (v === "blocked") s.blocked++;
    else if (v === "rejected") s.rejected++;
    else if (v === "needs-evidence") s.needsEvidence++;
    else s.other++;
  });
  return s;
}

export function groupByCategory(findings: Finding[], top = 7) {
  const m = new Map<string, number>();
  findings.forEach((f) => {
    const k = f.category?.cwe || f.category?.owasp || "Uncategorized";
    m.set(k, (m.get(k) || 0) + 1);
  });
  return [...m.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value).slice(0, top);
}

export function groupByAsset(findings: Finding[], top = 7) {
  const m = new Map<string, number>();
  findings.forEach((f) => { const k = hostOf(f.asset); m.set(k, (m.get(k) || 0) + 1); });
  return [...m.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value).slice(0, top);
}

export function maxCvss(findings: Finding[]): number {
  return findings.reduce((mx, f) => Math.max(mx, cvssScore(f.cvss_vector) ?? 0), 0);
}

/** agents grouped by family, with produced/accepted roll-ups */
export function agentsByFamily(agents: Agent[]) {
  const m = new Map<string, Agent[]>();
  agents.forEach((a) => { const arr = m.get(a.family) || []; arr.push(a); m.set(a.family, arr); });
  return [...m.entries()].map(([family, list]) => ({
    family,
    list,
    produced: list.reduce((a, x) => a + x.produced, 0),
    accepted: list.reduce((a, x) => a + x.accepted, 0),
    active: list.filter((x) => x.status === "running").length,
  }));
}

"use client";

import { useMemo, useState } from "react";
import { Printer, FileDown, ShieldCheck } from "lucide-react";
import { useConsole } from "@/lib/store";
import { reportable, severityCounts, maxCvss } from "@/lib/stats";
import { SEVERITY, SEVERITY_ORDER, VERDICT, FEASIBILITY, sevMeta } from "@/lib/theme";
import { cvssScore, cvssRating } from "@/lib/cvss";
import { fmtDate, verdictOf } from "@/lib/format";
import type { Finding } from "@/lib/types";
import { Card, PageHeader, Pill, SeverityBadge } from "@/components/ui/primitives";
import { FindingDrawer } from "@/components/findings/FindingDrawer";

export default function ReportPage() {
  const { activeEngagement: eng, findings, chains } = useConsole();
  const [selected, setSelected] = useState<Finding | null>(null);

  const rep = reportable(findings);
  const counts = severityCounts(rep);
  const ordered = useMemo(
    () => [...rep].sort((a, b) => sevMeta(b.severity).rank - sevMeta(a.severity).rank || (cvssScore(b.cvss_vector) ?? 0) - (cvssScore(a.cvss_vector) ?? 0)),
    [rep]
  );
  const blocked = rep.filter((f) => verdictOf(f) === "blocked");
  const headline = ordered.filter((f) => verdictOf(f) === "accepted").slice(0, 5);

  const posture = counts.critical > 0 ? "critical" : counts.high > 0 ? "high" : counts.medium > 0 ? "elevated" : "low";

  const exportJson = () => {
    const blob = new Blob([JSON.stringify(rep, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = "findings_consolidated.json"; a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <PageHeader
        title="Report"
        subtitle="Client-ready view assembled from accepted findings — risk-ordered, with CVSS and attack chains."
        actions={
          <>
            <button onClick={exportJson} className="inline-flex h-9 items-center gap-1.5 rounded-lg border border-line bg-card px-3 text-sm font-medium transition hover:border-brand/40">
              <FileDown size={15} /> Export JSON
            </button>
            <button onClick={() => window.print()} className="inline-flex h-9 items-center gap-1.5 rounded-lg bg-brand px-3 text-sm font-medium text-brand-fg transition hover:brightness-110">
              <Printer size={15} /> Print / PDF
            </button>
          </>
        }
      />

      {/* executive summary */}
      <Card className="mb-3 p-5">
        <h2 className="text-sm font-semibold">Executive summary</h2>
        <div className="mt-3 grid grid-cols-1 gap-4 sm:grid-cols-2">
          <div className="space-y-1.5 text-sm">
            <Meta label="Engagement" value={eng.name} />
            <Meta label="Target" value={eng.target} />
            <Meta label="Window" value={`${fmtDate(eng.window.start)} → ${fmtDate(eng.window.end)}`} />
            <Meta label="Authorized by" value={eng.authorized_by} />
            <Meta label="Methodology" value="PTES · OWASP WSTG / Top 10 · MITRE ATT&CK" />
          </div>
          <div>
            <p className="text-sm leading-relaxed">
              The assessment identified <strong>{rep.length}</strong> reportable finding{rep.length === 1 ? "" : "s"} across{" "}
              {eng.target}. Overall risk posture is <strong style={{ color: sevMeta(posture === "elevated" ? "medium" : posture === "critical" ? "critical" : posture === "high" ? "high" : "low").color }}>{posture}</strong>
              {counts.critical > 0 ? `, driven by ${counts.critical} critical issue${counts.critical === 1 ? "" : "s"} including full database access and administrator takeover.` : "."} Peak severity scored{" "}
              <strong className="tabular-nums">{maxCvss(rep).toFixed(1)}</strong> (CVSS 3.1).
            </p>
            {/* severity table */}
            <div className="mt-3 grid grid-cols-5 gap-2">
              {SEVERITY_ORDER.map((k) => (
                <div key={k} className="rounded-lg border border-line bg-card2 p-2 text-center">
                  <div className="text-lg font-semibold tabular-nums" style={{ color: SEVERITY[k].color }}>{counts[k]}</div>
                  <div className="text-[10px] uppercase tracking-wide text-muted">{SEVERITY[k].label}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
        <div className="mt-4 flex items-center gap-2 border-t border-line pt-3 text-xs text-muted">
          <ShieldCheck size={14} className="text-brand" />
          Every finding was re-judged by an independent reviewer agent; rejected and unverified items are excluded.
        </div>
      </Card>

      {/* headline findings */}
      {headline.length > 0 && (
        <Card className="mb-3 p-5">
          <h2 className="mb-3 text-sm font-semibold">Headline findings</h2>
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            {headline.map((f) => {
              const s = cvssScore(f.cvss_vector);
              return (
                <button key={f.id} onClick={() => setSelected(f)} className="flex items-center gap-3 rounded-lg border border-line bg-card2 p-3 text-left transition hover:border-brand/40">
                  <SeverityBadge severity={f.severity} />
                  <div className="min-w-0 flex-1">
                    <div className="truncate text-sm font-medium">{f.title}</div>
                    <div className="truncate font-mono text-[11px] text-muted">{f.id} · {f.asset}</div>
                  </div>
                  {s !== null && <span className="tabular-nums text-sm font-semibold" style={{ color: sevMeta(f.severity).color }}>{s.toFixed(1)}</span>}
                </button>
              );
            })}
          </div>
        </Card>
      )}

      {/* full findings, risk-ordered */}
      <Card className="mb-3">
        <div className="border-b border-line p-4"><h2 className="text-sm font-semibold">Findings detail</h2></div>
        <div className="divide-y divide-line">
          {ordered.map((f) => <ReportFinding key={f.id} finding={f} onOpen={() => setSelected(f)} />)}
        </div>
      </Card>

      {/* demonstration-limited */}
      {blocked.length > 0 && (
        <Card className="mb-3 p-5">
          <h2 className="text-sm font-semibold">Confirmed — demonstration limited</h2>
          <p className="mt-1 text-xs text-muted">Confirmed real, but full demonstration was prevented by target/environment state. Shown with demonstrated vs. potential severity.</p>
          <ul className="mt-3 space-y-2">
            {blocked.map((f) => (
              <li key={f.id} className="flex items-center gap-3 text-sm">
                <SeverityBadge severity={f.severity} dot={false} />
                {f.potential_severity && <span className="text-xs text-muted">potential <SeverityBadge severity={f.potential_severity} dot={false} /></span>}
                <span className="font-medium">{f.title}</span>
                <span className="font-mono text-[11px] text-muted">{f.id}</span>
              </li>
            ))}
          </ul>
        </Card>
      )}

      {/* attack chains */}
      {chains.length > 0 && (
        <Card className="p-5">
          <h2 className="mb-3 text-sm font-semibold">Attack chains</h2>
          <div className="space-y-3">
            {chains.map((c) => (
              <div key={c.id} className="rounded-lg border border-line bg-card2 p-3">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-medium">{c.title}</span>
                  {c.feasibility && <Pill label={FEASIBILITY[c.feasibility].label} color={FEASIBILITY[c.feasibility].color} dot />}
                </div>
                <div className="mt-1.5 flex flex-wrap items-center gap-1 font-mono text-[11px] text-muted">
                  {c.steps.map((s, i) => (
                    <span key={i}>{i > 0 && <span className="mx-1">→</span>}{s.finding_id}<span className="text-muted/60"> ({s.role})</span></span>
                  ))}
                </div>
                {c.impact && <p className="mt-2 text-sm text-muted">{c.impact}</p>}
              </div>
            ))}
          </div>
        </Card>
      )}

      <FindingDrawer finding={selected} onClose={() => setSelected(null)} />
    </>
  );
}

function ReportFinding({ finding: f, onOpen }: { finding: Finding; onOpen: () => void }) {
  const s = cvssScore(f.cvss_vector);
  return (
    <div className="p-4">
      <div className="flex flex-wrap items-center gap-2">
        <SeverityBadge severity={f.severity} />
        <button onClick={onOpen} className="text-sm font-semibold hover:text-brand">{f.title}</button>
        <span className="font-mono text-[11px] text-muted">{f.id}</span>
        <span className="ml-auto text-xs text-muted">
          {s !== null && <span className="tabular-nums" style={{ color: sevMeta(f.severity).color }}>{s.toFixed(1)} {cvssRating(s)}</span>}
        </span>
      </div>
      <div className="mt-1.5 flex flex-wrap gap-1.5">
        {f.category?.cwe && <Pill label={f.category.cwe} color="#f472b6" />}
        {f.category?.owasp && <Pill label={`OWASP ${f.category.owasp}`} color="#60a5fa" />}
        <code className="rounded bg-card2 px-1.5 py-0.5 text-[11px] text-muted">{f.asset}</code>
      </div>
      {f.impact && <p className="mt-2 text-sm text-muted"><span className="font-medium text-fg">Impact. </span>{f.impact}</p>}
      {f.remediation && <p className="mt-1 text-sm text-muted"><span className="font-medium text-fg">Remediation. </span>{f.remediation}</p>}
    </div>
  );
}

function Meta({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-2">
      <span className="w-28 shrink-0 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</span>
      <span className="flex-1">{value}</span>
    </div>
  );
}

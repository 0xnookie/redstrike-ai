"use client";

import { useConsole } from "@/lib/store";
import { reportable, severityCounts, verificationStats } from "@/lib/stats";
import { SEVERITY, SEVERITY_ORDER } from "@/lib/theme";
import { PageHeader, Kpi } from "@/components/ui/primitives";
import { FindingsTable } from "@/components/findings/FindingsTable";

export default function FindingsPage() {
  const { findings, openFinding, findingsQuery } = useConsole();

  const rep = reportable(findings);
  const counts = severityCounts(rep);
  const v = verificationStats(findings.filter((f) => !f.composite));

  return (
    <>
      <PageHeader title="Findings" subtitle="Verified findings across the engagement — click a row for the full write-up." />

      <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-7">
        <Kpi label="Reportable" value={rep.length} />
        {SEVERITY_ORDER.map((k) => (
          <Kpi key={k} label={SEVERITY[k].label} value={counts[k]} color={SEVERITY[k].color} />
        ))}
        <Kpi label="Rejected" value={v.rejected} sub="excluded" />
      </div>

      <FindingsTable key={findingsQuery} findings={findings} onSelect={openFinding} initialQuery={findingsQuery} />
    </>
  );
}

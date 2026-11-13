"use client";

import { useMemo, useState } from "react";
import { Download, Search } from "lucide-react";
import { useConsole } from "@/lib/store";
import { useToast } from "@/components/ui/Toast";
import { reportable, severityCounts } from "@/lib/stats";
import { SEVERITY, SEVERITY_ORDER, sevMeta, hexA } from "@/lib/theme";
import { cvssScore } from "@/lib/cvss";
import { cx, verdictOf } from "@/lib/format";
import type { Severity } from "@/lib/types";
import { ViewHead, Panel, Select } from "@/components/ui/primitives";
import { FindingsTable } from "@/components/findings/FindingsTable";

const VERDICT_OPTS: { value: string; label: string }[] = [
  { value: "all", label: "All statuses" },
  { value: "accepted", label: "Accepted" },
  { value: "blocked", label: "Demonstration-limited" },
  { value: "needs-evidence", label: "Needs evidence" },
  { value: "rejected", label: "Rejected" },
];

export default function FindingsPage() {
  const { findings, openFinding, findingsQuery, setFindingsQuery, freshFindingIds } = useConsole();
  const toast = useToast();
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [validatedOnly, setValidatedOnly] = useState(false);

  // header summary — engagement-wide, not filter-scoped (mirrors the mockup's fSub)
  const rep = reportable(findings);
  const counts = severityCounts(rep);
  const withProof = rep.filter((f) => (f.evidence?.length ?? 0) > 0).length;

  const toggleSev = (k: Severity) =>
    setSevFilter((prev) => {
      const next = new Set(prev);
      next.has(k) ? next.delete(k) : next.add(k);
      if (next.size === SEVERITY_ORDER.length) next.clear(); // all selected === no filter
      return next;
    });

  // one pass: status(verdict) + validated + search → base (drives chip counts),
  // then severity → rows (sorted by severity, then CVSS, like the mockup).
  const { rows, base } = useMemo(() => {
    const q = findingsQuery.trim().toLowerCase();
    const base = findings
      .filter((f) => !f.composite)
      .filter((f) => verdictFilter === "all" || verdictOf(f) === verdictFilter)
      .filter((f) => !validatedOnly || verdictOf(f) === "accepted")
      .filter((f) =>
        !q ||
        [f.id, f.title, f.asset, f.category?.cwe, f.category?.owasp, (f.attack_mapping || []).join(" ")]
          .join(" ").toLowerCase().includes(q),
      );
    const rows = (sevFilter.size ? base.filter((f) => sevFilter.has(f.severity)) : base)
      .slice()
      .sort((a, b) => sevMeta(b.severity).rank - sevMeta(a.severity).rank || (cvssScore(b.cvss_vector) ?? -1) - (cvssScore(a.cvss_vector) ?? -1));
    return { rows, base };
  }, [findings, findingsQuery, verdictFilter, validatedOnly, sevFilter]);

  const chipCounts = useMemo(() => severityCounts(base), [base]);
  const total = useMemo(() => findings.filter((f) => !f.composite).length, [findings]);

  const exportCsv = () => {
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = ["id,title,severity,cvss,category,asset,status,found"];
    rows.forEach((f) => {
      const s = cvssScore(f.cvss_vector);
      lines.push(
        [f.id, f.title, f.severity, s === null ? "" : s.toFixed(1), f.category?.cwe || f.category?.owasp || "", f.asset, verdictOf(f) || "", f.review?.reviewed_at || ""]
          .map(esc).join(","),
      );
    });
    const url = URL.createObjectURL(new Blob([lines.join("\n")], { type: "text/csv;charset=utf-8" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "findings.csv";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    toast(`Exported ${rows.length} finding${rows.length === 1 ? "" : "s"} to findings.csv`);
  };

  return (
    <>
      <ViewHead
        crumb="redstrike / findings"
        title="Findings"
        sub={`${rep.length} reportable · ${counts.critical} critical · ${withProof} validated with proof`}
        actions={
          <button
            onClick={exportCsv}
            className="inline-flex h-9 items-center gap-2 rounded-full border border-line px-3.5 text-sm font-medium text-fg transition hover:border-fg/30"
          >
            <Download size={15} /> Export CSV
          </button>
        }
      />

      {/* filters: severity chips · status · validated toggle · search (right) */}
      <div className="flex flex-wrap items-center gap-2">
        <div className="flex flex-wrap items-center gap-1.5">
          {SEVERITY_ORDER.map((k) => (
            <SevChip key={k} active={sevFilter.has(k)} onClick={() => toggleSev(k)} label={SEVERITY[k].label} color={SEVERITY[k].color} count={chipCounts[k]} />
          ))}
        </div>
        <div className="ml-auto flex flex-wrap items-center gap-2">
          <Select value={verdictFilter} onChange={(e) => setVerdictFilter(e.target.value)} aria-label="Status">
            {VERDICT_OPTS.map((o) => <option key={o.value} value={o.value}>{o.label}</option>)}
          </Select>
          <Toggle checked={validatedOnly} onChange={setValidatedOnly} label="Validated only" />
          <div className="relative">
            <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={findingsQuery}
              onChange={(e) => setFindingsQuery(e.target.value)}
              type="search"
              placeholder="Search title, asset, CWE…"
              aria-label="Search findings"
              className="h-9 w-56 rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40"
            />
          </div>
        </div>
      </div>

      <Panel tall className="mt-5">
        <FindingsTable rows={rows} onSelect={openFinding} fresh={freshFindingIds} />
        <div className="mt-auto flex items-center justify-between border-t border-line px-5 py-3 font-mono text-[11px] text-faint">
          <span>Showing {rows.length} of {total} findings</span>
          <span>{rows.filter((f) => (f.evidence?.length ?? 0) > 0).length} with proof</span>
        </div>
      </Panel>
    </>
  );
}

/* severity filter chip — data-colored (toggle), with a live count */
function SevChip({ active, onClick, label, color, count }: { active: boolean; onClick: () => void; label: string; color: string; count: number }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition"
      style={
        active
          ? { color, borderColor: hexA(color, "66"), background: hexA(color, "1a") }
          : { color: "rgb(var(--muted))", borderColor: "rgb(var(--line))", background: "transparent" }
      }
    >
      <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />
      {label}
      <span className="font-mono text-[11px] text-faint">{count}</span>
    </button>
  );
}

/* chrome toggle switch (theme-aware tokens only) */
function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={checked}
      onClick={() => onChange(!checked)}
      className={cx(
        "inline-flex h-9 items-center gap-2 rounded-full border border-line bg-card2 px-3 text-sm transition",
        checked ? "text-fg-strong" : "text-muted hover:text-fg",
      )}
    >
      <span className={cx("relative h-4 w-7 rounded-full transition-colors", checked ? "bg-brand" : "bg-fg/20")}>
        <span className={cx("absolute top-0.5 h-3 w-3 rounded-full transition-all", checked ? "left-[14px] bg-brand-fg" : "left-0.5 bg-fg-strong")} />
      </span>
      {label}
    </button>
  );
}

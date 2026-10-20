"use client";

import { useMemo, useState } from "react";
import { ChevronDown, Search } from "lucide-react";
import type { Finding, Severity } from "@/lib/types";
import { cvssScore } from "@/lib/cvss";
import { SEVERITY, SEVERITY_ORDER, VERDICT, sevMeta, CONFIDENCE, hexA } from "@/lib/theme";
import { cx, verdictOf } from "@/lib/format";
import { Pill, SeverityBadge } from "@/components/ui/primitives";

type SortKey = "id" | "severity" | "title" | "asset" | "cvss" | "category" | "confidence" | "verdict";

const COLUMNS: { key: SortKey; label: string }[] = [
  { key: "id", label: "ID" },
  { key: "severity", label: "Severity" },
  { key: "title", label: "Title" },
  { key: "asset", label: "Asset" },
  { key: "cvss", label: "CVSS" },
  { key: "category", label: "Category" },
  { key: "confidence", label: "Confidence" },
  { key: "verdict", label: "Verdict" },
];

export function FindingsTable({ findings, onSelect }: { findings: Finding[]; onSelect: (f: Finding) => void }) {
  const [sevFilter, setSevFilter] = useState<Set<Severity>>(new Set());
  const [verdictFilter, setVerdictFilter] = useState<string>("all");
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("cvss");
  const [sortDir, setSortDir] = useState<1 | -1>(-1);

  const toggleSev = (k: Severity) => {
    setSevFilter((prev) => {
      const next = new Set(prev);
      next.has(k) ? next.delete(k) : next.add(k);
      if (next.size === SEVERITY_ORDER.length) next.clear();
      return next;
    });
  };

  const rows = useMemo(() => {
    const q = query.trim().toLowerCase();
    let list = findings.filter((f) => !f.composite);
    if (sevFilter.size) list = list.filter((f) => sevFilter.has(f.severity));
    if (verdictFilter !== "all") list = list.filter((f) => verdictOf(f) === verdictFilter);
    if (q)
      list = list.filter((f) =>
        [f.id, f.title, f.asset, f.category?.cwe, f.category?.owasp, (f.attack_mapping || []).join(" ")]
          .join(" ").toLowerCase().includes(q)
      );
    const val = (f: Finding): string | number => {
      switch (sortKey) {
        case "severity": return sevMeta(f.severity).rank;
        case "cvss": return cvssScore(f.cvss_vector) ?? -1;
        case "category": return f.category?.cwe || f.category?.owasp || "";
        case "confidence": return { confirmed: 3, probable: 2, tentative: 1 }[f.confidence] || 0;
        case "verdict": return verdictOf(f);
        default: return (f[sortKey] as string) || "";
      }
    };
    return [...list].sort((a, b) => {
      const va = val(a), vb = val(b);
      const c = typeof va === "number" && typeof vb === "number" ? va - vb : String(va).localeCompare(String(vb));
      return sortDir * c;
    });
  }, [findings, sevFilter, verdictFilter, query, sortKey, sortDir]);

  const onHeader = (k: SortKey) => {
    if (sortKey === k) setSortDir((d) => (d === 1 ? -1 : 1));
    else { setSortKey(k); setSortDir(k === "cvss" || k === "severity" || k === "confidence" ? -1 : 1); }
  };

  return (
    <div className="rounded-xl border border-line bg-card shadow-card">
      {/* filter bar */}
      <div className="flex flex-col gap-3 border-b border-line p-3 md:flex-row md:items-center md:justify-between">
        <div className="flex flex-wrap items-center gap-1.5">
          <Chip active={sevFilter.size === 0} onClick={() => setSevFilter(new Set())} label="All" />
          {SEVERITY_ORDER.map((k) => (
            <Chip key={k} active={sevFilter.has(k)} onClick={() => toggleSev(k)} label={SEVERITY[k].label} color={SEVERITY[k].color} />
          ))}
        </div>
        <div className="flex items-center gap-2">
          <div className="relative">
            <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-muted" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search…"
              className="h-8 w-44 rounded-lg border border-line bg-card2 pl-8 pr-2 text-sm outline-none placeholder:text-muted focus:border-brand/50"
            />
          </div>
          <div className="relative">
            <select
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
              className="h-8 appearance-none rounded-lg border border-line bg-card2 pl-2.5 pr-7 text-sm outline-none focus:border-brand/50"
            >
              <option value="all">All verdicts</option>
              {Object.entries(VERDICT).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
            </select>
            <ChevronDown size={14} className="pointer-events-none absolute right-2 top-1/2 -translate-y-1/2 text-muted" />
          </div>
          <span className="hidden whitespace-nowrap text-xs text-muted sm:inline">{rows.length} shown</span>
        </div>
      </div>

      {/* table */}
      <div className="scroll-thin overflow-x-auto">
        <table className="w-full border-collapse text-sm">
          <thead>
            <tr className="text-left text-xs text-muted">
              {COLUMNS.map((c) => (
                <th key={c.key} onClick={() => onHeader(c.key)} className="cursor-pointer select-none px-4 py-2.5 font-medium hover:text-fg">
                  <span className="inline-flex items-center gap-1">
                    {c.label}
                    {sortKey === c.key && <span className="text-brand">{sortDir === 1 ? "↑" : "↓"}</span>}
                  </span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((f) => {
              const score = cvssScore(f.cvss_vector);
              const v = verdictOf(f);
              const cat = f.category?.cwe || f.category?.owasp || "—";
              const c = CONFIDENCE[f.confidence];
              return (
                <tr
                  key={f.id}
                  onClick={() => onSelect(f)}
                  className={cx("cursor-pointer border-t border-line transition hover:bg-card2", v === "rejected" && "opacity-50")}
                >
                  <td className="whitespace-nowrap px-4 py-3 font-mono text-xs">{f.id}</td>
                  <td className="px-4 py-3"><SeverityBadge severity={f.severity} /></td>
                  <td className="max-w-xs px-4 py-3"><div className="font-medium leading-tight">{f.title}</div></td>
                  <td className="px-4 py-3"><code className="text-xs text-muted">{f.asset}</code></td>
                  <td className="whitespace-nowrap px-4 py-3 tabular-nums">
                    {score === null ? <span className="text-muted">—</span> : <span style={{ color: sevMeta(f.severity).color }}>{score.toFixed(1)}</span>}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-xs text-muted">{cat}</td>
                  <td className="px-4 py-3">{c && <Pill label={c.label} color={c.color} />}</td>
                  <td className="px-4 py-3">{v ? <Pill label={VERDICT[v].label} color={VERDICT[v].color} dot /> : <span className="text-xs text-muted">—</span>}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
        {rows.length === 0 && <div className="py-12 text-center text-sm text-muted">No findings match the current filters.</div>}
      </div>
    </div>
  );
}

function Chip({ active, onClick, label, color }: { active: boolean; onClick: () => void; label: string; color?: string }) {
  return (
    <button
      onClick={onClick}
      className="inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium transition"
      style={
        active
          ? color
            ? { color, borderColor: hexA(color, "66"), background: hexA(color, "1a") }
            : { color: "rgb(var(--fg))", borderColor: "rgb(var(--fg) / 0.35)", background: "rgb(var(--fg) / 0.08)" }
          : { color: "rgb(var(--muted))", borderColor: "rgb(var(--line))", background: "transparent" }
      }
    >
      {color && <span className="h-1.5 w-1.5 rounded-full" style={{ background: color }} />}
      {label}
    </button>
  );
}

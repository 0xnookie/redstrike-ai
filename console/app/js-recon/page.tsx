"use client";

import { useMemo, useState } from "react";
import {
  Globe, SlidersHorizontal, Boxes, KeyRound, Crosshair, Library, FileText, Code2,
} from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx } from "@/lib/format";
import { SEVERITY, hexA } from "@/lib/theme";
import {
  ViewHead, Kpi, Panel, PanelHeader, PanelBody, EmptyState, Pill, Select,
} from "@/components/ui/primitives";
import type {
  JsReconSite, JsEndpoint, JsParam, JsApi, JsSecret, JsGadget, JsLibrary,
} from "@/lib/types";

type Stream = "endpoints" | "params" | "apis" | "secrets" | "gadgets" | "libraries";
type Tab = Stream | "summary";

const TABS: { id: Tab; label: string; icon: typeof Globe }[] = [
  { id: "endpoints", label: "Endpoints", icon: Globe },
  { id: "params", label: "Params", icon: SlidersHorizontal },
  { id: "apis", label: "APIs", icon: Boxes },
  { id: "secrets", label: "Secrets", icon: KeyRound },
  { id: "gadgets", label: "Gadgets", icon: Crosshair },
  { id: "libraries", label: "Libraries", icon: Library },
  { id: "summary", label: "Summary", icon: FileText },
];

const STREAMS: Stream[] = ["endpoints", "params", "apis", "secrets", "gadgets", "libraries"];

/* color for a free-form severity-ish string, else neutral slate */
function sevColor(s?: string): string {
  const k = (s || "").toLowerCase();
  return (SEVERITY as Record<string, { color: string }>)[k]?.color ?? "#94a3b8";
}

/* state -> color for an endpoint's reachability */
function stateColor(s?: string): string {
  switch ((s || "").toLowerCase()) {
    case "live": return "#22c55e";
    case "unauthed": return "#f59e0b";
    case "historical": return "#94a3b8";
    default: return "#60a5fa";
  }
}

/** "file.js:120" from a row's source_file + line. */
function Src({ file, line }: { file?: string; line?: number }) {
  if (!file) return <span className="text-faint">—</span>;
  return (
    <span className="font-mono text-[11px] text-faint" title={line != null ? `${file}:${line}` : file}>
      {file}{line != null ? <span className="text-muted">:{line}</span> : null}
    </span>
  );
}

function Th({ children, className }: { children?: React.ReactNode; className?: string }) {
  return <th className={cx("whitespace-nowrap px-3 py-2 text-left font-medium", className)}>{children}</th>;
}
function Td({ children, className }: { children?: React.ReactNode; className?: string }) {
  return <td className={cx("px-3 py-2 align-top", className)}>{children}</td>;
}

function Table({ head, children }: { head: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="scroll-thin overflow-x-auto">
      <table className="w-full border-collapse text-sm">
        <thead className="border-b border-line text-[11px] uppercase tracking-wider text-muted">
          <tr>{head}</tr>
        </thead>
        <tbody className="divide-y divide-line/60">{children}</tbody>
      </table>
    </div>
  );
}

export default function JsReconPage() {
  const { jsRecon, jsFiles } = useConsole();
  const [tab, setTab] = useState<Tab>("endpoints");
  const [siteIdx, setSiteIdx] = useState(0);

  const sites = jsRecon?.sites ?? [];
  const site: JsReconSite | undefined = sites[Math.min(siteIdx, Math.max(0, sites.length - 1))];

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const s of STREAMS) c[s] = site?.counts?.[s] ?? (site?.[s] as unknown[] | undefined)?.length ?? 0;
    return c;
  }, [site]);

  if (!jsRecon || sites.length === 0 || !site) {
    return (
      <>
        <ViewHead
          crumb="redstrike / js-recon"
          title="JS Recon"
          sub="Client-side JavaScript intelligence — endpoints, params, APIs, secrets, sinks and libraries mined from the target's JS."
        />
        <Panel>
          <PanelBody>
            <EmptyState
              icon={<Code2 size={30} />}
              title="No JS recon yet"
              hint="Run the js-analysis skill for this engagement. Its findings/*.jsonl + site-summary land under the engagement's js-analysis/ dir and surface here automatically."
            />
          </PanelBody>
        </Panel>
      </>
    );
  }

  const kpiFor: { id: Tab; label: string; icon: typeof Globe; color?: string }[] = [
    { id: "endpoints", label: "Endpoints", icon: Globe },
    { id: "params", label: "Params", icon: SlidersHorizontal },
    { id: "apis", label: "APIs", icon: Boxes },
    { id: "secrets", label: "Secrets", icon: KeyRound, color: counts.secrets ? "#f59e0b" : undefined },
    { id: "gadgets", label: "Gadgets", icon: Crosshair, color: counts.gadgets ? "#f87171" : undefined },
    { id: "libraries", label: "Libraries", icon: Library },
  ];

  return (
    <>
      <ViewHead
        crumb="redstrike / js-recon"
        title="JS Recon"
        live
        sub={`${jsFiles.length} file${jsFiles.length === 1 ? "" : "s"} analyzed · ${sites.length} site${sites.length === 1 ? "" : "s"}`}
        actions={
          sites.length > 1 ? (
            <Select value={String(siteIdx)} onChange={(e) => setSiteIdx(Number(e.target.value))}>
              {sites.map((s, i) => (
                <option key={s.site} value={i}>{s.site}</option>
              ))}
            </Select>
          ) : (
            <span className="font-mono text-xs text-faint">{site.site}</span>
          )
        }
      />

      {/* KPI row — click to jump to the matching tab */}
      <div className="mb-4 grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
        {kpiFor.map((k) => (
          <Kpi
            key={k.id}
            label={k.label}
            value={counts[k.id] ?? 0}
            icon={<k.icon size={16} />}
            color={k.color}
            onClick={() => setTab(k.id)}
            active={tab === k.id}
            note={site.truncated?.[k.id] ? "capped" : undefined}
          />
        ))}
      </div>

      {/* tab bar */}
      <div className="scroll-thin mb-3 flex gap-1.5 overflow-x-auto pb-1">
        {TABS.map((t) => {
          const active = tab === t.id;
          const n = t.id === "summary" ? undefined : counts[t.id];
          return (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={cx(
                "inline-flex shrink-0 items-center gap-1.5 rounded-full border px-3 py-1.5 text-sm transition",
                active ? "border-brand/50 bg-brand/10 font-medium text-brand" : "border-line text-muted hover:text-fg",
              )}
            >
              <t.icon size={14} />
              {t.label}
              {n != null && n > 0 && <span className="font-mono text-[11px] tabular-nums opacity-70">{n}</span>}
            </button>
          );
        })}
      </div>

      <Panel>
        <PanelHeader
          title={TABS.find((t) => t.id === tab)!.label}
          sub={site.site}
          actions={
            tab !== "summary" && site.truncated?.[tab] ? (
              <Pill label={`first ${(site[tab] as unknown[] | undefined)?.length ?? 0} of ${counts[tab]}`} color="#f59e0b" />
            ) : undefined
          }
        />
        <PanelBody flush>
          <TabBody tab={tab} site={site} />
        </PanelBody>
      </Panel>
    </>
  );
}

function TabBody({ tab, site }: { tab: Tab; site: JsReconSite }) {
  if (tab === "summary") {
    if (!site.summary_md) {
      return <EmptyState title="No site summary" hint={site.has_report ? "A report.md exists but no analysis/site-summary.md was written for this site." : "The js-analysis run didn't emit analysis/site-summary.md for this site."} />;
    }
    return (
      <div className="p-4">
        {site.has_report && <div className="mb-3"><Pill label="report.md present" color="#22c55e" dot /></div>}
        <pre className="scroll-thin max-h-[70vh] overflow-auto whitespace-pre-wrap break-words font-mono text-[12.5px] leading-relaxed text-fg">{site.summary_md}</pre>
      </div>
    );
  }

  const rows = (site[tab] as unknown[] | undefined) ?? [];
  if (rows.length === 0) {
    return <EmptyState title={`No ${tab} found`} hint="This stream was empty (or not produced) for this site." />;
  }

  if (tab === "endpoints") {
    return (
      <Table head={<><Th className="w-[48%]">URL</Th><Th>Method</Th><Th>State</Th><Th>Kind</Th><Th>Source</Th></>}>
        {(rows as JsEndpoint[]).map((r, i) => (
          <tr key={i} className="hover:bg-card2/50">
            <Td><span className="break-all font-mono text-[12.5px] text-fg">{r.url}</span>{r.guard ? <span className="ml-2 text-[11px] text-faint">guard: {r.guard}</span> : null}</Td>
            <Td><span className="font-mono text-xs text-muted">{r.method || "GET"}</span></Td>
            <Td>{r.state ? <Pill label={r.state} color={stateColor(r.state)} /> : <span className="text-faint">—</span>}</Td>
            <Td><span className="text-xs text-muted">{r.kind || "—"}</span></Td>
            <Td><Src file={r.source_file} line={r.line} /></Td>
          </tr>
        ))}
      </Table>
    );
  }

  if (tab === "params") {
    return (
      <Table head={<><Th>Name</Th><Th>Kind</Th><Th>Context</Th><Th>Flag</Th><Th>Source</Th></>}>
        {(rows as JsParam[]).map((r, i) => (
          <tr key={i} className="hover:bg-card2/50">
            <Td><span className="font-mono text-[12.5px] text-fg">{r.name}</span></Td>
            <Td><span className="text-xs text-muted">{r.kind || "query"}</span></Td>
            <Td><span className="break-all text-xs text-muted">{r.context || "—"}</span></Td>
            <Td>{r.likely_vuln ? <Pill label="likely vuln" color="#f59e0b" /> : <span className="text-faint">—</span>}</Td>
            <Td><Src file={r.source_file} line={r.line} /></Td>
          </tr>
        ))}
      </Table>
    );
  }

  if (tab === "apis") {
    return (
      <Table head={<><Th className="w-[46%]">Path</Th><Th>Group</Th><Th>Version</Th><Th>Method</Th><Th>Source</Th></>}>
        {(rows as JsApi[]).map((r, i) => (
          <tr key={i} className="hover:bg-card2/50">
            <Td><span className="break-all font-mono text-[12.5px] text-fg">{r.path}</span></Td>
            <Td><span className="text-xs text-muted">{r.group || "—"}</span></Td>
            <Td>{r.version ? <Pill label={r.version} color="#60a5fa" /> : <span className="text-faint">—</span>}</Td>
            <Td><span className="font-mono text-xs text-muted">{r.method || "—"}</span></Td>
            <Td><Src file={r.source_file} /></Td>
          </tr>
        ))}
      </Table>
    );
  }

  if (tab === "secrets") {
    return (
      <Table head={<><Th>Type</Th><Th>Value (redacted)</Th><Th>Severity</Th><Th>Source</Th></>}>
        {(rows as JsSecret[]).map((r, i) => (
          <tr key={i} className="hover:bg-card2/50">
            <Td><span className="text-sm text-fg">{r.type}</span>{r.provider_meta ? <div className="text-[11px] text-faint">{r.provider_meta}</div> : null}</Td>
            <Td><span className="break-all font-mono text-[12px] text-muted">{r.match_redacted || "‹redacted›"}</span>{r.entropy != null ? <span className="ml-2 text-[11px] text-faint">H={r.entropy.toFixed(1)}</span> : null}</Td>
            <Td>{r.severity ? <Pill label={r.severity} color={sevColor(r.severity)} dot /> : <span className="text-faint">—</span>}</Td>
            <Td><Src file={r.source_file} line={r.line} /></Td>
          </tr>
        ))}
      </Table>
    );
  }

  if (tab === "gadgets") {
    return (
      <Table head={<><Th>Sink</Th><Th>Category</Th><Th>Origin check</Th><Th className="w-[34%]">Snippet</Th><Th>Source</Th></>}>
        {(rows as JsGadget[]).map((r, i) => (
          <tr key={i} className="hover:bg-card2/50">
            <Td><span className="font-mono text-[12.5px] text-fg">{r.sink}</span></Td>
            <Td><span className="text-xs text-muted">{r.category || "—"}</span></Td>
            <Td>{r.origin_check ? <span className="text-xs text-muted">{r.origin_check}</span> : <span className="text-faint">—</span>}</Td>
            <Td><span className="break-all font-mono text-[11px] text-faint">{r.snippet || "—"}</span></Td>
            <Td><Src file={r.source_file} line={r.line} /></Td>
          </tr>
        ))}
      </Table>
    );
  }

  // libraries
  return (
    <Table head={<><Th>Library</Th><Th>Version</Th><Th>CVEs</Th><Th>Source</Th></>}>
      {(rows as JsLibrary[]).map((r, i) => {
        const cves = r.cves ?? [];
        return (
          <tr key={i} className="hover:bg-card2/50">
            <Td><span className="text-sm text-fg">{r.name}</span></Td>
            <Td><span className="font-mono text-xs text-muted">{r.version || "—"}</span></Td>
            <Td>
              {cves.length ? (
                <div className="flex flex-wrap gap-1">
                  {cves.slice(0, 6).map((c) => (
                    <span key={c} className="rounded px-1.5 py-0.5 font-mono text-[11px]" style={{ color: "#f87171", background: hexA("#f87171", "1f") }}>{c}</span>
                  ))}
                  {cves.length > 6 && <span className="text-[11px] text-faint">+{cves.length - 6}</span>}
                </div>
              ) : <span className="text-faint">—</span>}
            </Td>
            <Td><Src file={r.source_file} /></Td>
          </tr>
        );
      })}
    </Table>
  );
}

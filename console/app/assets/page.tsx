"use client";

import { useMemo, useState } from "react";
import { Network, Globe, Server, Link2, Boxes } from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx, fmtDate } from "@/lib/format";
import type { Asset, AssetKind } from "@/lib/types";
import { Card, PageHeader, Kpi, Pill } from "@/components/ui/primitives";
import { Progress } from "@/components/ui/charts";
import { AssetMap } from "@/components/AssetMap";
import { COVERAGE } from "@/lib/theme";

const KIND_LABEL: Record<AssetKind, string> = {
  domain: "Domain", subdomain: "Subdomain", ip: "IP", cidr: "CIDR", service: "Service", endpoint: "Endpoint",
};

export default function AssetsPage() {
  const { activeEngagement: eng, assets } = useConsole();
  const [kind, setKind] = useState<AssetKind | "all">("all");

  const kinds = useMemo(() => Array.from(new Set(assets.map((a) => a.kind))), [assets]);
  const shown = assets.filter((a) => kind === "all" || a.kind === kind);

  const inScope = assets.filter((a) => a.scope === "in");
  const tested = inScope.filter((a) => a.coverage === "tested").length;
  const cov = {
    tested: assets.filter((a) => a.coverage === "tested").length,
    "in-progress": assets.filter((a) => a.coverage === "in-progress").length,
    untested: assets.filter((a) => a.coverage === "untested").length,
  };

  const scopeList = (arr: string[], color: string) =>
    arr.length ? arr.map((d) => <Pill key={d} label={d} color={color} dot />) : <span className="text-xs text-muted">—</span>;

  return (
    <>
      <PageHeader title="Assets & scope" subtitle={`${eng.name} · authorization window ${fmtDate(eng.window.start)} → ${fmtDate(eng.window.end)}`} />

      <div className="mb-3 grid grid-cols-2 gap-3 sm:grid-cols-4">
        <Kpi label="Assets" value={assets.length} icon={<Network size={15} />} />
        <Kpi label="In scope" value={inScope.length} />
        <Kpi label="Coverage" value={`${Math.round((tested / Math.max(1, inScope.length)) * 100)}%`} sub={`${tested}/${inScope.length} tested`} />
        <Kpi label="Rate limit" value={`${eng.rules.rate_limit_rps ?? "—"}`} sub="rps" />
      </div>

      {/* asset coverage map */}
      <div className="mb-3">
        <AssetMap assets={assets} orgName={eng.target} />
      </div>

      {/* scope + coverage */}
      <div className="mb-3 grid grid-cols-1 gap-3 lg:grid-cols-3">
        <Card className="p-4 lg:col-span-2">
          <h2 className="mb-3 text-sm font-semibold">Scope</h2>
          <div className="space-y-3 text-sm">
            <ScopeRow label="In-scope domains">{scopeList(eng.in_scope.domains, "#22c55e")}</ScopeRow>
            {eng.in_scope.cidrs.length > 0 && <ScopeRow label="In-scope CIDRs">{scopeList(eng.in_scope.cidrs, "#22c55e")}</ScopeRow>}
            <ScopeRow label="Out-of-scope">{scopeList([...eng.out_of_scope.domains, ...eng.out_of_scope.cidrs], "#ef4444")}</ScopeRow>
          </div>
          <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-3 text-[11px] text-muted">
            {eng.rules.no_dos && <span className="rounded-md bg-card2 px-2 py-1">No DoS</span>}
            {eng.rules.no_destructive && <span className="rounded-md bg-card2 px-2 py-1">No destructive actions</span>}
            {eng.rules.prod_touch_requires_approval && <span className="rounded-md bg-card2 px-2 py-1">Prod touch needs approval</span>}
            {(eng.rules.approval_required_phases || []).map((p) => (
              <span key={p} className="rounded-md bg-amber-500/10 px-2 py-1 font-medium text-amber-500">{p} gated</span>
            ))}
          </div>
        </Card>

        <Card className="p-4">
          <h2 className="mb-3 text-sm font-semibold">Coverage</h2>
          <div className="space-y-3">
            {(Object.keys(COVERAGE) as (keyof typeof COVERAGE)[]).map((k) => (
              <div key={k}>
                <div className="mb-1 flex items-center justify-between text-xs">
                  <span className="flex items-center gap-2"><span className="h-2 w-2 rounded-full" style={{ background: COVERAGE[k].color }} />{COVERAGE[k].label}</span>
                  <span className="tabular-nums text-muted">{cov[k]}</span>
                </div>
                <Progress value={cov[k]} max={assets.length} color={COVERAGE[k].color} />
              </div>
            ))}
          </div>
        </Card>
      </div>

      {/* kind filter */}
      <div className="mb-3 flex flex-wrap items-center gap-1.5">
        <Chip active={kind === "all"} onClick={() => setKind("all")} label={`All (${assets.length})`} />
        {kinds.map((k) => (
          <Chip key={k} active={kind === k} onClick={() => setKind(k)} label={`${KIND_LABEL[k]} (${assets.filter((a) => a.kind === k).length})`} />
        ))}
      </div>

      {/* asset table */}
      <Card>
        <div className="scroll-thin overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="text-left text-xs text-muted">
                <th className="px-4 py-2.5 font-medium">Asset</th>
                <th className="px-4 py-2.5 font-medium">Type</th>
                <th className="px-4 py-2.5 font-medium">Scope</th>
                <th className="px-4 py-2.5 font-medium">Coverage</th>
                <th className="px-4 py-2.5 font-medium">Findings</th>
                <th className="px-4 py-2.5 font-medium">Tech</th>
              </tr>
            </thead>
            <tbody>
              {shown.map((a) => (
                <AssetRow key={a.id} asset={a} />
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </>
  );
}

function AssetRow({ asset: a }: { asset: Asset }) {
  const c = COVERAGE[a.coverage];
  const kindIcon =
    a.kind === "domain" || a.kind === "subdomain" ? <Globe size={14} /> :
    a.kind === "ip" || a.kind === "cidr" ? <Server size={14} /> :
    a.kind === "endpoint" ? <Link2 size={14} /> : <Boxes size={14} />;
  return (
    <tr className={cx("border-t border-line", a.scope === "out" && "opacity-55")}>
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="text-muted">{kindIcon}</span>
          <code className="text-xs">{a.value}</code>
        </div>
      </td>
      <td className="px-4 py-3 text-xs text-muted">{KIND_LABEL[a.kind]}</td>
      <td className="px-4 py-3">
        <Pill label={a.scope === "in" ? "In scope" : "Out of scope"} color={a.scope === "in" ? "#22c55e" : "#ef4444"} dot />
      </td>
      <td className="px-4 py-3"><Pill label={c.label} color={c.color} dot /></td>
      <td className="px-4 py-3 tabular-nums">{a.findings || <span className="text-muted">0</span>}</td>
      <td className="px-4 py-3">
        <div className="flex flex-wrap gap-1">
          {(a.tech || []).map((t) => <span key={t} className="rounded bg-card2 px-1.5 py-0.5 text-[11px] text-muted">{t}</span>)}
        </div>
      </td>
    </tr>
  );
}

function ScopeRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex flex-col gap-1.5 sm:flex-row sm:items-start sm:gap-3">
      <span className="w-40 shrink-0 text-[11px] font-medium uppercase tracking-wide text-muted">{label}</span>
      <div className="flex flex-wrap gap-1.5">{children}</div>
    </div>
  );
}

function Chip({ active, onClick, label }: { active: boolean; onClick: () => void; label: string }) {
  return (
    <button onClick={onClick} className={cx("rounded-full border px-2.5 py-1 text-xs font-medium transition", active ? "border-brand/60 bg-brand/10 text-brand" : "border-line text-muted hover:text-fg")}>
      {label}
    </button>
  );
}

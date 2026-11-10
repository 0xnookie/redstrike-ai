"use client";

import { useMemo, useState } from "react";
import { useRouter } from "next/navigation";
import { Network, Globe, Server, Link2, Boxes, Radio, Search, X, ShieldCheck, ShieldAlert } from "lucide-react";
import { useConsole } from "@/lib/store";
import { cx, fmtDate, hostOf, isReportable, assetHosts } from "@/lib/format";
import type { Asset, AssetKind, Service, Severity } from "@/lib/types";
import { COVERAGE, SEVERITY } from "@/lib/theme";
import { Kpi, Pill, Dot, ViewHead, Panel, PanelHeader, PanelBody, Segmented } from "@/components/ui/primitives";
import { Progress } from "@/components/ui/charts";
import { AssetMap } from "@/components/AssetMap";
import { SubdomainMap } from "@/components/SubdomainMap";
import { buildSubdomainData } from "@/lib/subdomainMap";

const KIND_LABEL: Record<AssetKind, string> = {
  domain: "Domain", subdomain: "Subdomain", ip: "IP", cidr: "CIDR", service: "Service", endpoint: "Endpoint",
};

export default function AssetsPage() {
  const { activeEngagement: eng, assets, services, findings, notebook, setFindingsQuery, openHost, openEndpoint } = useConsole();
  const router = useRouter();
  const openHostFindings = (host: string) => { setFindingsQuery(host); router.push("/findings"); };
  // endpoint rows open the endpoint drawer; everything else opens the host drawer
  const openAsset = (a: Asset) => (a.kind === "endpoint" ? openEndpoint(a.value) : openHost(a.value));

  const [assetMode, setAssetMode] = useState<"inventory" | "map">("inventory");
  const [kind, setKind] = useState<AssetKind | "all">("all");
  const [assetQuery, setAssetQuery] = useState("");
  const [svcQuery, setSvcQuery] = useState("");
  const [proto, setProto] = useState<"all" | "tcp" | "udp">("all");
  const [hostFilter, setHostFilter] = useState<string | null>(null);
  // selecting a host both opens its detail drawer and scopes the ports table to it
  const selectHost = (host: string) => { setHostFilter(host); openHost(host); };

  const kinds = useMemo(() => Array.from(new Set(assets.map((a) => a.kind))), [assets]);

  // per-host worst finding severity → drives the risk bar + the risk sort
  const worstSevByHost = useMemo(() => {
    const m = new Map<string, Severity>();
    for (const f of findings) {
      if (f.composite) continue;
      const rank = SEVERITY[f.severity]?.rank ?? 0;
      for (const h of assetHosts(f.asset)) {
        const cur = m.get(h);
        if (!cur || rank > SEVERITY[cur].rank) m.set(h, f.severity);
      }
    }
    return m;
  }, [findings]);

  const sevOf = (a: Asset): Severity | null =>
    worstSevByHost.get(a.kind === "endpoint" ? hostOf(a.value) : a.value) ?? null;

  // asset table rows: kind tab + text filter, severity-ranked
  const rows = useMemo(() => {
    const q = assetQuery.trim().toLowerCase();
    return assets
      .filter((a) => kind === "all" || a.kind === kind)
      .filter((a) => !q || `${a.value} ${a.kind} ${(a.tech ?? []).join(" ")} ${a.server ?? ""} ${a.title ?? ""}`.toLowerCase().includes(q))
      .map((a) => ({ asset: a, sev: sevOf(a) }))
      .sort((x, y) => {
        const rx = x.sev ? SEVERITY[x.sev].rank : 0;
        const ry = y.sev ? SEVERITY[y.sev].rank : 0;
        return ry - rx || y.asset.findings - x.asset.findings || x.asset.value.localeCompare(y.asset.value);
      });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [assets, kind, assetQuery, worstSevByHost]);

  const inScope = assets.filter((a) => a.scope === "in");
  const tested = inScope.filter((a) => a.coverage === "tested").length;
  const withFindings = assets.filter((a) => a.findings > 0).length;
  const covPct = Math.round((tested / Math.max(1, inScope.length)) * 100);
  const cov = {
    tested: assets.filter((a) => a.coverage === "tested").length,
    "in-progress": assets.filter((a) => a.coverage === "in-progress").length,
    untested: assets.filter((a) => a.coverage === "untested").length,
  };

  const openPorts = services.filter((s) => s.state === "open").length;
  const hostCount = new Set(services.map((s) => s.host)).size;
  const shownSvcs = useMemo(() => {
    const q = svcQuery.trim().toLowerCase();
    return services
      .filter((s) => !hostFilter || s.host === hostFilter)
      .filter((s) => proto === "all" || (s.proto ?? "tcp") === proto)
      .filter((s) => !q || `${s.host} ${s.ip ?? ""} ${s.service} ${s.product ?? ""} ${s.port}`.toLowerCase().includes(q))
      .sort((a, b) => a.host.localeCompare(b.host) || a.port - b.port);
  }, [services, proto, svcQuery, hostFilter]);
  // reportable findings per host, so the ports table links to real findings in live mode too
  const findingsByHost = useMemo(() => {
    const m = new Map<string, number>();
    for (const f of findings) if (isReportable(f)) { const h = hostOf(f.asset); m.set(h, (m.get(h) ?? 0) + 1); }
    return m;
  }, [findings]);

  const tabs: { k: AssetKind | "all"; label: string; n: number }[] = [
    { k: "all", label: "All", n: assets.length },
    ...kinds.map((k) => ({ k, label: KIND_LABEL[k], n: assets.filter((a) => a.kind === k).length })),
  ];

  const scopeList = (arr: string[], color: string) =>
    arr.length ? arr.map((d) => <Pill key={d} label={d} color={color} dot />) : <span className="text-xs text-muted">—</span>;

  // subdomain-map data (notebook recon_intel + host-discovery assets), built once
  const mapData = useMemo(() => buildSubdomainData(notebook, assets, services, findings, eng), [notebook, assets, services, findings, eng]);
  const mapAnswering = mapData.records.filter((r) => r.http != null).length;
  const mapAuthWall = mapData.records.filter((r) => r.st === "auth").length;
  const mapTakeover = mapData.records.filter((r) => r.st === "takeover").length;
  const mapAnswerPct = mapData.records.length ? Math.round((mapAnswering / mapData.records.length) * 100) : 0;

  return (
    <>
      <ViewHead
        crumb="redstrike / assets"
        title="Assets"
        live={eng.status === "running"}
        sub={`${eng.name} · auth window ${fmtDate(eng.window.start)} → ${fmtDate(eng.window.end)} · ${inScope.length} in scope`}
        actions={
          <Segmented
            value={assetMode}
            onChange={setAssetMode}
            options={[
              { value: "inventory", label: "Inventory" },
              { value: "map", label: "Subdomain map" },
            ]}
          />
        }
      />

      {assetMode === "map" ? (
        <>
          {/* subdomain-map KPIs */}
          <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
            <Kpi label="Subdomains" value={mapData.records.length} icon={<Globe size={16} />} note={`under ${mapData.rootDomain}`} />
            <Kpi label="Answering HTTP" value={mapAnswering} icon={<Radio size={16} />} note={`${mapAnswerPct}% of hosts`} />
            <Kpi label="Login wall" value={mapAuthWall} icon={<ShieldCheck size={16} />} note="401 / 403 gated" />
            <Kpi label="Takeover risk" value={mapTakeover} color={mapTakeover ? SEVERITY.critical.color : undefined} icon={<ShieldAlert size={16} />} note={mapTakeover ? "dangling records" : "none found"} />
          </div>
          <div className="mt-5">
            {mapData.records.length ? (
              <SubdomainMap records={mapData.records} domains={mapData.domains} rootDomain={mapData.rootDomain} onSelectHost={openHost} />
            ) : (
              <Panel><div className="py-16 text-center text-sm text-muted">No subdomains discovered yet — run host-discovery or populate the notebook&apos;s recon intel.</div></Panel>
            )}
          </div>
        </>
      ) : (
      <>
      {/* KPI tiles */}
      <div className="grid grid-cols-2 gap-3.5 sm:grid-cols-4">
        <Kpi label="Assets" value={assets.length} icon={<Network size={16} />} note={`${inScope.length} in scope`} />
        <Kpi label="Open ports" value={openPorts} icon={<Radio size={16} />} note={`${hostCount} hosts`} />
        <Kpi label="Coverage" value={`${covPct}%`} icon={<ShieldCheck size={16} />} note={`${tested}/${inScope.length} tested`} />
        <Kpi label="With findings" value={withFindings} color={SEVERITY.high.color} icon={<ShieldAlert size={16} />} note="assets affected" />
      </div>

      {/* asset coverage map (signature feature — kept wired, click → scope + drawer) */}
      <Panel className="mt-5">
        <PanelHeader
          title="Coverage map"
          sub="host hierarchy · risk + coverage"
          actions={hostFilter ? <ActiveFilter host={hostFilter} onClear={() => setHostFilter(null)} /> : undefined}
        />
        <div className="px-3 pb-4 sm:px-4">
          <AssetMap assets={assets} orgName={eng.target} services={services} findings={findings} onSelectHost={selectHost} selectedHost={hostFilter ?? undefined} />
        </div>
      </Panel>

      {/* filters row: asset-type tabs (segmented) + search */}
      <div className="mt-5 flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div className="flex flex-wrap gap-1.5 rounded-full border border-line p-1">
          {tabs.map((t) => (
            <button
              key={t.k}
              onClick={() => setKind(t.k)}
              aria-pressed={kind === t.k}
              className={cx(
                "inline-flex items-center gap-2 rounded-full px-3 py-1.5 text-[13px] transition",
                kind === t.k ? "bg-card2 text-fg-strong" : "text-muted hover:text-fg",
              )}
            >
              {t.label}
              <span className="font-mono text-[11px] text-faint">{t.n}</span>
            </button>
          ))}
        </div>
        <label className="relative block lg:w-72">
          <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
          <input
            value={assetQuery}
            onChange={(e) => setAssetQuery(e.target.value)}
            placeholder="Search assets or tech…"
            className="h-9 w-full rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40"
          />
        </label>
      </div>

      {/* asset inventory table */}
      <Panel tall className="mt-3">
        <PanelHeader title="Inventory" sub={`${rows.length} of ${assets.length}`} />
        <div className="scroll-thin overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="px-5 py-3 font-medium">Asset</th>
                <th className="px-5 py-3 font-medium">Type</th>
                <th className="px-5 py-3 font-medium">Exposure</th>
                <th className="px-5 py-3 font-medium">Risk</th>
                <th className="px-5 py-3 font-medium">Open findings</th>
                <th className="px-5 py-3 font-medium">Coverage</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(({ asset, sev }) => (
                <AssetRow key={asset.id} asset={asset} sev={sev} onOpen={openAsset} />
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <div className="py-12 text-center text-sm text-muted">No assets match.</div>}
        </div>
      </Panel>

      {/* ports & services (from host discovery) — preserved, restyled */}
      <Panel className="mt-5">
        <div className="flex flex-col gap-3 px-[22px] pb-2 pt-[18px] sm:flex-row sm:items-center sm:justify-between">
          <div className="flex min-w-0 items-center gap-2.5">
            <span className="text-[15px] font-medium text-fg-strong">Ports &amp; services</span>
            <span className="font-mono text-xs text-faint">
              {hostFilter ? `${shownSvcs.length} port${shownSvcs.length === 1 ? "" : "s"} on ${hostFilter}` : `${openPorts} open · ${hostCount} hosts`}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            {hostFilter && <ActiveFilter host={hostFilter} onClear={() => setHostFilter(null)} />}
            <label className="relative block">
              <Search size={14} className="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-muted" />
              <input
                value={svcQuery}
                onChange={(e) => setSvcQuery(e.target.value)}
                placeholder="host / service / port"
                className="h-9 w-full rounded-full border border-line bg-card2 pl-9 pr-3 text-sm text-fg outline-none transition placeholder:text-muted focus:border-fg/40 sm:w-48"
              />
            </label>
            <Segmented
              value={proto}
              onChange={setProto}
              options={[
                { value: "all", label: "All" },
                { value: "tcp", label: "TCP" },
                { value: "udp", label: "UDP" },
              ]}
            />
          </div>
        </div>
        <div className="scroll-thin overflow-x-auto">
          <table className="w-full border-collapse text-sm">
            <thead>
              <tr className="border-b border-line text-left text-[11px] uppercase tracking-wider text-faint">
                <th className="px-5 py-3 font-medium">Host</th>
                <th className="px-5 py-3 font-medium">Port</th>
                <th className="px-5 py-3 font-medium">Service</th>
                <th className="px-5 py-3 font-medium">Product / version</th>
                <th className="px-5 py-3 font-medium">TLS</th>
                <th className="px-5 py-3 font-medium">State</th>
                <th className="px-5 py-3 font-medium">Note</th>
                <th className="px-5 py-3 font-medium">Findings</th>
              </tr>
            </thead>
            <tbody>
              {shownSvcs.map((s) => <ServiceRow key={s.id} svc={s} count={findingsByHost.get(s.host) ?? s.findings ?? 0} onFindings={openHostFindings} />)}
            </tbody>
          </table>
          {shownSvcs.length === 0 && <div className="py-12 text-center text-sm text-muted">No ports match.</div>}
        </div>
      </Panel>

      {/* scope + rules + coverage distribution */}
      <div className="mt-5 grid grid-cols-1 gap-5 lg:grid-cols-3">
        <Panel className="lg:col-span-2">
          <PanelHeader title="Scope & rules" sub={eng.target} />
          <PanelBody>
            <div className="space-y-3 text-sm">
              <ScopeRow label="In-scope domains">{scopeList(eng.in_scope.domains, "#22c55e")}</ScopeRow>
              {eng.in_scope.cidrs.length > 0 && <ScopeRow label="In-scope CIDRs">{scopeList(eng.in_scope.cidrs, "#22c55e")}</ScopeRow>}
              <ScopeRow label="Out-of-scope">{scopeList([...eng.out_of_scope.domains, ...eng.out_of_scope.cidrs], "#ef4444")}</ScopeRow>
            </div>
            <div className="mt-4 flex flex-wrap gap-2 border-t border-line pt-3 text-[11px] text-muted">
              {eng.rules.no_dos && <span className="rounded-md bg-card2 px-2 py-1">No DoS</span>}
              {eng.rules.no_destructive && <span className="rounded-md bg-card2 px-2 py-1">No destructive actions</span>}
              {eng.rules.prod_touch_requires_approval && <span className="rounded-md bg-card2 px-2 py-1">Prod touch needs approval</span>}
              {eng.rules.rate_limit_rps != null && <span className="rounded-md bg-card2 px-2 py-1">{eng.rules.rate_limit_rps} rps limit</span>}
              {(eng.rules.approval_required_phases || []).map((p) => (
                <span key={p} className="rounded-md bg-amber-500/10 px-2 py-1 font-medium text-amber-500">{p} gated</span>
              ))}
            </div>
          </PanelBody>
        </Panel>

        <Panel>
          <PanelHeader title="Coverage" sub={`${assets.length} assets`} />
          <PanelBody>
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
          </PanelBody>
        </Panel>
      </div>
      </>
      )}
    </>
  );
}

/* ── asset row ──────────────────────────────────────────────────────────── */
function AssetRow({ asset: a, sev, onOpen }: { asset: Asset; sev: Severity | null; onOpen?: (asset: Asset) => void }) {
  const c = COVERAGE[a.coverage];
  const clickable = !!onOpen;
  const kindIcon =
    a.kind === "domain" || a.kind === "subdomain" ? <Globe size={15} /> :
    a.kind === "ip" || a.kind === "cidr" ? <Server size={15} /> :
    a.kind === "endpoint" ? <Link2 size={15} /> : <Boxes size={15} />;
  const subtext = a.tech?.length ? a.tech.join(" · ") : a.server || a.title || "";
  return (
    <tr
      className={cx("border-t border-line/70 transition", a.scope === "out" && "opacity-55", clickable && "cursor-pointer hover:bg-fg/[0.03]")}
      onClick={clickable ? () => onOpen!(a) : undefined}
      title={clickable ? `Inspect ${a.value}` : undefined}
    >
      <td className="px-5 py-3">
        <div className="flex items-center gap-3">
          <span className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line text-muted">{kindIcon}</span>
          <div className="min-w-0">
            <div className="truncate font-mono text-[13px] text-fg-strong">{a.value}</div>
            {subtext && <div className="truncate text-[11px] text-faint">{subtext}</div>}
          </div>
        </div>
      </td>
      <td className="px-5 py-3 text-xs text-muted">{KIND_LABEL[a.kind]}</td>
      <td className="px-5 py-3">
        <Pill label={a.scope === "in" ? "In scope" : "Out of scope"} color={a.scope === "in" ? "#22c55e" : "#ef4444"} dot />
      </td>
      <td className="px-5 py-3"><RiskBar sev={sev} /></td>
      <td className="px-5 py-3">
        {a.findings > 0 ? (
          <span className="inline-flex items-center gap-1.5 tabular-nums text-fg">
            <Dot color={sev ? SEVERITY[sev].color : "rgb(var(--muted))"} /> {a.findings}
          </span>
        ) : (
          <span className="text-faint">0</span>
        )}
      </td>
      <td className="px-5 py-3"><Pill label={c.label} color={c.color} dot /></td>
    </tr>
  );
}

/* small colored bar: worst finding severity on the asset (muted track when none) */
function RiskBar({ sev }: { sev: Severity | null }) {
  const m = sev ? SEVERITY[sev] : null;
  return (
    <div className="flex items-center gap-2" title={m ? `Worst finding: ${m.label}` : "No findings"}>
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-line">
        {m && <div className="h-full rounded-full" style={{ width: `${(m.rank / 5) * 100}%`, background: m.color }} />}
      </div>
      <span className="font-mono text-[11px]" style={m ? { color: m.color } : undefined}>
        {m ? m.label : <span className="text-faint">none</span>}
      </span>
    </div>
  );
}

/* ── ports & services row ───────────────────────────────────────────────── */
const SVC_STATE: Record<Service["state"], { label: string; color: string }> = {
  open: { label: "open", color: "#22c55e" },
  filtered: { label: "filtered", color: "#f59e0b" },
  closed: { label: "closed", color: "#9ca3af" },
};
const SVC_FLAG: Record<string, string> = { outdated: "#f59e0b", exposed: "#ef4444", edge: "#3b82f6", "out-of-scope": "#9ca3af" };

function ServiceRow({ svc: s, count = 0, onFindings }: { svc: Service; count?: number; onFindings?: (host: string) => void }) {
  const st = SVC_STATE[s.state] ?? SVC_STATE.open;
  const out = s.flagged === "out-of-scope";
  return (
    <tr className={cx("border-t border-line/70 transition hover:bg-fg/[0.03]", out && "opacity-55")}>
      <td className="px-5 py-3">
        <div className="font-medium leading-tight text-fg-strong">{s.host}</div>
        {s.ip && s.ip !== s.host && <div className="font-mono text-[11px] text-faint">{s.ip}</div>}
      </td>
      <td className="whitespace-nowrap px-5 py-3 font-mono text-xs" style={{ boxShadow: `inset 3px 0 0 ${st.color}` }}>
        {s.port}<span className="text-muted">/{s.proto ?? "tcp"}</span>
      </td>
      <td className="px-5 py-3"><span className="rounded bg-card2 px-1.5 py-0.5 text-xs font-medium">{s.service}</span></td>
      <td className="px-5 py-3 text-xs text-muted">{s.product || "—"}{s.version && <span className="text-fg"> {s.version}</span>}</td>
      <td className="px-5 py-3">{s.tls ? <Pill label={s.tls} color="#38bdf8" /> : <span className="text-xs text-muted">—</span>}</td>
      <td className="px-5 py-3"><span className="inline-flex items-center gap-1.5 text-xs"><Dot color={st.color} />{st.label}</span></td>
      <td className="px-5 py-3">{s.flagged ? <Pill label={s.flagged} color={SVC_FLAG[s.flagged] ?? "#9ca3af"} dot /> : <span className="text-xs text-muted">—</span>}</td>
      <td className="px-5 py-3 tabular-nums">
        {count ? (
          <button onClick={() => onFindings?.(s.host)} className="font-medium text-fg underline decoration-fg/30 underline-offset-2 hover:decoration-fg" title={`View ${count} findings on ${s.host}`}>{count}</button>
        ) : (
          <span className="text-faint">0</span>
        )}
      </td>
    </tr>
  );
}

/* ── chrome helpers ─────────────────────────────────────────────────────── */
function ActiveFilter({ host, onClear }: { host: string; onClear: () => void }) {
  return (
    <button
      onClick={onClear}
      title="Clear host filter"
      className="inline-flex items-center gap-1.5 rounded-full border border-brand/50 bg-brand/10 px-2.5 py-1 font-mono text-[11px] font-medium text-brand transition hover:bg-brand/20"
    >
      <span className="max-w-[160px] truncate">{host}</span> <X size={12} />
    </button>
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

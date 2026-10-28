"use client";

import { useEffect, useMemo } from "react";
import { useRouter } from "next/navigation";
import {
  X, Globe, Server as ServerIcon, Shield, FileCode2, Radio, Link2, Bug, ExternalLink, ListChecks, AlertTriangle,
} from "lucide-react";
import { useConsole } from "@/lib/store";
import type { Finding } from "@/lib/types";
import { SEVERITY, COVERAGE, VERDICT, sevMeta, ink } from "@/lib/theme";
import { assetHosts, hostOf, verdictOf, isReportable } from "@/lib/format";
import { Pill, SeverityBadge, Dot } from "@/components/ui/primitives";

/* An asset (host) detail drawer: everything the engagement knows about one host —
   recon identity, findings, open ports, API endpoints, matched CVEs, and the JS
   files recon pulled + analyzed. Opened from the asset map or the asset table. */

function Section({ icon, title, count, children }: { icon: React.ReactNode; title: string; count?: number; children: React.ReactNode }) {
  return (
    <section className="mb-5">
      <div className="mb-2 flex items-center gap-2 text-[11px] font-semibold uppercase tracking-wide text-muted">
        <span className="text-muted/80">{icon}</span>
        {title}
        {count != null && <span className="rounded-full bg-card2 px-1.5 py-0.5 text-[10px] tabular-nums text-muted">{count}</span>}
      </div>
      {children}
    </section>
  );
}

function kb(bytes?: number | null): string {
  if (bytes == null) return "";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

/* The port a finding's asset targets on a given host — so a finding can be attributed
   to a specific service (host:port), not just the host. Reads the explicit port, else
   the scheme default (https→443, http→80). null when the asset names no URL for this
   host (a bare-host asset can't be pinned to one port). */
function portForHost(asset: string, host: string): number | null {
  for (const tok of (asset || "").split(/[,\s]+/)) {
    const t = tok.trim();
    if (!t) continue;
    try {
      const u = new URL(t);
      if (u.host.split(":")[0] !== host) continue;
      if (u.port) return Number(u.port);
      return u.protocol === "https:" ? 443 : u.protocol === "http:" ? 80 : null;
    } catch { /* bare host / non-URL token — can't resolve a port */ }
  }
  return null;
}

export function AssetDetail({ host, onClose }: { host: string | null; onClose: () => void }) {
  const { assets, services, findings, apiEndpoints, jsFiles, cveIntel, activeId, openFinding, setFindingsQuery } = useConsole();
  const router = useRouter();

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [onClose]);

  const data = useMemo(() => {
    if (!host) return null;
    const asset = assets.find((a) => a.value === host);
    const svcs = services.filter((s) => s.host === host).sort((a, b) => a.port - b.port);
    const finds = findings
      .filter((f) => !f.composite && assetHosts(f.asset).includes(host))
      .sort((a, b) => (SEVERITY[b.severity]?.rank ?? 0) - (SEVERITY[a.severity]?.rank ?? 0));
    const apis = apiEndpoints.filter((e) => e.host === host || (e.url && hostOf(e.url) === host));
    // js-analysis subdirs are subdomain labels (mein → mein.wien.gv.at)
    const label = host.split(".")[0];
    const js = jsFiles.filter((j) => j.dir && (host === j.dir || label === j.dir || host.startsWith(j.dir + ".")));
    // match target-wide CVE intel to THIS host by its detected tech/server string
    const entries = cveIntel?.cves ?? cveIntel?.entries ?? [];
    const hay = `${(asset?.tech ?? []).join(" ")} ${asset?.server ?? ""} ${asset?.title ?? ""}`.toLowerCase();
    const cves = entries.filter((e) => {
      const c = (e.component ?? "").toLowerCase().trim();
      return c && hay.includes(c);
    });
    // attribute each host finding to the specific service (port) it targets, so a
    // service row can link to the findings on that port (finds is already severity-sorted)
    const findsByPort = new Map<number, Finding[]>();
    for (const f of finds) {
      const p = portForHost(f.asset, host);
      if (p == null) continue;
      const list = findsByPort.get(p);
      if (list) list.push(f); else findsByPort.set(p, [f]);
    }
    return { asset, svcs, finds, apis, js, cves, findsByPort };
  }, [host, assets, services, findings, apiEndpoints, jsFiles, cveIntel]);

  if (!host || !data) return null;
  const { asset, svcs, finds, apis, js, cves, findsByPort } = data;
  const cov = asset ? COVERAGE[asset.coverage] : null;
  const repCount = finds.filter(isReportable).length;
  const sensitive = asset?.note && /sensitive|health|no scan|liveness/i.test(asset.note);

  const goToFindings = () => { setFindingsQuery(host); onClose(); router.push("/findings"); };
  const openOne = (f: Finding) => openFinding(f);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm animate-fade-in" onClick={onClose} />
      <aside className="scroll-thin fixed inset-y-0 right-0 z-50 w-full max-w-xl animate-slide-in overflow-y-auto border-l border-line bg-card p-5">
        {/* header */}
        <div className="mb-4 flex items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <Pill label={asset ? (asset.scope === "in" ? "In scope" : "Out of scope") : "Host"} color={asset?.scope === "out" ? "#ef4444" : "#22c55e"} dot />
              {cov && <Pill label={cov.label} color={cov.color} dot />}
              {asset?.tier != null && <Pill label={`Tier ${asset.tier}`} color="#a78bfa" />}
              {asset?.status != null && <Pill label={`HTTP ${asset.status}`} color="#64748b" />}
            </div>
            <h2 className="mt-2 flex items-center gap-2 text-lg font-semibold leading-tight">
              <Globe size={17} className="shrink-0 text-muted" />
              <span className="break-all">{host}</span>
            </h2>
            {asset?.title && <div className="mt-0.5 truncate text-sm text-muted">{asset.title}</div>}
          </div>
          <button onClick={onClose} aria-label="Close" className="grid h-8 w-8 shrink-0 place-items-center rounded-lg border border-line text-muted transition hover:text-fg">
            <X size={16} />
          </button>
        </div>

        {/* quick stats */}
        <div className="mb-5 grid grid-cols-4 gap-2 text-center">
          {[
            { k: "Findings", v: repCount },
            { k: "Ports", v: svcs.length },
            { k: "APIs", v: apis.length },
            { k: "JS files", v: js.length },
          ].map((s) => (
            <div key={s.k} className="rounded-lg border border-line bg-card2 px-2 py-2">
              <div className="text-base font-semibold tabular-nums">{s.v}</div>
              <div className="text-[10px] uppercase tracking-wide text-muted">{s.k}</div>
            </div>
          ))}
        </div>

        {sensitive && (
          <div className="mb-5 flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-xs text-amber-500">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <span>{asset?.note}</span>
          </div>
        )}

        {/* recon identity */}
        {(asset?.server || (asset?.tech?.length ?? 0) > 0 || (asset?.note && !sensitive) || asset?.parent) && (
          <Section icon={<ServerIcon size={13} />} title="Recon">
            <dl className="space-y-1.5 text-sm">
              {asset?.server && <Row label="Server">{asset.server}</Row>}
              {asset?.parent && <Row label="Parent">{asset.parent}</Row>}
              {asset?.note && !sensitive && <Row label="Note">{asset.note}</Row>}
              {(asset?.tech?.length ?? 0) > 0 && (
                <Row label="Tech">
                  <div className="flex flex-wrap gap-1">
                    {asset!.tech!.map((t) => <span key={t} className="rounded bg-card2 px-1.5 py-0.5 text-[11px] text-muted">{t}</span>)}
                  </div>
                </Row>
              )}
            </dl>
          </Section>
        )}

        {/* findings */}
        <Section icon={<Bug size={13} />} title="Findings" count={finds.length}>
          {finds.length === 0 ? (
            <Empty>No findings recorded on this host.</Empty>
          ) : (
            <>
              <ul className="space-y-1.5">
                {finds.map((f) => {
                  const v = verdictOf(f);
                  return (
                    <li key={f.id}>
                      <button onClick={() => openOne(f)} className="flex w-full items-start gap-2 rounded-lg border border-line bg-card2 px-2.5 py-2 text-left transition hover:border-brand/40">
                        <span className="mt-0.5 h-2 w-2 shrink-0 rounded-full" style={{ background: sevMeta(f.severity).color }} />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate text-sm font-medium">{f.title}</span>
                          <span className="mt-0.5 flex flex-wrap items-center gap-1.5 text-[11px] text-muted">
                            <span className="uppercase" style={{ color: sevMeta(f.severity).color }}>{SEVERITY[f.severity]?.label ?? f.severity}</span>
                            {f.category?.owasp && <span>· {f.category.owasp}</span>}
                            {v && <Pill label={VERDICT[v].label} color={VERDICT[v].color} />}
                          </span>
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
              <button onClick={goToFindings} className="mt-2 inline-flex items-center gap-1 text-xs text-sky-400 hover:underline">
                <ListChecks size={12} /> View on Findings page
              </button>
            </>
          )}
        </Section>

        {/* ports & services */}
        {svcs.length > 0 && (
          <Section icon={<Radio size={13} />} title="Ports & services" count={svcs.length}>
            <ul className="space-y-1.5">
              {svcs.map((s) => {
                const sf = findsByPort.get(s.port) ?? [];
                return (
                  <li key={s.id} className="flex items-center gap-2 rounded-lg border border-line bg-card2 px-2.5 py-1.5 text-sm">
                    <code className="font-mono text-xs">{s.port}<span className="text-muted">/{s.proto ?? "tcp"}</span></code>
                    <span className="rounded bg-card px-1.5 py-0.5 text-[11px] font-medium">{s.service}</span>
                    {(s.product || s.version) && <span className="truncate text-xs text-muted">{s.product}{s.version ? ` ${s.version}` : ""}</span>}
                    {s.tls && <Pill label={s.tls} color="#38bdf8" />}
                    {s.flagged && <Pill label={s.flagged} color={s.flagged === "exposed" ? "#ef4444" : s.flagged === "outdated" ? "#f59e0b" : "#64748b"} dot />}
                    <span className="ml-auto inline-flex items-center gap-2">
                      {sf.length > 0 && (
                        <button
                          onClick={() => openOne(sf[0])}
                          title={`${sf.length} finding${sf.length === 1 ? "" : "s"} on port ${s.port}${sf.length > 1 ? " — opens the most severe" : ""}`}
                          className="inline-flex items-center gap-1 rounded-full border border-line px-1.5 py-0.5 text-[11px] font-medium transition hover:border-brand/40"
                          style={{ color: sevMeta(sf[0].severity).color }}
                        >
                          <Bug size={11} />{sf.length}
                        </button>
                      )}
                      <span className="inline-flex items-center gap-1 text-[11px] text-muted"><Dot color={s.state === "open" ? "#22c55e" : "#9ca3af"} />{s.state}</span>
                    </span>
                  </li>
                );
              })}
            </ul>
          </Section>
        )}

        {/* api endpoints */}
        {apis.length > 0 && (
          <Section icon={<Link2 size={13} />} title="API endpoints" count={apis.length}>
            <ul className="space-y-1.5">
              {apis.map((e, i) => (
                <li key={i} className="rounded-lg border border-line bg-card2 px-2.5 py-1.5">
                  <div className="flex items-center gap-2">
                    {e.method && <span className="rounded bg-card px-1.5 py-0.5 text-[10px] font-semibold uppercase text-brand">{e.method}</span>}
                    <code className="min-w-0 flex-1 break-all text-xs">{e.url ?? e.host}</code>
                  </div>
                  {e.evidence && <div className="mt-0.5 text-[11px] text-muted">{e.evidence}</div>}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {/* matched CVEs */}
        {cves.length > 0 && (
          <Section icon={<Shield size={13} />} title="Matched CVEs" count={cves.length}>
            <ul className="space-y-1.5">
              {cves.map((c) => (
                <li key={c.cve} className="rounded-lg border border-line bg-card2 px-2.5 py-1.5 text-sm">
                  <div className="flex flex-wrap items-center gap-1.5">
                    <code className="font-mono text-xs font-semibold">{c.cve}</code>
                    {c.kev && <Pill label="KEV" color="#ef4444" />}
                    {c.cvss && <span className="text-xs text-muted">CVSS {c.cvss}</span>}
                    {c.reachable && <Pill label={`reach: ${c.reachable}`} color={c.reachable === "yes" ? "#ef4444" : "#64748b"} />}
                  </div>
                  {(c.component || c.title) && <div className="mt-0.5 text-[11px] text-muted">{[c.component && `${c.component}${c.version ? ` ${c.version}` : ""}`, c.title].filter(Boolean).join(" · ")}</div>}
                </li>
              ))}
            </ul>
          </Section>
        )}

        {/* JS analyzed files */}
        {js.length > 0 && (
          <Section icon={<FileCode2 size={13} />} title="JS analyzed" count={js.length}>
            <ul className="space-y-1.5">
              {js.map((j) => {
                const url = `/e/${activeId}/js/${j.rel.split("/").map(encodeURIComponent).join("/")}`;
                return (
                  <li key={j.rel}>
                    <a href={url} target="_blank" rel="noopener noreferrer" className="group flex items-center gap-2 rounded-lg border border-line bg-card2 px-2.5 py-1.5 text-sm transition hover:border-brand/40">
                      <FileCode2 size={13} className="shrink-0 text-muted" />
                      <code className="min-w-0 flex-1 truncate text-xs">{j.name}</code>
                      {j.bytes != null && <span className="shrink-0 text-[11px] tabular-nums text-muted">{kb(j.bytes)}</span>}
                      <ExternalLink size={12} className="shrink-0 text-muted opacity-0 transition group-hover:opacity-100" />
                    </a>
                  </li>
                );
              })}
            </ul>
          </Section>
        )}

        {!asset && finds.length === 0 && svcs.length === 0 && apis.length === 0 && js.length === 0 && (
          <div className="rounded-lg border border-line bg-card2 px-3 py-6 text-center text-sm text-muted" style={{ color: ink(0.6) }}>
            No recorded detail for this host yet.
          </div>
        )}
      </aside>
    </>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-3">
      <dt className="w-16 shrink-0 text-[11px] uppercase tracking-wide text-muted">{label}</dt>
      <dd className="min-w-0 flex-1 break-words">{children}</dd>
    </div>
  );
}

function Empty({ children }: { children: React.ReactNode }) {
  return <div className="rounded-lg border border-dashed border-line px-3 py-3 text-xs text-muted">{children}</div>;
}

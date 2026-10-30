// Console data layer.
//
// The console renders ONLY real engagement data — the JSON the Redstrike skills
// emit into the engagement dir (served by scripts/console.py, or loaded from
// Settings → Data source). There is no bundled demo dataset: with nothing loaded
// the console shows honest empty states.
//
// What lives here:
//   • emptyData       — the zero-state the store boots from (one placeholder
//                       engagement so the UI always has a context, empty arrays).
//   • agentRoster     — the framework's executor+reviewer catalog. This is
//                       framework STRUCTURE, not engagement data; per-engagement
//                       counts/status are DERIVED from the loaded findings.
//   • builders        — turn the real host_discovery.json into assets/services,
//                       and derive activity + agent stats from the real findings.

import type {
  ConsoleData, Engagement, Finding, Agent, ActivityEvent, Asset, Service,
} from "./types";
import { assetHosts, isReportable, verdictOf } from "./format";

/* ------------------------------------------------------------------ *
 * Static framework catalog — the executor + independent-reviewer fleet.
 * (Counts/status are overlaid from real findings in deriveAgentStats.)
 * ------------------------------------------------------------------ */
const A = (
  slug: string, name: string, family: Agent["family"], tier: Agent["tier"], summary: string,
  approvalGated = false
): Agent => ({ slug, name, family, tier, summary, reviewer: `${slug}-verify`, status: "idle", produced: 0, accepted: 0, rejected: 0, approvalGated });

export const agentRoster: Agent[] = [
  // Recon feeders (no reviewer gate — feed context)
  A("osint", "OSINT", "Recon", "Feeder", "Passive public intelligence on the org & domain."),
  A("host-discovery", "Host discovery", "Recon", "Feeder", "Subdomains, live hosts, ports, services, host tech."),
  A("content-discovery", "Content discovery", "Recon", "Feeder", "Crawl + historical URLs + custom wordlist brute-force."),
  A("js-analysis", "JS analysis", "Recon", "Feeder", "Endpoints, params, secrets, DOM sinks, libraries."),
  // Web vuln agents
  A("sqli-inband", "SQLi (in-band)", "Web", "Tier-1", "Error/union SQL injection returning data in-band."),
  A("sqli-blind", "SQLi (blind)", "Web", "Tier-1", "Boolean/time/OOB blind SQL injection."),
  A("auth-bypass", "Auth bypass", "Web", "Tier-1", "Forced browsing, response tampering, 2FA skip, reset flaws."),
  A("ssrf-cloud", "SSRF (cloud)", "Web", "Tier-1", "SSRF → cloud metadata credential theft."),
  A("xss-stored", "XSS (stored)", "Web", "Tier-1", "Cross-user stored script execution."),
  A("xss-reflected", "XSS (reflected)", "Web", "Tier-2", "Reflected script execution with context match."),
  A("xss-dom", "XSS (DOM)", "Web", "Tier-2", "Client-side source→sink taint execution."),
  A("deserialization", "Deserialization", "Web", "Tier-1", "Benign gadget proves the sink deserializes attacker data."),
  A("command-injection", "Command injection", "Web", "Tier-1", "OS command execution confirmed via OOB/timing."),
  A("csrf", "CSRF", "Web", "Tier-2", "State-changing requests lacking effective anti-CSRF."),
  A("clickjacking", "Clickjacking", "Web", "Tier-2", "Frameable sensitive actions + UI-redress PoC."),
  A("security-headers", "Security headers", "Web", "Tier-2", "Missing/weak headers enabling a contextual attack."),
  A("idor", "IDOR", "Web", "Tier-1", "Object-level access control across two identities."),
  A("bola-bfla", "BOLA / BFLA", "Web", "Tier-1", "API object/function-level authz across two identities."),
  A("exposed-surface", "Exposed surface", "Web", "Tier-2", "Unauthenticated reach to a sensitive, unintended resource."),
  A("secrets", "Secrets", "Web", "Tier-2", "Live, high-impact secrets in responses/bundles."),
  A("ssti", "SSTI", "Web", "Tier-1", "Server-side template expression evaluation."),
  A("path-traversal-lfi", "Path traversal / LFI", "Web", "Tier-1", "Read a file outside the base dir; assess LFI-RCE."),
  A("upload-rce", "Upload → RCE", "Web", "Tier-1", "Uploaded file executes server-side."),
  A("xxe-inband", "XXE (in-band)", "Web", "Tier-1", "External entity resolved + reflected in-band."),
  A("xxe-blind", "XXE (blind)", "Web", "Tier-1", "OOB callback proves the parser fetched the attacker DTD."),
  A("jwt", "JWT attacks", "Web", "Tier-2", "alg:none / weak secret / key confusion / claim tamper."),
  A("business-logic", "Business logic", "Web", "Tier-2", "Model workflows + invariants, break them for impact."),
  A("race-condition", "Race condition", "Web", "Tier-2", "TOCTOU + limit-overrun on single-use actions."),
  // AI / LLM
  A("prompt-injection", "Prompt injection", "AI / LLM", "Tier-2", "Direct/indirect/role injection past a guardrail (OWASP LLM01)."),
  A("sensitive-disclosure", "Sensitive disclosure", "AI / LLM", "Tier-2", "Real sensitive-data disclosure, corroborated (LLM02/07/08)."),
  A("excessive-agency", "Excessive agency", "AI / LLM", "Tier-2", "Drive the LLM's tools to a benign unauthorized action (LLM06)."),
  A("llm-output-handling", "LLM output handling", "AI / LLM", "Tier-2", "Model output executes at a downstream sink (LLM05)."),
  // Active Directory (approval-gated)
  A("ad-initial-access", "AD initial access", "Active Directory", "Tier-2", "Unauth → first valid domain credential.", true),
  A("ad-kerberos", "AD Kerberos", "Active Directory", "Tier-2", "Kerberoast / AS-REP / delegation abuse.", true),
  A("ad-adcs", "AD ADCS (ESC1-8)", "Active Directory", "Tier-2", "Abuse a vulnerable template/CA to issue + auth a cert.", true),
  // Post-exploitation (approval-gated)
  A("linux-privesc", "Linux privesc", "Post-Exploitation", "Tier-2", "Enumerate + confirm a vector to root benignly.", true),
  A("windows-privesc", "Windows privesc", "Post-Exploitation", "Tier-2", "Benign SYSTEM/admin via the claimed vector.", true),
  A("container-escape", "Container escape", "Post-Exploitation", "Tier-2", "Break out to the host benignly via a named misconfig.", true),
  // Smart contract
  A("sc-reentrancy", "SC reentrancy", "Smart Contract", "Tier-2", "CEI violation drains funds on a local fork."),
  A("sc-access-control", "SC access control", "Smart Contract", "Tier-2", "Unauthorized privileged on-chain action."),
  // Mobile / IoT
  A("mobile", "Mobile app", "Mobile / IoT", "Tier-2", "Android/iOS static+dynamic, mapped to OWASP MASVS.", true),
  A("iot", "IoT / embedded", "Mobile / IoT", "Tier-2", "Firmware extraction, hardcoded creds, update flaws.", true),
  // Capabilities (Tier-3)
  A("attack-chain-discovery", "Attack-chain discovery", "Capabilities", "Tier-3", "Compose accepted findings into kill chains."),
  A("cve-intelligence", "CVE intelligence", "Capabilities", "Tier-3", "Map components to version-matched reachable CVEs."),
  A("exploit-generator", "Exploit generator", "Capabilities", "Tier-3", "Turn an accepted finding into a scoped benign PoC."),
  A("exploit-dev", "Exploit dev", "Capabilities", "Tier-3", "Triaged crash → benign control-of-execution PoC.", true),
];

/* ------------------------------------------------------------------ *
 * Zero-state — one placeholder engagement so the UI always has a context.
 * ------------------------------------------------------------------ */
export const PLACEHOLDER_ENGAGEMENT_ID = "engagement";

export const emptyEngagement: Engagement = {
  id: PLACEHOLDER_ENGAGEMENT_ID,
  name: "No engagement loaded",
  target: "—",
  goal: "Point scripts/console.py at an engagement directory, or load the engagement JSON from Settings → Data source.",
  status: "scoping",
  authorized_by: "—",
  window: { start: "", end: "" },
  in_scope: { domains: [], cidrs: [], urls: [] },
  out_of_scope: { domains: [], cidrs: [], urls: [] },
  rules: {},
};

export const emptyData: ConsoleData = {
  engagements: [emptyEngagement],
  activeEngagementId: emptyEngagement.id,
  findings: [],
  chains: [],
  agents: agentRoster,
  activity: [],
  assets: [],
  services: [],
  tests: [],
  cveFeed: undefined,
  coverage: undefined,
  cveIntel: undefined,
};

/* ------------------------------------------------------------------ *
 * Builders — real host_discovery.json → services + assets.
 * Supports the current skill shape ({ live_hosts, api_endpoints }) and the
 * older flattened shape ({ hosts: [{ ports: [...] }] }).
 * ------------------------------------------------------------------ */
const isIpLike = (s: string) => /^\d{1,3}(\.\d{1,3}){3}$/.test(s) || /^[0-9a-f]*:[0-9a-f:]+$/i.test(s);
const hostFromUrl = (u?: string): string => {
  if (!u) return "";
  try { return new URL(u).host.split(":")[0]; } catch { return String(u).replace(/^https?:\/\//, "").split("/")[0].split(":")[0]; }
};

export function buildServices(o: Record<string, any>): Service[] {
  const out: Service[] = [];
  // current shape: live_hosts[]
  if (Array.isArray(o.live_hosts)) {
    o.live_hosts.forEach((h: any, i: number) => {
      const host = hostFromUrl(h?.url) || h?.ip || `host-${i}`;
      const port = Number(h?.port) || (h?.scheme === "https" ? 443 : 80);
      const stack: string[] = Array.isArray(h?.stack) ? h.stack : [];
      out.push({
        id: `svc-${i}`,
        host,
        ip: h?.ip,
        port,
        proto: "tcp",
        service: h?.scheme || "http",
        product: h?.app || stack[0],
        version: stack.length ? stack.join(" · ") : undefined,
        state: "open",
        title: h?.title,
        findings: 0,
      });
    });
    return out;
  }
  // older flattened shape: hosts[].ports[]
  if (Array.isArray(o.hosts)) {
    o.hosts.forEach((h: any, hi: number) => {
      const ports = Array.isArray(h?.ports) ? h.ports : [];
      ports.forEach((p: any, pi: number) => out.push({
        id: `svc-${hi}-${pi}`,
        host: h?.host ?? h?.hostname ?? String(h?.ip ?? ""),
        ip: h?.ip,
        port: Number(p?.port),
        proto: p?.proto ?? p?.protocol ?? "tcp",
        service: p?.service ?? p?.name ?? "?",
        product: p?.product,
        version: p?.version,
        state: p?.state ?? "open",
        tls: p?.tls,
        title: h?.title,
        flagged: p?.flagged,
        findings: 0,
      }));
    });
  }
  return out;
}

export function buildAssets(o: Record<string, any>, orgName: string): Asset[] {
  const assets: Asset[] = [];
  const seen = new Set<string>();
  const addHost = (host: string, tech?: string[]) => {
    if (!host || seen.has(host)) return;
    seen.add(host);
    assets.push({
      id: `a-host-${assets.length}`,
      value: host,
      kind: isIpLike(host) ? "ip" : "subdomain",
      scope: "in",
      // Discovery only tells us the host is LIVE, not that it was security-tested.
      // Default to "untested"; overlayAssetFindings() upgrades to tested/in-progress
      // where there's real evidence (a finding, or an analysed/flagged service).
      coverage: "untested",
      findings: 0,
      tech,
      parent: orgName && host !== orgName ? orgName : undefined,
    });
  };

  if (Array.isArray(o.live_hosts)) {
    o.live_hosts.forEach((h: any) => addHost(hostFromUrl(h?.url) || h?.ip, Array.isArray(h?.stack) ? h.stack : undefined));
  } else if (Array.isArray(o.hosts)) {
    o.hosts.forEach((h: any) => addHost(h?.host ?? h?.hostname ?? String(h?.ip ?? ""), undefined));
  }

  const primaryHost = assets[0]?.value;
  if (Array.isArray(o.api_endpoints)) {
    o.api_endpoints.forEach((e: any, i: number) => {
      if (!e?.path) return;
      assets.push({
        id: `a-ep-${i}`,
        value: e.path,
        kind: "endpoint",
        scope: "in",
        coverage: "untested", // upgraded by overlayAssetFindings() when a finding hits this path
        findings: 0,
        tech: e?.method ? [String(e.method)] : undefined,
        parent: primaryHost,
      });
    });
  }
  return assets;
}

/** Pick a sensible org-root label for the asset map (the shared parent domain). */
export function hostRoot(services: Service[], fallback: string): string {
  const hosts = Array.from(new Set(services.map((s) => s.host).filter(Boolean)));
  if (hosts.length === 1) return hosts[0];
  if (hosts.length > 1) {
    const apex = hosts[0].split(".").slice(-2).join(".");
    if (hosts.every((h) => h.split(".").slice(-2).join(".") === apex)) return apex;
  }
  return fallback || hosts[0] || "target";
}

/**
 * Overlay real reportable-finding counts AND evidence-driven coverage onto assets.
 * Coverage is derived, never assumed: a host is only "tested" if it carries a
 * reportable finding; "in-progress" if a service on it was analysed and flagged
 * (exposed/outdated) but produced no finding; otherwise "untested" — discovered
 * by recon but not individually security-tested. This keeps the asset map honest
 * (an engagement discovers the whole surface but tests only a slice of it).
 */
export function overlayAssetFindings(assets: Asset[], findings: Finding[], services: Service[] = []): Asset[] {
  if (!assets.length) return assets;
  const rep = findings.filter(isReportable);
  // "examined" = a conclusion was drawn or work was done but no REPORTABLE finding landed:
  // an analysed/flagged service, or any finding (incl. open/unconfirmed) touching the host.
  const examined = new Set<string>();
  for (const s of services) if (s.flagged === "exposed" || s.flagged === "outdated") examined.add(s.host);
  for (const f of findings) if (!f.composite) for (const h of assetHosts(f.asset)) examined.add(h);
  return assets.map((a) => {
    let n = 0;
    if (a.kind === "endpoint") {
      n = rep.filter((f) => f.asset && f.asset.replace(/[?#].*$/, "").endsWith(a.value)).length;
    } else {
      n = rep.filter((f) => assetHosts(f.asset).includes(a.value)).length;
    }
    const coverage: Asset["coverage"] =
      n > 0 ? "tested" : a.kind !== "endpoint" && examined.has(a.value) ? "in-progress" : "untested";
    return n === a.findings && coverage === a.coverage ? a : { ...a, findings: n, coverage };
  });
}

/**
 * Fallback asset list when host-discovery didn't emit host_discovery.json (the common
 * case today — recon often runs ad-hoc). Built from data that always exists: the
 * engagement's in-scope domains/urls + the hosts and endpoints the findings reference,
 * so the Assets map/table/coverage are populated instead of empty. Port/service detail
 * still needs host_discovery.json (the Ports table stays empty until recon persists it).
 */
export function deriveAssetsFromScope(eng: Engagement, findings: Finding[]): Asset[] {
  const assets: Asset[] = [];
  const seen = new Set<string>();
  const tested = new Set<string>();
  for (const f of findings) if (isReportable(f)) for (const h of assetHosts(f.asset)) tested.add(h);
  const norm = (raw: string) =>
    (raw || "").replace(/^\*\./, "").replace(/^https?:\/\//, "").split("/")[0].split(":")[0];
  const addHost = (raw: string) => {
    const host = norm(raw);
    if (!host || seen.has(host)) return;
    seen.add(host);
    assets.push({
      id: `a-scope-${assets.length}`,
      value: host,
      kind: isIpLike(host) ? "ip" : host.includes(".") ? "subdomain" : "domain",
      scope: "in",
      coverage: tested.has(host) ? "tested" : "untested",
      findings: 0,
    });
  };
  (eng.in_scope?.domains ?? []).forEach(addHost);
  (eng.in_scope?.urls ?? []).forEach((u) => addHost(hostFromUrl(u)));
  tested.forEach(addHost);

  const primary = assets[0]?.value;
  const epSeen = new Set<string>();
  for (const f of findings) {
    if (!isReportable(f)) continue;
    let path = "";
    try { path = new URL(f.asset).pathname; } catch { continue; }
    if (path && path !== "/" && !epSeen.has(path)) {
      epSeen.add(path);
      assets.push({ id: `a-ep-${assets.length}`, value: path, kind: "endpoint", scope: "in", coverage: "tested", findings: 0, parent: primary });
    }
  }
  return assets;
}

/* ------------------------------------------------------------------ *
 * Derivations from the real findings — the engagement never emits a
 * separate agents.json / activity.json, so we compute them.
 * ------------------------------------------------------------------ */

/** Per-skill produced/accepted/rejected + status, from each finding's reviewer. */
export function deriveAgentStats(roster: Agent[], findings: Finding[]): Agent[] {
  const stats = new Map<string, { produced: number; accepted: number; rejected: number }>();
  for (const f of findings) {
    const reviewer = f.review?.reviewer;
    if (!reviewer) continue;
    const slug = reviewer.replace(/-verify$/, "");
    const rec = stats.get(slug) ?? { produced: 0, accepted: 0, rejected: 0 };
    rec.produced += 1;
    const v = f.review?.verdict;
    if (v === "accepted") rec.accepted += 1;
    else if (v === "rejected") rec.rejected += 1;
    stats.set(slug, rec);
  }
  if (!stats.size) return roster;
  const overlaid = roster.map((a) => {
    const r = stats.get(a.slug);
    return r ? { ...a, ...r, status: "done" as const } : a;
  });
  // Any reviewer that produced a finding but isn't in the static catalog gets a derived row,
  // so the Agents page never silently drops a real finding (e.g. privesc, graphql, cloud).
  const known = new Set(roster.map((a) => a.slug));
  const extra: Agent[] = [];
  for (const [slug, r] of stats) {
    if (known.has(slug)) continue;
    extra.push({
      slug, name: slug, family: "Web", tier: "Tier-2",
      summary: "Derived from this engagement's findings (not in the static catalog).",
      reviewer: `${slug}-verify`, status: "done", approvalGated: false, ...r,
    });
  }
  return extra.length ? [...overlaid, ...extra] : overlaid;
}

/** An execution timeline synthesized from each finding's review record. */
export function deriveActivity(findings: Finding[]): ActivityEvent[] {
  const ev: ActivityEvent[] = [];
  for (const f of findings) {
    const rv = f.review;
    const skill = (f as any)._skill || (rv?.reviewer ? rv.reviewer.replace(/-verify$/, "") : "executor");
    const ts = rv?.reviewed_at;
    if (!ts) continue;
    ev.push({ id: `fev-${f.id}`, ts, actor: skill, kind: "finding", title: f.title, refId: f.id, severity: f.severity });
    if (rv?.verdict) {
      ev.push({
        id: `rev-${f.id}`, ts, actor: rv.reviewer ?? `${skill}-verify`, kind: "review",
        title: `Reviewer ${rv.verdict} ${f.id}`, refId: f.id, verdict: rv.verdict,
        detail: rv.notes,
      });
    }
  }
  return ev.sort((a, b) => +new Date(a.ts) - +new Date(b.ts));
}

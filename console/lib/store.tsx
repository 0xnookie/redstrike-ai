"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ConsoleData, Engagement, Finding, AttackChain, Service, TestRun, CveFeed } from "./types";
import {
  emptyData, agentRoster, buildServices, buildAssets, overlayAssetFindings,
  deriveAgentStats, deriveActivity,
} from "./data";
import { fetchLiveCveFeed, CVE_FEED } from "./cveFeed";

// "empty" = nothing loaded (honest zero-state); "live" = reading a real engagement.
type Mode = "empty" | "live";

interface ConsoleCtx {
  mode: Mode;
  engagements: Engagement[];
  activeEngagement: Engagement;
  activeId: string;
  setActiveId: (id: string) => void;
  /** findings / chains scoped to the active engagement */
  findings: Finding[];
  chains: AttackChain[];
  agents: ConsoleData["agents"];
  activity: ConsoleData["activity"];
  assets: ConsoleData["assets"];
  services: ConsoleData["services"];
  /** pentest runs scoped to the active engagement (Testing Activity + Recent Tests) */
  tests: TestRun[];
  /** global CVE feed for "What's New in Cyber" (not engagement-scoped) */
  cveFeed: CveFeed | undefined;
  /** true once the live CVE feed has been fetched (vs a pinned cve_feed.json) */
  cveLive: boolean;
  loadFiles: (files: FileList | File[]) => Promise<string[]>;
  /** clear back to the empty zero-state */
  clearData: () => void;
  /** finding detail drawer, lifted to the app so it opens from any view (and the ⌘K palette) */
  selectedFinding: Finding | null;
  openFinding: (f: Finding) => void;
  closeFinding: () => void;
  /** seed for the Findings search (e.g. clicking a host's finding count on Assets) */
  findingsQuery: string;
  setFindingsQuery: (q: string) => void;
}

const Ctx = createContext<ConsoleCtx | null>(null);

export function ConsoleProvider({ children }: { children: React.ReactNode }) {
  const [data, setData] = useState<ConsoleData>(emptyData);
  const [mode, setMode] = useState<Mode>("empty");
  const [activeId, setActiveId] = useState<string>(emptyData.activeEngagementId);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const openFinding = useCallback((f: Finding) => setSelectedFinding(f), []);
  const closeFinding = useCallback(() => setSelectedFinding(null), []);
  const [findingsQuery, setFindingsQuery] = useState("");
  const [cveLive, setCveLive] = useState(false);
  const cvePinnedRef = useRef(false); // a served cve_feed.json pins the feed (disables live fetch)
  const cveTimer = useRef<ReturnType<typeof setInterval> | null>(null);

  const activeEngagement =
    data.engagements.find((e) => e.id === activeId) ?? data.engagements[0];

  // findings / chains scoped to the active engagement; findings without an
  // engagement_id are treated as belonging to the active one (loaded files).
  const findings = useMemo(
    () => data.findings.filter((f) => !f.engagement_id || f.engagement_id === activeId),
    [data.findings, activeId]
  );
  const chains = data.chains;

  // tests scoped to the active engagement
  const tests = useMemo(
    () => data.tests.filter((t) => !t.engagement_id || t.engagement_id === activeId),
    [data.tests, activeId]
  );

  // Agents, activity and per-asset finding counts have no dedicated engagement
  // file — they are derived from the real findings + host-discovery.
  const agents = useMemo(() => deriveAgentStats(agentRoster, findings), [findings]);
  const activity = useMemo(() => deriveActivity(findings), [findings]);
  const assets = useMemo(() => overlayAssetFindings(data.assets, findings), [data.assets, findings]);

  const patchEngagement = useCallback(
    (patch: Partial<Engagement>) => {
      setData((d) => ({
        ...d,
        engagements: d.engagements.map((e) => (e.id === activeId ? { ...e, ...patch } : e)),
      }));
      setMode("live");
    },
    [activeId]
  );

  const classify = useCallback(
    (json: unknown, _name: string): string => {
      // bare findings array (older findings_consolidated.json / a per-skill findings.json)
      if (Array.isArray(json)) {
        const tagged = (json as Finding[]).map((f) => ({ ...f, engagement_id: activeId }));
        setData((d) => ({ ...d, findings: tagged }));
        setMode("live");
        return "findings";
      }
      if (json && typeof json === "object") {
        const o = json as Record<string, unknown>;

        // tests.json → { tests: [...] }
        if (Array.isArray(o.tests)) {
          const t = (o.tests as TestRun[]).map((x) => ({ ...x, engagement_id: activeId }));
          setData((d) => ({ ...d, tests: t }));
          setMode("live");
          return "tests";
        }

        // cve_feed.json → { generated_at, count_7d, count_30d, items: [...] }
        if (Array.isArray(o.items) && (o.count_7d != null || o.count_30d != null || o.generated_at != null)) {
          cvePinnedRef.current = true; // explicit feed file wins over the live fetch
          setData((d) => ({ ...d, cveFeed: o as unknown as CveFeed }));
          return "cve_feed";
        }

        // host_discovery.json → services + assets (current live_hosts shape OR older hosts[].ports[])
        if (Array.isArray(o.live_hosts) || Array.isArray(o.hosts)) {
          const orgName = (o.engagement as string) || activeEngagement.target || "";
          const services = buildServices(o);
          const builtAssets = buildAssets(o, hostRoot(services, orgName));
          setData((d) => ({ ...d, services, assets: builtAssets }));
          // a minimal scope hint from host-discovery's scope block
          const sc = o.scope as Record<string, unknown> | undefined;
          if (sc && typeof sc.host === "string") {
            setData((d) => ({
              ...d,
              engagements: d.engagements.map((e) =>
                e.id === activeId && e.in_scope.domains.length === 0
                  ? { ...e, in_scope: { ...e.in_scope, domains: [sc.host as string] } }
                  : e
              ),
            }));
          }
          setMode("live");
          return "host_discovery";
        }

        // attack chains (step-graph): attack-chain-discovery/chains.json → { chains: [{ steps }] }
        if (Array.isArray(o.chains)) {
          setData((d) => ({ ...d, chains: o.chains as AttackChain[] }));
          setMode("live");
          return "chains";
        }
        if (Array.isArray(o.attack_chains) && (o.attack_chains as any[])[0]?.steps) {
          setData((d) => ({ ...d, chains: o.attack_chains as AttackChain[] }));
          setMode("live");
          return "chains";
        }

        // findings_consolidated.json → { engagement, target, findings: [...], attack_chains?: [...] }
        if (Array.isArray(o.findings)) {
          const tagged = (o.findings as Finding[]).map((f) => ({ ...f, engagement_id: activeId }));
          // the consolidated `attack_chains` are composite, non-additive findings
          // (the kill-chain write-ups). Fold them in flagged composite so they
          // resolve in the chain graph / report but stay OUT of the severity counts.
          const composites = Array.isArray(o.attack_chains) && !(o.attack_chains as any[])[0]?.steps
            ? (o.attack_chains as Finding[]).map((f) => ({ ...f, composite: true, engagement_id: activeId }))
            : [];
          setData((d) => ({ ...d, findings: [...tagged, ...composites] }));
          patchEngagement({
            name: (o.engagement as string) || activeEngagement.name,
            target: (o.target as string) || activeEngagement.target,
            status: "running",
            ...(o.window ? { window: o.window as Engagement["window"] } : {}),
            ...(o.authorized_by ? { authorized_by: o.authorized_by as string } : {}),
            ...(o.in_scope ? { in_scope: o.in_scope as Engagement["in_scope"] } : {}),
            ...(o.out_of_scope ? { out_of_scope: o.out_of_scope as Engagement["out_of_scope"] } : {}),
            ...(o.rules ? { rules: o.rules as Engagement["rules"] } : {}),
          });
          // step-graph chains only; the consolidated attack_chains are composite findings
          if (Array.isArray(o.attack_chains) && (o.attack_chains as any[])[0]?.steps) {
            setData((d) => ({ ...d, chains: o.attack_chains as AttackChain[] }));
          }
          setMode("live");
          return "findings";
        }

        // scope.json → engagement header (name / window / scope / rules)
        if (o.in_scope || o.window || o.engagement || o.authorized_by) {
          patchEngagement({
            name: (o.engagement as string) || activeEngagement.name,
            target: (o.target as string) || firstDomain(o) || activeEngagement.target,
            goal: (o.goal as string) || (o.notes as string) || activeEngagement.goal,
            authorized_by: (o.authorized_by as string) || activeEngagement.authorized_by,
            ...(o.window ? { window: o.window as Engagement["window"] } : {}),
            ...(o.in_scope ? { in_scope: o.in_scope as Engagement["in_scope"] } : {}),
            ...(o.out_of_scope ? { out_of_scope: o.out_of_scope as Engagement["out_of_scope"] } : {}),
            ...(o.rules ? { rules: o.rules as Engagement["rules"] } : {}),
          });
          return "scope";
        }
      }
      return "unknown";
    },
    [activeId, activeEngagement.name, activeEngagement.target, patchEngagement]
  );

  const loadFiles = useCallback(
    async (files: FileList | File[]): Promise<string[]> => {
      const arr = Array.from(files);
      const kinds: string[] = [];
      for (const file of arr) {
        try {
          const text = await file.text();
          kinds.push(classify(JSON.parse(text), file.name));
        } catch {
          kinds.push(`error:${file.name}`);
        }
      }
      return kinds;
    },
    [classify]
  );

  const clearData = useCallback(() => {
    setData(emptyData);
    setActiveId(emptyData.activeEngagementId);
    setMode("empty");
  }, []);

  // Auto-load a live engagement when the console is served next to its output
  // (scripts/console.py). Harmless 404s otherwise → the empty state stays.
  const booted = useRef(false);
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    (async () => {
      for (const url of ["/findings_consolidated.json", "/scope.json", "/host_discovery.json", "/attack_chains.json", "/tests.json", "/cve_feed.json"]) {
        try {
          const res = await fetch(url, { cache: "no-store" });
          if (!res.ok) continue;
          classify(JSON.parse(await res.text()), url);
        } catch {
          /* missing / not JSON — ignore */
        }
      }
      // Live CVE feed for "What's New in Cyber" — fetched client-side, refreshed on
      // an interval. Skipped when a cve_feed.json was served (explicit override).
      // On failure (offline / CORS / rate-limited) the card simply stays hidden.
      if (!cvePinnedRef.current) {
        const applyLive = async () => {
          try {
            const live = await fetchLiveCveFeed();
            setData((d) => ({ ...d, cveFeed: live }));
            setCveLive(true);
          } catch {
            /* keep whatever feed we already have */
          }
        };
        await applyLive();
        if (!cvePinnedRef.current) cveTimer.current = setInterval(applyLive, CVE_FEED.refreshMs);
      }
    })();
    return () => {
      if (cveTimer.current) clearInterval(cveTimer.current);
    };
  }, [classify]);

  const value: ConsoleCtx = {
    mode,
    engagements: data.engagements,
    activeEngagement,
    activeId,
    setActiveId,
    findings,
    chains,
    agents,
    activity,
    assets,
    services: data.services,
    tests,
    cveFeed: data.cveFeed,
    cveLive,
    loadFiles,
    clearData,
    selectedFinding,
    openFinding,
    closeFinding,
    findingsQuery,
    setFindingsQuery,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Pick a sensible org-root label for the asset map (the shared parent domain). */
function hostRoot(services: Service[], fallback: string): string {
  const hosts = Array.from(new Set(services.map((s) => s.host).filter(Boolean)));
  if (hosts.length === 1) return hosts[0];
  // common apex suffix (e.g. example.com) across hosts, else the fallback
  const parts = hosts.map((h) => h.split("."));
  if (parts.length > 1) {
    const apex = parts[0].slice(-2).join(".");
    if (parts.every((p) => p.slice(-2).join(".") === apex)) return apex;
  }
  return fallback || hosts[0] || "target";
}

/** First in-scope domain from a scope object, used as a target fallback. */
function firstDomain(o: Record<string, unknown>): string | undefined {
  const inScope = o.in_scope as { domains?: string[] } | undefined;
  return inScope?.domains?.[0]?.replace(/^\*\./, "");
}

export function useConsole(): ConsoleCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useConsole must be used within ConsoleProvider");
  return ctx;
}

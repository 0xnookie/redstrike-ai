"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ConsoleData, Engagement, Finding, AttackChain, Service, TestRun, CveFeed } from "./types";
import { sampleData } from "./data";

type Mode = "demo" | "live";

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
  loadFiles: (files: FileList | File[]) => Promise<string[]>;
  resetDemo: () => void;
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
  const [data, setData] = useState<ConsoleData>(sampleData);
  const [mode, setMode] = useState<Mode>("demo");
  const [activeId, setActiveId] = useState<string>(sampleData.activeEngagementId);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const openFinding = useCallback((f: Finding) => setSelectedFinding(f), []);
  const closeFinding = useCallback(() => setSelectedFinding(null), []);
  const [findingsQuery, setFindingsQuery] = useState("");

  const activeEngagement =
    data.engagements.find((e) => e.id === activeId) ?? data.engagements[0];

  // findings / chains scoped to the active engagement; findings without an
  // engagement_id are treated as belonging to the active one (loaded files).
  const findings = useMemo(
    () => data.findings.filter((f) => !f.engagement_id || f.engagement_id === activeId),
    [data.findings, activeId]
  );
  const chains = data.chains;

  // tests scoped to the active engagement (untagged demo runs belong to it)
  const tests = useMemo(
    () => data.tests.filter((t) => !t.engagement_id || t.engagement_id === activeId),
    [data.tests, activeId]
  );

  const classify = useCallback(
    (json: unknown, name: string): string => {
      // findings array
      if (Array.isArray(json)) {
        const tagged = (json as Finding[]).map((f) => ({ ...f, engagement_id: activeId }));
        setData((d) => ({ ...d, findings: tagged }));
        setMode("live");
        return "findings";
      }
      if (json && typeof json === "object") {
        const o = json as Record<string, unknown>;
        // tests.json → { tests: [...] } pentest runs (object-wrapped so it isn't
        // mistaken for a bare findings array)
        if (Array.isArray(o.tests)) {
          const t = (o.tests as TestRun[]).map((x) => ({ ...x, engagement_id: activeId }));
          setData((d) => ({ ...d, tests: t }));
          setMode("live");
          return "tests";
        }
        // cve_feed.json → { generated_at, count_7d, count_30d, items: [...] }
        if (Array.isArray(o.items) && (o.count_7d != null || o.count_30d != null || o.generated_at != null)) {
          setData((d) => ({ ...d, cveFeed: o as unknown as CveFeed }));
          return "cve_feed";
        }
        // host_discovery.json → flatten hosts[].ports[] into the services table
        if (Array.isArray(o.hosts)) {
          const services: Service[] = [];
          (o.hosts as any[]).forEach((h, hi) => {
            const ports = Array.isArray(h?.ports) ? h.ports : [];
            ports.forEach((p: any, pi: number) => services.push({
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
          setData((d) => ({ ...d, services }));
          setMode("live");
          return "host_discovery";
        }
        if (Array.isArray(o.chains)) {
          setData((d) => ({ ...d, chains: o.chains as AttackChain[] }));
          return "chains";
        }
        if (Array.isArray(o.findings)) {
          const tagged = (o.findings as Finding[]).map((f) => ({ ...f, engagement_id: activeId }));
          setData((d) => ({ ...d, findings: tagged }));
          setMode("live");
          return "findings";
        }
        if (o.in_scope || o.window || o.engagement) {
          // scope.json → patch the active engagement's header fields
          setData((d) => ({
            ...d,
            engagements: d.engagements.map((e) =>
              e.id === activeId
                ? {
                    ...e,
                    name: (o.engagement as string) || e.name,
                    authorized_by: (o.authorized_by as string) || e.authorized_by,
                    window: (o.window as Engagement["window"]) || e.window,
                    in_scope: (o.in_scope as Engagement["in_scope"]) || e.in_scope,
                    out_of_scope: (o.out_of_scope as Engagement["out_of_scope"]) || e.out_of_scope,
                    rules: (o.rules as Engagement["rules"]) || e.rules,
                  }
                : e
            ),
          }));
          return "scope";
        }
      }
      return "unknown";
    },
    [activeId]
  );

  const loadFiles = useCallback(
    async (files: FileList | File[]): Promise<string[]> => {
      const arr = Array.from(files);
      const kinds: string[] = [];
      for (const file of arr) {
        try {
          const text = await file.text();
          kinds.push(classify(JSON.parse(text), file.name));
        } catch (e) {
          kinds.push(`error:${file.name}`);
        }
      }
      return kinds;
    },
    [classify]
  );

  const resetDemo = useCallback(() => {
    setData(sampleData);
    setActiveId(sampleData.activeEngagementId);
    setMode("demo");
  }, []);

  // Auto-load a live engagement when the console is served next to its output
  // (the `redstrike console` launcher). Harmless 404s otherwise → demo stays.
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
    })();
  }, [classify]);

  const value: ConsoleCtx = {
    mode,
    engagements: data.engagements,
    activeEngagement,
    activeId,
    setActiveId,
    findings,
    chains,
    agents: data.agents,
    activity: data.activity,
    assets: data.assets,
    services: data.services,
    tests,
    cveFeed: data.cveFeed,
    loadFiles,
    resetDemo,
    selectedFinding,
    openFinding,
    closeFinding,
    findingsQuery,
    setFindingsQuery,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useConsole(): ConsoleCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useConsole must be used within ConsoleProvider");
  return ctx;
}

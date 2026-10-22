"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ConsoleData, Engagement, Finding, AttackChain, Service, Asset, TestRun, CveFeed, CoverageLedger, CveIntel, EngagementStatus } from "./types";
import {
  emptyData, agentRoster, buildServices, buildAssets, overlayAssetFindings,
  deriveAgentStats, deriveActivity, deriveAssetsFromScope, hostRoot,
} from "./data";
import { fetchLiveCveFeed, CVE_FEED } from "./cveFeed";

// "empty" = nothing loaded (honest zero-state); "live" = reading real engagements.
type Mode = "empty" | "live";

// Each engagement's own findings/chains/services/assets, loaded on demand.
interface Dataset { findings: Finding[]; chains: AttackChain[]; services: Service[]; assets: Asset[]; coverage?: CoverageLedger; cveIntel?: CveIntel; }
const EMPTY_DS: Dataset = { findings: [], chains: [], services: [], assets: [] };

const ACTIVE_KEY = "redstrike.activeEngagement";

interface ConsoleCtx {
  mode: Mode;
  engagements: Engagement[];
  activeEngagement: Engagement;
  activeId: string;
  setActiveId: (id: string) => void;
  findings: Finding[];
  chains: AttackChain[];
  agents: ConsoleData["agents"];
  activity: ConsoleData["activity"];
  assets: ConsoleData["assets"];
  services: ConsoleData["services"];
  tests: TestRun[];
  coverage: CoverageLedger | undefined;
  cveIntel: CveIntel | undefined;
  cveFeed: CveFeed | undefined;
  cveLive: boolean;
  loadFiles: (files: FileList | File[]) => Promise<string[]>;
  clearData: () => void;
  selectedFinding: Finding | null;
  openFinding: (f: Finding) => void;
  closeFinding: () => void;
  findingsQuery: string;
  setFindingsQuery: (q: string) => void;
}

const Ctx = createContext<ConsoleCtx | null>(null);

/* ---- helpers ---- */
async function fetchJson(url: string): Promise<any> {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return undefined;
    return await res.json();
  } catch {
    return undefined;
  }
}

const safeLocalGet = (k: string): string | null => {
  try { return localStorage.getItem(k); } catch { return null; }
};
const safeLocalSet = (k: string, v: string) => {
  try { localStorage.setItem(k, v); } catch { /* private mode / blocked */ }
};

/** Assemble a dataset from an engagement's parsed canonical files. */
function datasetFromFiles(cons: any, host: any, chainsFile: any, cover?: any, intel?: any): Dataset {
  let findings: Finding[] = [];
  let chains: AttackChain[] = [];
  if (Array.isArray(cons)) {
    findings = cons as Finding[];
  } else if (cons && Array.isArray(cons.findings)) {
    findings = cons.findings as Finding[];
    // consolidated attack_chains are composite kill-chain write-ups (no steps) →
    // fold in flagged composite so they resolve in the graph but stay out of counts
    if (Array.isArray(cons.attack_chains) && !cons.attack_chains[0]?.steps) {
      findings = [...findings, ...cons.attack_chains.map((f: Finding) => ({ ...f, composite: true }))];
    }
  }
  if (chainsFile && Array.isArray(chainsFile.chains)) chains = chainsFile.chains as AttackChain[];
  else if (cons && Array.isArray(cons.attack_chains) && cons.attack_chains[0]?.steps) chains = cons.attack_chains as AttackChain[];

  const coverage = cover && Array.isArray(cover.categories) ? (cover as CoverageLedger) : undefined;
  const cveIntel = intel && (Array.isArray(intel.cves) || Array.isArray(intel.entries)) ? (intel as CveIntel) : undefined;

  let services: Service[] = [];
  let assets: Asset[] = [];
  if (host && (Array.isArray(host.live_hosts) || Array.isArray(host.hosts))) {
    services = buildServices(host);
    assets = buildAssets(host, hostRoot(services, (cons && cons.target) || ""));
  }
  return { findings, chains, services, assets, coverage, cveIntel };
}

/** Build an Engagement header from a manifest entry (its parsed scope + summary). */
function toEngagement(entry: any): Engagement {
  const sc = entry.scope || {};
  const win = sc.window && (sc.window.start || sc.window.end) ? sc.window : { start: "", end: "" };
  const ended = win.end && !isNaN(+new Date(win.end)) && +new Date(win.end) < Date.now();
  const hasConsolidated = !!entry.has?.["findings_consolidated.json"];
  const hasFindings = (entry.summary?.findings ?? 0) > 0;
  // Derive status from the DATA, not the clock. An explicit scope `status:` wins; otherwise:
  // nothing produced yet => scoping; the terminal report exists (reporting ran) or the window has
  // lapsed => completed; findings but no report yet => running. (Previously this keyed only off the
  // window end date, and the lazy-load path below hard-coded "running", so a finished engagement
  // showed "Running" until its scheduled window elapsed.)
  const EXPLICIT = new Set(["running", "paused", "completed", "scoping"]);
  const explicit = typeof sc.status === "string" && EXPLICIT.has(sc.status) ? (sc.status as EngagementStatus) : null;
  const status: EngagementStatus = explicit
    ? explicit
    : (!hasFindings && !hasConsolidated) ? "scoping"
    : (hasConsolidated || ended) ? "completed"
    : "running";
  return {
    id: entry.id,
    name: sc.engagement || entry.id,
    target: sc.target || "—",
    goal: sc.notes || "",
    status,
    authorized_by: sc.authorized_by || "—",
    window: { start: win.start || "", end: win.end || "" },
    in_scope: sc.in_scope || { domains: [], cidrs: [], urls: [] },
    out_of_scope: sc.out_of_scope || { domains: [], cidrs: [], urls: [] },
    rules: sc.rules || {},
    summary: entry.summary,
  };
}

export function ConsoleProvider({ children }: { children: React.ReactNode }) {
  const [engagements, setEngagements] = useState<Engagement[]>(emptyData.engagements);
  const [datasets, setDatasets] = useState<Record<string, Dataset>>({});
  const [activeId, setActiveIdState] = useState<string>(emptyData.activeEngagementId);
  const [mode, setMode] = useState<Mode>("empty");
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const openFinding = useCallback((f: Finding) => setSelectedFinding(f), []);
  const closeFinding = useCallback(() => setSelectedFinding(null), []);
  const [findingsQuery, setFindingsQuery] = useState("");
  const [cveFeed, setCveFeed] = useState<CveFeed | undefined>(undefined);
  const [cveLive, setCveLive] = useState(false);
  const cvePinnedRef = useRef(false);
  const cveTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const loadedRef = useRef<Set<string>>(new Set());

  const activeEngagement = engagements.find((e) => e.id === activeId) ?? engagements[0];
  const active = datasets[activeId] ?? EMPTY_DS;

  const findings = active.findings;
  const chains = active.chains;
  const services = active.services;
  const coverage = active.coverage;
  const cveIntel = active.cveIntel;
  const assets = useMemo(() => {
    // Prefer real host-discovery assets; otherwise derive from scope + findings so the
    // Assets views aren't empty when recon didn't emit host_discovery.json.
    const base = active.assets.length ? active.assets : deriveAssetsFromScope(activeEngagement, active.findings);
    return overlayAssetFindings(base, active.findings);
  }, [active.assets, active.findings, activeEngagement]);
  const agents = useMemo(() => deriveAgentStats(agentRoster, active.findings), [active.findings]);
  const activity = useMemo(() => deriveActivity(active.findings), [active.findings]);
  const tests: TestRun[] = []; // no per-run source yet; the activity timeline drives the heatmap

  /** Fetch + assemble one engagement's dataset (once). */
  const loadEngagement = useCallback(async (id: string) => {
    if (loadedRef.current.has(id)) return;
    loadedRef.current.add(id);
    const base = `/e/${id}`;
    const [cons, host, chainsFile, cover, intel] = await Promise.all([
      fetchJson(`${base}/findings_consolidated.json`),
      fetchJson(`${base}/host_discovery.json`),
      fetchJson(`${base}/attack_chains.json`),
      fetchJson(`${base}/coverage_ledger.json`),
      fetchJson(`${base}/cve_intel.json`),
    ]);
    if (cons === undefined && host === undefined && chainsFile === undefined && cover === undefined && intel === undefined) {
      loadedRef.current.delete(id); // nothing served (e.g. scaffold-only) — allow a retry later
      return;
    }
    const ds = datasetFromFiles(cons, host, chainsFile, cover, intel);
    setDatasets((d) => ({ ...d, [id]: ds }));
  }, []);

  const setActiveId = useCallback((id: string) => {
    setActiveIdState(id);
    safeLocalSet(ACTIVE_KEY, id);
    void loadEngagement(id);
  }, [loadEngagement]);

  /* ---- manual file drop/load into the ACTIVE engagement ---- */
  const patchActive = useCallback((partial: Partial<Dataset>) => {
    setDatasets((d) => ({ ...d, [activeId]: { ...(d[activeId] ?? EMPTY_DS), ...partial } }));
    setMode("live");
  }, [activeId]);

  const patchEngagement = useCallback((patch: Partial<Engagement>) => {
    setEngagements((es) => es.map((e) => (e.id === activeId ? { ...e, ...patch } : e)));
  }, [activeId]);

  const classify = useCallback((json: unknown, _name: string): string => {
    if (Array.isArray(json)) { patchActive({ findings: json as Finding[] }); return "findings"; }
    if (json && typeof json === "object") {
      const o = json as Record<string, unknown>;
      if (Array.isArray(o.items) && (o.count_7d != null || o.count_30d != null || o.generated_at != null)) {
        cvePinnedRef.current = true;
        setCveFeed(o as unknown as CveFeed);
        return "cve_feed";
      }
      if (Array.isArray(o.categories) && (o.map_version != null || o.active_phases != null || (o.categories[0] as any)?.phase != null)) {
        patchActive({ coverage: o as unknown as CoverageLedger });
        return "coverage";
      }
      if ((Array.isArray(o.cves) || Array.isArray(o.entries)) && (o.target != null || o.generated_at != null)) {
        patchActive({ cveIntel: o as unknown as CveIntel });
        return "cve_intel";
      }
      if (Array.isArray(o.live_hosts) || Array.isArray(o.hosts)) {
        const services = buildServices(o);
        patchActive({ services, assets: buildAssets(o, hostRoot(services, activeEngagement.target)) });
        return "host_discovery";
      }
      if (Array.isArray(o.chains)) { patchActive({ chains: o.chains as AttackChain[] }); return "chains"; }
      if (Array.isArray(o.attack_chains) && (o.attack_chains as any[])[0]?.steps) {
        patchActive({ chains: o.attack_chains as AttackChain[] }); return "chains";
      }
      if (Array.isArray(o.findings)) {
        let findings = o.findings as Finding[];
        if (Array.isArray(o.attack_chains) && !(o.attack_chains as any[])[0]?.steps) {
          findings = [...findings, ...(o.attack_chains as Finding[]).map((f) => ({ ...f, composite: true }))];
        }
        patchActive({ findings });
        patchEngagement({
          name: (o.engagement as string) || activeEngagement.name,
          target: (o.target as string) || activeEngagement.target,
          // Do NOT force status here: loading a findings file is not evidence the engagement is
          // actively running. Keep the data-derived status computed in toEngagement().
        });
        return "findings";
      }
      if (o.in_scope || o.window || o.engagement || o.authorized_by) {
        patchEngagement({
          name: (o.engagement as string) || activeEngagement.name,
          target: (o.target as string) || activeEngagement.target,
          goal: (o.goal as string) || (o.notes as string) || activeEngagement.goal,
          authorized_by: (o.authorized_by as string) || activeEngagement.authorized_by,
          ...(o.window ? { window: o.window as Engagement["window"] } : {}),
          ...(o.in_scope ? { in_scope: o.in_scope as Engagement["in_scope"] } : {}),
          ...(o.out_of_scope ? { out_of_scope: o.out_of_scope as Engagement["out_of_scope"] } : {}),
          ...(o.rules ? { rules: o.rules as Engagement["rules"] } : {}),
        });
        setMode("live");
        return "scope";
      }
    }
    return "unknown";
  }, [activeEngagement.name, activeEngagement.target, activeEngagement.goal, activeEngagement.authorized_by, patchActive, patchEngagement]);

  const loadFiles = useCallback(async (files: FileList | File[]): Promise<string[]> => {
    const arr = Array.from(files);
    const kinds: string[] = [];
    for (const file of arr) {
      try { kinds.push(classify(JSON.parse(await file.text()), file.name)); }
      catch { kinds.push(`error:${file.name}`); }
    }
    return kinds;
  }, [classify]);

  const clearData = useCallback(() => {
    loadedRef.current = new Set();
    setEngagements(emptyData.engagements);
    setDatasets({});
    setActiveIdState(emptyData.activeEngagementId);
    setMode("empty");
  }, []);

  /* ---- boot: load the manifest of all engagements, then the active one ---- */
  const booted = useRef(false);
  useEffect(() => {
    if (booted.current) return;
    booted.current = true;
    (async () => {
      const manifest = await fetchJson("/engagements.json");
      if (manifest && Array.isArray(manifest.engagements) && manifest.engagements.length) {
        const engs = manifest.engagements.map(toEngagement);
        setEngagements(engs);
        setMode("live");
        const remembered = safeLocalGet(ACTIVE_KEY);
        const initial = engs.find((e: Engagement) => e.id === remembered)?.id ?? engs[0].id;
        setActiveIdState(initial);
        await loadEngagement(initial);
      }
      // Global CVE feed — live, client-side; hidden on failure (no fabricated data).
      if (!cvePinnedRef.current) {
        const applyLive = async () => {
          try { setCveFeed(await fetchLiveCveFeed()); setCveLive(true); } catch { /* keep current */ }
        };
        await applyLive();
        if (!cvePinnedRef.current) cveTimer.current = setInterval(applyLive, CVE_FEED.refreshMs);
      }
    })();
    return () => { if (cveTimer.current) clearInterval(cveTimer.current); };
  }, [loadEngagement]);

  const value: ConsoleCtx = {
    mode, engagements, activeEngagement, activeId, setActiveId,
    findings, chains, agents, activity, assets, services, tests, coverage, cveIntel,
    cveFeed, cveLive, loadFiles, clearData,
    selectedFinding, openFinding, closeFinding, findingsQuery, setFindingsQuery,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useConsole(): ConsoleCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useConsole must be used within ConsoleProvider");
  return ctx;
}

"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState } from "react";
import type { ConsoleData, Engagement, Finding, AttackChain, Service, Asset, TestRun, CveFeed, CoverageLedger, CveIntel, CveIntelEntry, EngagementStatus, ApiEndpoint, JsFile, JsRecon, ContentMap, HttpHistory, Notebook, Severity, Confidence, SurfaceLedger, SourceContext } from "./types";
import {
  emptyData, agentRoster, buildServices, buildAssets, overlayAssetFindings,
  deriveAgentStats, deriveActivity, deriveAssetsFromScope, hostRoot,
} from "./data";
import { fetchLiveCveFeed, CVE_FEED } from "./cveFeed";
import { useToast } from "@/components/ui/Toast";
import { resolveStatus, type ControlRuns } from "./engagementStatus";

// "empty" = nothing loaded (honest zero-state); "live" = reading real engagements.
type Mode = "empty" | "live";

// Each engagement's own findings/chains/services/assets, loaded on demand.
interface Dataset { findings: Finding[]; chains: AttackChain[]; services: Service[]; assets: Asset[]; apiEndpoints: ApiEndpoint[]; jsFiles: JsFile[]; jsRecon?: JsRecon; coverage?: CoverageLedger; cveIntel?: CveIntel; content?: ContentMap; history?: HttpHistory; notebook?: Notebook; hostRaw?: any; surfaceLedger?: SurfaceLedger; sourceContext?: SourceContext; }
const EMPTY_DS: Dataset = { findings: [], chains: [], services: [], assets: [], apiEndpoints: [], jsFiles: [] };

const ACTIVE_KEY = "redstrike.activeEngagement";

// How often to re-read the engagement manifest while the console is open, so an
// engagement that finishes (its findings_consolidated.json lands) flips from
// "running" to "completed" on its own instead of waiting for a manual reload.
const MANIFEST_REFRESH_MS = 15_000;

// While a run is live for the engagement being viewed, re-check its data files this often
// (HEAD only; a file is re-downloaded only when its size changed). Without the control plane
// (read-only viewer) we can't see the run, so fall back to a slow check while the DATA says
// the engagement is running.
const LIVE_REFRESH_MS = 6_000;
const DATA_RUNNING_REFRESH_MS = 20_000;
const FRESH_FLASH_MS = 2_600;

// An engagement's canonical files, in datasetFromFiles' argument order. The last two are the
// WHITE-BOX source-audit artifacts (absent on black-box web engagements); they're served at the
// paths below by the console launcher — source_context lives under source-audit/, so its route
// carries that prefix. A miss (web engagement) just leaves the field undefined.
const ENG_FILES = [
  "findings_consolidated.json", "host_discovery.json", "attack_chains.json", "coverage_ledger.json",
  "cve_intel.json", "js_analysis.json", "content.json", "http_history.json", "notebook.json", "js_recon.json",
  "surface_ledger.json", "source-audit/source_context.json",
] as const;

/** A response's change signature: status + byte length (the server sends no Last-Modified). */
const sigOf = (status: number, len: string | number | null) => (status >= 200 && status < 300 ? `${status}:${len ?? "?"}` : String(status));

/** GET + parse one engagement file, with its signature (undefined json for a miss). */
async function fetchWithSig(url: string): Promise<{ json: any; sig: string }> {
  try {
    const res = await fetch(url, { cache: "no-store" });
    if (!res.ok) return { json: undefined, sig: sigOf(res.status, null) };
    const text = await res.text();
    const len = res.headers.get("content-length") ?? new TextEncoder().encode(text).length;
    let json: any;
    try { json = JSON.parse(text); } catch { json = undefined; }
    return { json, sig: sigOf(res.status, len) };
  } catch {
    return { json: undefined, sig: "err" };
  }
}

/** HEAD one engagement file → its signature, or null on a network error (don't treat as a change). */
async function headSig(url: string): Promise<string | null> {
  try {
    const res = await fetch(url, { method: "HEAD", cache: "no-store" });
    return sigOf(res.status, res.headers.get("content-length"));
  } catch {
    return null;
  }
}

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
  apiEndpoints: ApiEndpoint[];
  jsFiles: JsFile[];
  jsRecon: JsRecon | undefined;
  tests: TestRun[];
  coverage: CoverageLedger | undefined;
  cveIntel: CveIntel | undefined;
  content: ContentMap | undefined;
  history: HttpHistory | undefined;
  notebook: Notebook | undefined;
  hostRaw: any;
  /** white-box source-audit artifacts (undefined on black-box web engagements) */
  surfaceLedger: SurfaceLedger | undefined;
  sourceContext: SourceContext | undefined;
  cveFeed: CveFeed | undefined;
  cveLive: boolean;
  loadFiles: (files: FileList | File[]) => Promise<string[]>;
  clearData: () => void;
  reloadEngagements: () => Promise<void>;
  /** re-fetch the ACTIVE engagement's served files (HEAD-compared), so a just-written
   *  artifact — e.g. an added/removed test account in notebook.json — shows without a reload */
  reloadActive: () => Promise<void>;
  selectedFinding: Finding | null;
  openFinding: (f: Finding) => void;
  closeFinding: () => void;
  selectedHost: string | null;
  openHost: (host: string) => void;
  closeHost: () => void;
  selectedEndpoint: string | null;
  openEndpoint: (path: string) => void;
  closeEndpoint: () => void;
  findingsQuery: string;
  setFindingsQuery: (q: string) => void;
  /** finding ids that just landed via live refresh (rows flash briefly) */
  freshFindingIds: Set<string>;
  /** fed by the control plane: its live runs + how runs ended (a JSON key; "" = no plane) */
  setControlRuns: (key: string) => void;
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

/** Parse host_discovery's `api_endpoints` into a typed list (both shapes are tolerant). */
function apiEndpointsOf(host: any): ApiEndpoint[] {
  const raw = host && Array.isArray(host.api_endpoints) ? host.api_endpoints : [];
  return raw
    .map((e: any) => ({ host: e?.host ?? "", url: e?.url, method: e?.method, evidence: e?.evidence }))
    .filter((e: ApiEndpoint) => e.host || e.url);
}

/* ---- per-artifact ingest normalizer (defense-in-depth) --------------------------------
 * Loaded engagement JSON is produced by many independent skills + hand-edited runs, so a field
 * can arrive in the wrong shape: a severity typo, a `source` scalar where an array is expected,
 * a non-array `steps`, a row that isn't an object. Rather than let that reach a leaf component and
 * throw (the cve-intel blank-screen class), each loaded artifact is coerced to the reader's expected
 * shape HERE and rows too malformed to use are dropped. This generalizes the cve-intel
 * sourcesOf()/epssOf() coercers to every artifact. It's the first line of defense; the guarded enum
 * accessors (lib/theme.ts) + the render-time ErrorBoundary are the backstop. A separate agent owns
 * the serve-time validator + the schemas; this is the CLIENT resilience half. */
const SEVERITIES = new Set(["critical", "high", "medium", "low", "info"]);
const CONFIDENCES = new Set(["confirmed", "probable", "tentative"]);
const FEASIBILITIES = new Set(["demonstrated", "plausible", "theoretical"]);

const isObj = (v: any): boolean => !!v && typeof v === "object" && !Array.isArray(v);
const strOr = (v: any, fallback = ""): string => (typeof v === "string" ? v : v == null ? fallback : String(v));
const strArray = (v: any): string[] | undefined => (Array.isArray(v) ? v.filter((x) => typeof x === "string") : undefined);

/** Coerce one loaded finding to the Finding shape; null → drop (unusable row, no id). */
function normFinding(f: any): Finding | null {
  if (!isObj(f) || typeof f.id !== "string" || !f.id) return null;
  return {
    ...f,
    id: f.id,
    title: strOr(f.title, f.id),
    asset: strOr(f.asset),
    severity: (SEVERITIES.has(f.severity) ? f.severity : "info") as Severity,
    potential_severity: SEVERITIES.has(f.potential_severity) ? (f.potential_severity as Severity) : undefined,
    confidence: (CONFIDENCES.has(f.confidence) ? f.confidence : "tentative") as Confidence,
    evidence: Array.isArray(f.evidence) ? f.evidence : [],
    reproduction: Array.isArray(f.reproduction) ? f.reproduction.filter((x: any) => typeof x === "string") : [],
    references: strArray(f.references),
    attack_mapping: strArray(f.attack_mapping),
    review: isObj(f.review) ? f.review : undefined,
  } as Finding;
}

/** Coerce one loaded attack chain; null → drop. Guarantees `steps` is always an array. */
function normChain(c: any): AttackChain | null {
  if (!isObj(c) || typeof c.id !== "string" || !c.id) return null;
  const steps = Array.isArray(c.steps)
    ? c.steps.filter(isObj).map((s: any) => ({ ...s, finding_id: strOr(s.finding_id), role: strOr(s.role) }))
    : [];
  return {
    ...c,
    id: c.id,
    title: strOr(c.title, c.id),
    steps,
    feasibility: FEASIBILITIES.has(c.feasibility) ? c.feasibility : undefined,
    preconditions: strArray(c.preconditions),
  } as AttackChain;
}

/** Coerce one loaded CVE-intel entry; null → drop. Generalizes sourcesOf()/epssOf(). */
function normCveEntry(e: any): CveIntelEntry | null {
  if (!isObj(e) || typeof e.cve !== "string" || !e.cve) return null;
  const epssN = typeof e.epss === "number" ? e.epss : typeof e.epss === "string" ? parseFloat(e.epss) : NaN;
  return {
    ...e,
    cve: e.cve,
    source: Array.isArray(e.source) ? e.source.filter(Boolean) : e.source ? [String(e.source)] : undefined,
    epss: Number.isFinite(epssN) ? epssN : undefined,
  } as CveIntelEntry;
}

const normCveEntries = (arr: any): CveIntelEntry[] | undefined =>
  Array.isArray(arr) ? arr.map(normCveEntry).filter((e): e is CveIntelEntry => e !== null) : undefined;

/** Assemble a dataset from an engagement's parsed canonical files. */
function datasetFromFiles(cons: any, host: any, chainsFile: any, cover?: any, intel?: any, js?: any, contentFile?: any, historyFile?: any, notebookFile?: any, jsReconFile?: any, surfaceFile?: any, sourceCtxFile?: any): Dataset {
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

  // normalize loaded rows to the reader's shape + drop unusable ones, so a malformed field
  // (bad severity, non-array steps, a non-object row) never reaches a leaf render and throws
  findings = findings.map(normFinding).filter((f): f is Finding => f !== null);
  chains = chains.map(normChain).filter((c): c is AttackChain => c !== null);

  const coverage = cover && Array.isArray(cover.categories) ? (cover as CoverageLedger) : undefined;
  const cveIntel = intel && (Array.isArray(intel.cves) || Array.isArray(intel.entries))
    ? ({ ...intel, cves: normCveEntries(intel.cves), entries: normCveEntries(intel.entries) } as CveIntel)
    : undefined;

  let services: Service[] = [];
  let assets: Asset[] = [];
  if (host && (Array.isArray(host.live_hosts) || Array.isArray(host.hosts))) {
    services = buildServices(host);
    assets = buildAssets(host, hostRoot(services, (cons && cons.target) || ""));
  }
  const apiEndpoints = apiEndpointsOf(host);
  const jsFiles: JsFile[] = js && Array.isArray(js.files) ? (js.files as JsFile[]) : [];
  const jsRecon = isJsRecon(jsReconFile) ? (jsReconFile as JsRecon) : undefined;
  const content = isContentMap(contentFile) ? (contentFile as ContentMap) : undefined;
  const history = normHistory(historyFile);
  const notebook = isNotebook(notebookFile) ? (notebookFile as Notebook) : undefined;
  const surfaceLedger = isSurfaceLedger(surfaceFile) ? (surfaceFile as SurfaceLedger) : undefined;
  const sourceContext = isSourceContext(sourceCtxFile) ? (sourceCtxFile as SourceContext) : undefined;
  // keep the raw host_discovery object (hostRaw) too: the Site Map builder reads
  // web_routes_seen + api_endpoints (type/confirmed) + live_hosts, which the derived
  // services/assets above intentionally drop.
  return { findings, chains, services, assets, apiEndpoints, jsFiles, jsRecon, coverage, cveIntel, content, history, notebook, hostRaw: host, surfaceLedger, sourceContext };
}

/** Assemble a dataset from the raw files array (ENG_FILES order). */
function datasetFromRaw(r: any[]): Dataset {
  return datasetFromFiles(r[0], r[1], r[2], r[3], r[4], r[5], r[6], r[7], r[8], r[9], r[10], r[11]);
}

/** Does a parsed object look like notebook.json (leads / recon_intel / roe / test_accounts)? */
function isNotebook(o: any): boolean {
  return !!o && typeof o === "object" && !Array.isArray(o) &&
    (Array.isArray(o.leads) || (o.recon_intel && typeof o.recon_intel === "object") ||
      Array.isArray(o.evidence) || Array.isArray(o.test_accounts) ||
      (o.roe && typeof o.roe === "object"));
}

/** Does a parsed object look like the JS Recon payload (js_recon.json)? */
function isJsRecon(o: any): boolean {
  return !!o && typeof o === "object" && !Array.isArray(o) && Array.isArray(o.sites);
}

/** Does a parsed object look like a surface_ledger.json (web OR source)? `{surfaces:[…]}`. */
function isSurfaceLedger(o: any): boolean {
  return !!o && typeof o === "object" && !Array.isArray(o) && Array.isArray(o.surfaces);
}

/** Does a parsed object look like the white-box source_context.json (structural map / sink leads)? */
function isSourceContext(o: any): boolean {
  return !!o && typeof o === "object" && !Array.isArray(o) &&
    (Array.isArray(o.structural) || Array.isArray(o.candidates) || Array.isArray(o.dependencies));
}

/** Does a parsed object look like content-discovery's content.json? */
function isContentMap(o: any): boolean {
  return !!o && typeof o === "object" && !Array.isArray(o) &&
    (Array.isArray(o.routes) || Array.isArray(o.params_discovered) ||
      (o.notable_sinks && typeof o.notable_sinks === "object" && !Array.isArray(o.notable_sinks)));
}

/** proxy-context's http_history.json — the `{exchanges:[…]}` object or a legacy flat array. */
function normHistory(o: any): HttpHistory | undefined {
  if (Array.isArray(o)) return o.length && o.every((e) => e && typeof e === "object" && "path" in e) ? { exchanges: o } : undefined;
  if (o && typeof o === "object" && Array.isArray(o.exchanges)) return o as HttpHistory;
  return undefined;
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
  // White-box source-audit grant: the server projects scope.source → scope.source_repo. Accept
  // either key, but only as a real repo object (a bare `source: "scope.yaml"` provenance string is
  // NOT a white-box signal). Present ⇒ the recon views branch to their source-audit layout.
  const srcRepo = isObj(sc.source_repo) && sc.source_repo.repo_url ? sc.source_repo
    : isObj(sc.source) && sc.source.repo_url ? sc.source
    : undefined;
  return {
    id: entry.id,
    name: sc.engagement || entry.id,
    target: sc.target || srcRepo?.repo_url || (Array.isArray(sc.in_scope?.urls) ? sc.in_scope.urls[0] : "") || "—",
    source: srcRepo ? { repo_url: srcRepo.repo_url, local_path: srcRepo.local_path, commit: srcRepo.commit, branch: srcRepo.branch } : undefined,
    goal: sc.notes || "",
    status,
    authorized_by: sc.authorized_by || "—",
    window: { start: win.start || "", end: win.end || "" },
    in_scope: sc.in_scope || { domains: [], cidrs: [], urls: [] },
    out_of_scope: sc.out_of_scope || { domains: [], cidrs: [], urls: [] },
    rules: sc.rules || {},
    summary: entry.summary,
    phase_progress: entry.progress && entry.progress.total ? entry.progress : undefined,
    run: entry.run || undefined,
    report: hasConsolidated,
    status_explicit: !!explicit,
  };
}

export function ConsoleProvider({ children }: { children: React.ReactNode }) {
  const [engagements, setEngagements] = useState<Engagement[]>(emptyData.engagements);
  const [datasets, setDatasets] = useState<Record<string, Dataset>>({});
  const [activeId, setActiveIdState] = useState<string>(emptyData.activeEngagementId);
  const [mode, setMode] = useState<Mode>("empty");
  // true once we've booted from a real server-served manifest (console.py) — the poller
  // below only runs then, so dev empty-state and manual drag-and-drop loads are untouched.
  const [served, setServed] = useState(false);
  // three mutually-exclusive right-side drawers (finding / host / endpoint): opening
  // any one closes the others so only a single detail panel is ever up.
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const openFinding = useCallback((f: Finding) => { setSelectedHost(null); setSelectedEndpoint(null); setSelectedFinding(f); }, []);
  const closeFinding = useCallback(() => setSelectedFinding(null), []);
  const [selectedHost, setSelectedHost] = useState<string | null>(null);
  const openHost = useCallback((host: string) => { setSelectedFinding(null); setSelectedEndpoint(null); setSelectedHost(host); }, []);
  const closeHost = useCallback(() => setSelectedHost(null), []);
  const [selectedEndpoint, setSelectedEndpoint] = useState<string | null>(null);
  const openEndpoint = useCallback((path: string) => { setSelectedFinding(null); setSelectedHost(null); setSelectedEndpoint(path); }, []);
  const closeEndpoint = useCallback(() => setSelectedEndpoint(null), []);
  const [findingsQuery, setFindingsQuery] = useState("");
  const [cveFeed, setCveFeed] = useState<CveFeed | undefined>(undefined);
  const [cveLive, setCveLive] = useState(false);
  const cvePinnedRef = useRef(false);
  const cveTimer = useRef<ReturnType<typeof setInterval> | null>(null);
  const loadedRef = useRef<Set<string>>(new Set());
  const rawRef = useRef<Record<string, any[]>>({});    // per engagement: parsed files (ENG_FILES order)
  const sigRef = useRef<Record<string, string[]>>({}); // per engagement: their change signatures
  const refreshing = useRef(false);
  const manifestRefreshing = useRef(false); // guards the manifest poll from stacking (see refreshManifest)
  const datasetsRef = useRef(datasets);
  datasetsRef.current = datasets;
  const toast = useToast();
  const [controlRuns, setControlRuns] = useState(""); // fed by the control-plane bridge
  const [freshFindingIds, setFreshFindingIds] = useState<Set<string>>(() => new Set());
  const freshTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  const ctl = useMemo<ControlRuns | null>(() => (controlRuns ? JSON.parse(controlRuns) : null), [controlRuns]);
  // re-resolved whenever the manifest re-polls (every 15s), so a quiet run log ages into "completed"
  const shownEngagements = useMemo(() => {
    const now = Date.now();
    return engagements.map((e) => {
      const status = resolveStatus(e, ctl, now);
      return status === e.status ? e : { ...e, status };
    });
  }, [engagements, ctl]);
  const activeEngagement = shownEngagements.find((e) => e.id === activeId) ?? shownEngagements[0];
  const active = datasets[activeId] ?? EMPTY_DS;

  const findings = active.findings;
  const chains = active.chains;
  const services = active.services;
  const coverage = active.coverage;
  const cveIntel = active.cveIntel;
  const content = active.content;
  const history = active.history;
  const notebook = active.notebook;
  const hostRaw = active.hostRaw;
  const surfaceLedger = active.surfaceLedger;
  const sourceContext = active.sourceContext;
  const apiEndpoints = active.apiEndpoints;
  const jsFiles = active.jsFiles;
  const jsRecon = active.jsRecon;
  const assets = useMemo(() => {
    // Prefer real host-discovery assets; otherwise derive from scope + findings so the
    // Assets views aren't empty when recon didn't emit host_discovery.json.
    const base = active.assets.length ? active.assets : deriveAssetsFromScope(activeEngagement, active.findings);
    return overlayAssetFindings(base, active.findings, active.services);
  }, [active.assets, active.findings, active.services, activeEngagement]);
  const agents = useMemo(() => deriveAgentStats(agentRoster, active.findings), [active.findings]);
  const activity = useMemo(() => deriveActivity(active.findings), [active.findings]);
  const tests: TestRun[] = []; // no per-run source yet; the activity timeline drives the heatmap

  /** Fetch + assemble one engagement's dataset (once). The consolidated findings file is fetched
   *  FIRST and rendered the moment it lands; the remaining artifacts are folded in afterwards. This
   *  keeps the findings view from waiting on — and the ten parallel requests from contending over —
   *  sibling artifacts a pre-reporting engagement hasn't produced yet, which matters most when each
   *  request is slow to serve (e.g. a white-box engagement whose large source checkout makes the
   *  server's per-request file discovery expensive): findings used to appear only once ALL ten
   *  requests resolved, so a single slow/absent sibling left the view empty. Findings populate from
   *  findings_consolidated.json alone, shape-agnostically — a bare array, a {findings} union, or a
   *  full report envelope all yield the same findings[] (see datasetFromFiles). */
  const loadEngagement = useCallback(async (id: string) => {
    if (loadedRef.current.has(id)) return;
    loadedRef.current.add(id);
    // full-length raw/sig baselines, filled IN PLACE as each artifact lands — the early findings
    // render and the live-refresh HEAD-compare both read these, so they must exist up front.
    const raw: any[] = new Array(ENG_FILES.length).fill(undefined);
    const sigs: string[] = new Array(ENG_FILES.length).fill("");
    rawRef.current[id] = raw;
    sigRef.current[id] = sigs;
    // ENG_FILES[0] === findings_consolidated.json — show findings as soon as it arrives.
    const first = await fetchWithSig(`/e/${id}/${ENG_FILES[0]}`);
    raw[0] = first.json; sigs[0] = first.sig;
    if (first.json !== undefined) setDatasets((d) => ({ ...d, [id]: datasetFromRaw(raw) }));
    // then the rest, merged on top of the findings already shown.
    const rest = await Promise.all(ENG_FILES.slice(1).map((f) => fetchWithSig(`/e/${id}/${f}`)));
    rest.forEach((g, i) => { raw[i + 1] = g.json; sigs[i + 1] = g.sig; });
    if (raw.every((j) => j === undefined)) {
      loadedRef.current.delete(id); // nothing served (e.g. scaffold-only) — allow a retry later
      return;
    }
    setDatasets((d) => ({ ...d, [id]: datasetFromRaw(raw) }));
  }, []);

  /* ---- live refresh: re-read only the files that changed while a run produces them ---- */
  const refreshEngagement = useCallback(async (id: string) => {
    if (refreshing.current) return; // a slow tick is still in flight
    refreshing.current = true;
    try {
      // nothing served at first load (a brand-new engagement) → try a full load instead
      if (!loadedRef.current.has(id) || !rawRef.current[id]) { await loadEngagement(id); return; }
      const raw = rawRef.current[id];
      const sigs = sigRef.current[id];
      const heads = await Promise.all(ENG_FILES.map((f) => headSig(`/e/${id}/${f}`)));
      const changed = heads.map((h, i) => h !== null && h !== sigs[i]);
      if (!changed.some(Boolean)) return; // the common case: nothing new, no re-render
      const got = await Promise.all(ENG_FILES.map((f, i) => (changed[i] ? fetchWithSig(`/e/${id}/${f}`) : null)));
      got.forEach((g, i) => { if (g) { raw[i] = g.json; sigs[i] = g.sig; } });
      const ds = datasetFromRaw(raw);
      const before = new Set((datasetsRef.current[id]?.findings ?? []).map((f) => f.id));
      const added = ds.findings.filter((f) => !f.composite && !before.has(f.id));
      setDatasets((d) => ({ ...d, [id]: ds }));
      if (added.length) {
        // new findings landed: flash their rows + say so (only for a refresh, never the first load)
        setFreshFindingIds(new Set(added.map((f) => f.id)));
        if (freshTimer.current) clearTimeout(freshTimer.current);
        freshTimer.current = setTimeout(() => setFreshFindingIds(new Set()), FRESH_FLASH_MS);
        const hot = added.filter((f) => f.severity === "critical" || f.severity === "high").length;
        toast(`${added.length} new finding${added.length === 1 ? "" : "s"} landed${hot ? ` · ${hot} critical/high` : ""}`);
      }
    } finally {
      refreshing.current = false;
    }
  }, [loadEngagement, toast]);

  // On-demand refresh of the active engagement's served files (same HEAD-compare path the live
  // poller uses; notebook.json's size changes on write, so it's re-fetched). Lets a control-plane
  // write — e.g. adding/removing a test account — surface at once instead of waiting for a poll.
  const reloadActive = useCallback(() => refreshEngagement(activeId), [refreshEngagement, activeId]);

  // which cadence applies to the engagement being viewed (if any)
  const runLive = !!activeId && !!ctl?.live.includes(activeId);
  const dataLive = activeEngagement?.status === "running";
  useEffect(() => {
    if (!served || !activeId || (!runLive && !dataLive)) return;
    const tick = () => {
      if (typeof document === "undefined" || document.visibilityState !== "hidden") void refreshEngagement(activeId);
    };
    const t = setInterval(tick, runLive ? LIVE_REFRESH_MS : DATA_RUNNING_REFRESH_MS);
    // catch up at once when the tab comes back (the interval skips hidden ticks)
    const onVisible = () => { if (document.visibilityState === "visible") tick(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => {
      clearInterval(t);
      document.removeEventListener("visibilitychange", onVisible);
    };
  }, [served, activeId, runLive, dataLive, refreshEngagement]);

  // the run just ended → one last pass picks up whatever it wrote on the way out
  const wasLive = useRef(false);
  useEffect(() => {
    if (wasLive.current && !runLive && served && activeId) void refreshEngagement(activeId);
    wasLive.current = runLive;
  }, [runLive, served, activeId, refreshEngagement]);

  useEffect(() => () => { if (freshTimer.current) clearTimeout(freshTimer.current); }, []);

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
      if (Array.isArray(o.files) && o.files.length > 0 &&
          (o.files as any[]).every((f) => f && typeof f === "object" && "rel" in f && "name" in f)) {
        patchActive({ jsFiles: o.files as JsFile[] });
        return "js_analysis";
      }
      if (isJsRecon(o)) {
        patchActive({ jsRecon: o as unknown as JsRecon });
        return "js_recon";
      }
      const hist = normHistory(o);
      if (hist) {
        patchActive({ history: hist });
        return "http_history";
      }
      if (isContentMap(o)) {
        patchActive({ content: o as unknown as ContentMap });
        return "content_map";
      }
      if (isNotebook(o)) {
        patchActive({ notebook: o as unknown as Notebook });
        return "notebook";
      }
      // white-box source-audit artifacts — must be checked BEFORE the scope branch below
      // (surface_ledger also carries an `engagement` key, which that branch keys off).
      if (isSourceContext(o)) {
        patchActive({ sourceContext: o as unknown as SourceContext });
        return "source_context";
      }
      if (isSurfaceLedger(o)) {
        patchActive({ surfaceLedger: o as unknown as SurfaceLedger });
        return "surface_ledger";
      }
      if (Array.isArray(o.live_hosts) || Array.isArray(o.hosts)) {
        const services = buildServices(o);
        patchActive({ services, assets: buildAssets(o, hostRoot(services, activeEngagement.target)), apiEndpoints: apiEndpointsOf(o), hostRaw: o });
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
    setServed(false); // stop the manifest poller after an explicit Clear data
  }, []);

  /* ---- re-read the engagement manifest (after a create/delete on the control plane) ---- */
  const reloadEngagements = useCallback(async () => {
    const manifest = await fetchJson("/engagements.json");
    if (!manifest || !Array.isArray(manifest.engagements)) return;
    const engs: Engagement[] = manifest.engagements.map(toEngagement);
    if (engs.length) {
      setEngagements(engs);
      setMode("live");
      setServed(true);
      setActiveIdState((cur) => {
        const keep = engs.find((e) => e.id === cur)?.id ?? engs[0].id;
        safeLocalSet(ACTIVE_KEY, keep);
        void loadEngagement(keep);
        return keep;
      });
    } else {
      // everything was deleted — fall back to the zero-state placeholder
      setEngagements(emptyData.engagements);
      setDatasets({});
      setActiveIdState(emptyData.activeEngagementId);
      setMode("empty");
    }
  }, [loadEngagement]);

  /* ---- lightweight manifest re-poll: refresh engagement HEADERS (status/summary) in place,
         so a finishing engagement flips "running" -> "completed" without a manual reload.
         Headers-only: datasets and the active selection are left untouched. Non-destructive —
         a failed or empty fetch is a no-op (a transient blip must never blank the list) and
         engagements are never removed here (control-plane delete owns that). ---- */
  const refreshManifest = useCallback(async () => {
    // Don't stack: /engagements.json is rebuilt server-side on every hit (it re-discovers every
    // engagement's files), so for a large engagement one poll can take longer than the 15s interval.
    // Without this guard, polls pile up and starve the on-demand data fetches (a finishing engagement
    // never rendered its findings). refreshEngagement guards the same way.
    if (manifestRefreshing.current) return;
    manifestRefreshing.current = true;
    try {
      const manifest = await fetchJson("/engagements.json");
      if (!manifest || !Array.isArray(manifest.engagements) || manifest.engagements.length === 0) return;
      const next: Engagement[] = manifest.engagements.map(toEngagement);
      const byId = new Map(next.map((e) => [e.id, e]));
      setEngagements((prev) => {
        const merged = prev.map((e) => byId.get(e.id) ?? e); // refresh known headers in place
        for (const e of next) if (!prev.some((p) => p.id === e.id)) merged.push(e); // append new ones
        return merged;
      });
    } finally {
      manifestRefreshing.current = false;
    }
  }, []);

  /* ---- drive the re-poll: an interval while the tab is visible, plus a refresh the moment
         the tab regains focus. Only runs once served by console.py (see `served`). ---- */
  useEffect(() => {
    if (!served) return;
    const tick = () => {
      if (typeof document === "undefined" || document.visibilityState === "visible") void refreshManifest();
    };
    const id = setInterval(tick, MANIFEST_REFRESH_MS);
    const onFocus = () => { if (document.visibilityState === "visible") void refreshManifest(); };
    window.addEventListener("focus", onFocus);
    document.addEventListener("visibilitychange", onFocus);
    return () => {
      clearInterval(id);
      window.removeEventListener("focus", onFocus);
      document.removeEventListener("visibilitychange", onFocus);
    };
  }, [served, refreshManifest]);

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
        setServed(true);
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
    mode, engagements: shownEngagements, activeEngagement, activeId, setActiveId,
    findings, chains, agents, activity, assets, services, apiEndpoints, jsFiles, jsRecon, tests, coverage, cveIntel,
    content, history, notebook, hostRaw, surfaceLedger, sourceContext,
    cveFeed, cveLive, loadFiles, clearData, reloadEngagements, reloadActive,
    selectedFinding, openFinding, closeFinding,
    selectedHost, openHost, closeHost,
    selectedEndpoint, openEndpoint, closeEndpoint,
    findingsQuery, setFindingsQuery,
    freshFindingIds, setControlRuns,
  };

  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useConsole(): ConsoleCtx {
  const ctx = useContext(Ctx);
  if (!ctx) throw new Error("useConsole must be used within ConsoleProvider");
  return ctx;
}

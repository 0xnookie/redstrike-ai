// Data model for the Redstrike console.
// `Finding` / `AttackChain` mirror skills/_contract/*.schema.json so the console
// renders the exact JSON the reporting skill emits. The rest (Engagement, Agent,
// ActivityEvent, Asset) are console-level views over the same engagement.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "probable" | "tentative";
export type FindingStatus = "open" | "verified" | "rejected" | "duplicate" | "remediated";
export type Verdict = "accepted" | "rejected" | "needs-evidence" | "blocked";
export type EvidenceType =
  | "request_response" | "tool_output" | "screenshot" | "dom_capture" | "log" | "poc_script";

export interface Evidence {
  type: EvidenceType;
  ref: string;
  sha256?: string;
}

export interface FindingReview {
  verdict: Verdict;
  reviewer: string;
  reviewed_at?: string;
  rubric?: Record<string, "pass" | "fail" | "n/a">;
  false_positive_checks?: string[];
  scope_ok?: boolean;
  notes?: string;
}

export interface Finding {
  id: string;
  title: string;
  asset: string;
  category?: { owasp?: string; wstg?: string; cwe?: string };
  attack_mapping?: string[];
  severity: Severity;
  potential_severity?: Severity;
  composite?: boolean;
  cvss_vector?: string;
  confidence: Confidence;
  status: FindingStatus;
  evidence: Evidence[];
  reproduction: string[];
  impact?: string;
  remediation?: string;
  references?: string[];
  review?: FindingReview;
  /** console-only: which engagement this finding belongs to */
  engagement_id?: string;
}

export type ChainFeasibility = "demonstrated" | "plausible" | "theoretical";
export interface ChainStep {
  finding_id: string;
  role: string; // entry | pivot | escalation | exfil
  enables?: string;
}
export interface AttackChain {
  id: string;
  title: string;
  steps: ChainStep[];
  preconditions?: string[];
  impact?: string;
  cvss?: string;
  feasibility?: ChainFeasibility;
  evidence?: string;
  notes?: string;
}

export type EngagementStatus = "running" | "paused" | "completed" | "scoping";
export interface Engagement {
  id: string;
  name: string;
  target: string;
  goal: string;
  status: EngagementStatus;
  authorized_by: string;
  window: { start: string; end: string };
  in_scope: { domains: string[]; cidrs: string[]; urls: string[] };
  out_of_scope: { domains: string[]; cidrs: string[]; urls: string[] };
  rules: {
    no_dos?: boolean;
    no_destructive?: boolean;
    rate_limit_rps?: number;
    prod_touch_requires_approval?: boolean;
    approval_required_phases?: string[];
  };
  phase_progress?: { done: number; total: number };
  starred?: boolean;
  /** summary counts for the engagements list (active engagement is computed live) */
  summary?: { findings: number; critical: number; high: number; medium: number; low: number; chains: number };
}

export type AgentFamily =
  | "Recon" | "Web" | "AI / LLM" | "Active Directory" | "Post-Exploitation"
  | "Smart Contract" | "Mobile / IoT" | "Capabilities";
export type AgentTier = "Tier-1" | "Tier-2" | "Tier-3" | "Feeder" | "Capability";
export type AgentStatus = "idle" | "running" | "done" | "blocked";

export interface Agent {
  slug: string;         // e.g. "xss-reflected"
  name: string;         // human label
  family: AgentFamily;
  tier: AgentTier;
  summary: string;
  reviewer: string;     // the independent verify agent, e.g. "xss-reflected-verify"
  status: AgentStatus;
  produced: number;     // findings emitted
  accepted: number;     // findings accepted by its reviewer
  rejected: number;     // findings rejected by its reviewer
  approvalGated?: boolean;
}

export type ActivityKind =
  | "recon" | "tool_use" | "finding" | "review" | "approval" | "chain" | "report" | "note";
export interface ActivityEvent {
  id: string;
  ts: string;
  actor: string;        // agent slug or "orchestrator"
  kind: ActivityKind;
  title: string;
  detail?: string;
  refId?: string;       // finding id / chain id
  severity?: Severity;
  verdict?: Verdict;
}

export type AssetKind = "domain" | "subdomain" | "ip" | "cidr" | "service" | "endpoint";
export type AssetScope = "in" | "out";
export type AssetCoverage = "tested" | "in-progress" | "untested";
export interface Asset {
  id: string;
  value: string;
  kind: AssetKind;
  scope: AssetScope;
  coverage: AssetCoverage;
  findings: number;
  tech?: string[];
  parent?: string;
  // recon detail carried from host_discovery's live_hosts entry (shown in the asset drawer)
  status?: number;      // HTTP status observed
  server?: string;      // Server header / gateway banner
  title?: string;       // page / portal title
  tier?: number;        // recon priority tier (1 = highest-value)
  note?: string;        // recon note, e.g. "health-sensitive: liveness-only, no scan"
}

// Open port + service, built from host-discovery's host_discovery.json
// (current `{ live_hosts: [{ url, ip, port, scheme, service, stack, title }] }`,
//  or the older `{ hosts: [{ host, ip, ports: [...] }] }`).
export type PortState = "open" | "filtered" | "closed";
export interface Service {
  id: string;
  host: string;
  ip?: string;
  port: number;
  proto?: "tcp" | "udp";
  service: string;        // http · https · ssh · smtp …
  product?: string;       // nginx · OpenSSH · Tomcat …
  version?: string;
  state: PortState;
  tls?: string;           // e.g. "TLS 1.3"
  title?: string;         // HTTP title / banner
  findings?: number;      // findings attributed to this service
  flagged?: string;       // short note when notable: outdated · exposed · edge · out-of-scope
}

// API endpoint surfaced by host-discovery (host_discovery.json `api_endpoints`).
export interface ApiEndpoint {
  host: string;
  url?: string;
  method?: string;
  evidence?: string;      // why it's interesting (e.g. "Service API (401 auth-protected)")
}

// One JS file recon pulled + analyzed, from the console launcher's js_analysis.json
// listing (scripts/console.py scans <eng>/js-analysis/**). `dir` is the per-host subdir
// (a subdomain label), `rel` the path under js-analysis/ used to fetch the raw file.
export interface JsFile {
  dir: string;
  name: string;
  rel: string;
  bytes?: number | null;
}

// JS Recon — the js-analysis skill's FINDINGS, parsed from each out/<site>/findings/*.jsonl
// into /e/<id>/js_recon.json by scripts/console.py (see js_recon_report). Every row shape is
// loose by design (recon emits what it found); the view tolerates partial/legacy records and
// the extra enrichment fields the skill may add (kind/guard/category/origin_check/provider_meta).
// Secrets arrive already redacted at the source (match_redacted) — the console never sees raw.
export type JsEndpointState = "live" | "historical" | "unauthed" | string;
export interface JsEndpoint { url: string; method?: string; source_file?: string; line?: number; state?: JsEndpointState; kind?: string; guard?: string; }
export interface JsParam { name: string; context?: string; source_file?: string; line?: number; likely_vuln?: boolean; kind?: string; }
export interface JsApi { path: string; group?: string; version?: string; method?: string; source_file?: string; }
export interface JsSecret { type: string; match_redacted?: string; entropy?: number; source_file?: string; line?: number; severity?: string; provider_meta?: string; }
export interface JsGadget { sink: string; snippet?: string; source_file?: string; line?: number; category?: string; origin_check?: string; }
export interface JsLibrary { name: string; version?: string; cves?: string[]; source_file?: string; }
export interface JsReconSite {
  site: string;
  endpoints?: JsEndpoint[];
  params?: JsParam[];
  apis?: JsApi[];
  secrets?: JsSecret[];
  gadgets?: JsGadget[];
  libraries?: JsLibrary[];
  counts?: Record<string, number>;      // total valid rows per stream (may exceed the rows shown)
  truncated?: Record<string, boolean>;  // stream -> true when counts > rows returned
  summary_md?: string;                  // analysis/site-summary.md, verbatim
  has_report?: boolean;                 // report.md exists for this site
}
export interface JsRecon {
  sites: JsReconSite[];
  totals?: Record<string, number>;
  site_count?: number;
}

// A discrete pentest run — feeds the Testing Activity heatmap + the Recent Tests list.
export type TestStatus = "running" | "completed" | "failed" | "queued";
export interface TestRun {
  id: string;
  target: string;          // host / scope the run was pointed at
  profile?: string;        // e.g. "Full web assessment", "XSS hunt"
  status: TestStatus;
  startedAt: string;       // ISO
  durationMin?: number;
  findings?: number;       // findings produced by the run
  topSeverity?: Severity;  // highest-severity finding of the run
  engagement_id?: string;
}

// Global CVE feed for the "What's New in Cyber" dashboard section. Not engagement-
// scoped; a deployment may override the demo feed by serving `cve_feed.json`.
export interface CveItem {
  id: string;              // e.g. "CVE-2026-9589"
  summary: string;
  severity?: Severity;     // when the record carries a qualitative rating
  cvss?: number;           // base score
  published: string;       // ISO date
}
export interface CveFeed {
  generated_at: string;
  count_7d: number;        // detections in the last 7 days
  count_30d: number;       // detections in the last 30 days
  items: CveItem[];        // newest detections, most-recent first
}

// Category coverage ledger (coverage_ledger.json from scripts/coverage.py): which vuln
// categories were attempted vs skipped-with-reason vs out-of-phase. Makes "not attempted" a
// first-class, visible state instead of indistinguishable from "ran and found nothing".
export type CoverageStatus = "pending" | "attempted" | "blocked" | "skipped" | "n/a" | "pipeline";
export interface CoverageCategory {
  id: string;
  name?: string;
  phase: string;
  status: CoverageStatus;
  reason?: string;
  findings_count?: number;
  skills?: string[];
  triggers_matched?: string[];
}
export interface CoverageLedger {
  engagement?: string;
  generated_at?: string;
  map_version?: number;
  active_phases?: string[];
  categories: CoverageCategory[];
}

// Per-engagement CVE intelligence (cve_intel.json from the cve-intelligence capability):
// detected components mapped to version-matched CVEs, KEV/EPSS-prioritized (scripts/cve_prioritize.py).
// Distinct from the global CveFeed above — this is THIS target's surface. Some runs emit the entry
// array as `entries` rather than the schema's `cves`; readers accept either.
export type Reachable = "yes" | "no" | "unknown";
export interface CveComponent { name: string; version?: string; source?: string; }
export interface CveIntelEntry {
  cve: string;
  component?: string;
  version?: string;
  cvss?: string;
  title?: string;
  exploit_available?: boolean | null;
  exploit_ref?: string;
  reachable?: Reachable;
  confidence?: Confidence;
  source?: string[];
  kev?: boolean;
  epss?: number;
  priority_rank?: number;
  notes?: string;
}
export interface CveIntel {
  target?: string;
  generated_at?: string;
  components?: CveComponent[];
  cves?: CveIntelEntry[];
  entries?: CveIntelEntry[];
}

// content-discovery's content.json — the crawl/content map that feeds the Site Map
// view. One `routes` entry per discovered URL (path + what recon learned about it),
// plus the mined parameter list and the notable interpreter sinks. The shape is loose
// by design (recon emits what it found); every field but `path` is optional and the
// Site Map builder tolerates partial/legacy records.
export interface ContentRoute {
  path: string;
  status?: number;          // HTTP status observed, when the route was actually requested
  type?: string;            // html · form · json · graphql · graphql-ide · websocket · …
  methods?: string[];       // verbs seen (defaults to GET when absent)
  params?: string[];        // parameters this route accepts
  note?: string;            // recon note ("lists pastes flagged private")
  js?: string;              // JS origin hint ("importPaste [SSRF-shaped]")
  introspection?: boolean;  // GraphQL introspection reachable
}
export interface ContentMap {
  engagement?: string;
  target?: string;          // "host" or "host:port" the crawl was pointed at
  generated_at?: string;
  crawl_method?: string;    // how the map was built (tooling / manual note)
  routes?: ContentRoute[];
  params_discovered?: string[];
  notable_sinks?: Record<string, string[]>; // vuln-class -> sink identifiers
}

// proxy-context's http_history.json — the connected interception proxy's captured traffic
// (Caido / Burp / mitmproxy / ZAP), exported into the engagement with secrets redacted. One
// `exchanges[]` record per request/response. Feeds the Site Map: host+path+method are the merge
// keys, status/mime/params drive its facets, and req/res carry the raw message for the viewer.
export interface HttpMessage {
  headers?: [string, string][]; // [name, value] pairs, secrets redacted to ‹redacted›
  body?: string;
}
export interface HttpExchange {
  id: string;
  host: string;                 // hostname (port optional)
  method?: string;              // verb (defaults to GET)
  path: string;                 // pathname (+ query)
  status?: number;
  mime?: string;                // response content-type
  length?: number;
  ms?: number;
  ts?: string;                  // ISO-8601
  params?: string[];
  req?: HttpMessage;
  res?: HttpMessage;
  note?: string;
  finding?: string;             // linked finding id, when the exchange is a confirmation
}
export interface HttpHistory {
  engagement?: string;
  generated_at?: string;
  source?: string;              // caido | burp | mitmproxy | zap | manual
  exchanges?: HttpExchange[];
}

// notebook.json (scripts/notebook.py / skills/_contract/notebook.schema.json) — "what an
// engagement gathers that isn't a finding yet": investigative leads (open→testing→promoted/dead),
// aggregated recon intel, the evidence locker, RoE, and test accounts. Cross-links the ledgers +
// findings (a promoted lead carries the RS- finding id) rather than duplicating them. Loose by design
// — every field but the few noted is optional; the view tolerates partial/missing sections.
export type LeadStatus = "open" | "testing" | "promoted" | "dead";
export interface NotebookLead {
  id: string;
  status: LeadStatus;
  priority?: number;            // 1 (highest) .. 3
  title: string;
  host?: string;
  path?: string;
  owner?: string;
  hypothesis?: string;
  observations?: string[];
  next_steps?: string[];
  verdict?: string;             // present on `dead` (why it was closed)
  surface_ref?: string;         // -> surface_ledger.surfaces[].id
  promoted_to?: string;         // -> finding.id (RS-YYYY-NNN), present on `promoted`
  related?: string[];           // related finding ids
  discovered_by?: string;
  updated_at?: string;
}
export type ScopeTag = "in" | "out" | "takeover" | "other";
export interface NotebookSub { host: string; source?: string; resolves_to?: string; http_status?: number; scope?: ScopeTag; note?: string; }
export interface NotebookDns { type: string; name: string; value: string; note?: string; severity?: string; }
export interface NotebookNet { range: string; owner?: string; hosts?: string; ports?: string[]; note?: string; }
export interface NotebookContentRow { path: string; status?: number; type?: string; methods?: string[]; params?: string[]; note?: string; }
export interface NotebookDefense { control: string; where?: string; observed?: string; effect?: string; kind?: "block" | "gap" | "detect"; }
export interface NotebookOsint { source: string; fact: string; use?: string; }
export interface NotebookReconIntel {
  subdomains?: NotebookSub[];
  dns?: NotebookDns[];
  network?: NotebookNet[];
  content?: NotebookContentRow[];
  defenses?: NotebookDefense[];
  osint?: NotebookOsint[];
  sources?: Record<string, string>; // aggregated-from artifact paths
}
export interface NotebookEvidence { id?: string; name: string; kind?: string; size?: number; finding_id?: string; by?: string; captured_at?: string; sha256?: string; }
export interface NotebookRoeRule { allowed: boolean; text: string; }
export interface NotebookRoe {
  approach?: string;
  authorization?: string;
  window?: { from?: string; to?: string };
  in_scope?: string[];
  out_of_scope?: string[];
  rate_limit?: number | string;
  rules?: NotebookRoeRule[];
  contacts?: { label: string; value: string }[];
  egress?: string[];
}
export type AccountStatus = "active" | "expired" | "pending" | "retired";
export interface NotebookAccount { id: string; tenant?: string; role?: string; identity?: string; auth?: string; used_on?: string; status?: AccountStatus; used_for?: string; }
export interface Notebook {
  engagement?: string;
  target?: string;
  generated_at?: string;
  leads?: NotebookLead[];
  recon_intel?: NotebookReconIntel;
  evidence?: NotebookEvidence[];
  roe?: NotebookRoe;
  test_accounts?: NotebookAccount[];
}

export interface ConsoleData {
  engagements: Engagement[];
  activeEngagementId: string;
  findings: Finding[];
  chains: AttackChain[];
  agents: Agent[];
  activity: ActivityEvent[];
  assets: Asset[];
  services: Service[];
  tests: TestRun[];
  cveFeed?: CveFeed;
  coverage?: CoverageLedger;
  cveIntel?: CveIntel;
  content?: ContentMap;
  history?: HttpHistory;
  notebook?: Notebook;
}

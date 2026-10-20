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
}

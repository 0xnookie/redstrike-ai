// Sample engagement dataset — a self-contained demo so the console runs with no
// backend (the Claude Code skills produce the real JSON into the engagement dir).
// `example.com` is reserved for documentation. Findings mirror the finding.schema.json.

import type { ConsoleData, Engagement, Finding, AttackChain, Agent, ActivityEvent, Asset, Service } from "./types";

const ENG = "acme-corp-2026-10";

export const engagements: Engagement[] = [
  {
    id: ENG,
    name: "Acme Corp — external web assessment",
    target: "example.com",
    goal: "Reach the admin console and confirm access to sensitive user data across the public web estate.",
    status: "running",
    authorized_by: "Acme Corp Security (written authorization on file)",
    window: { start: "2026-10-12T00:00:00Z", end: "2026-10-26T23:59:59Z" },
    in_scope: { domains: ["*.example.com", "api.example.com", "app.example.com"], cidrs: ["203.0.113.0/24"], urls: [] },
    out_of_scope: { domains: ["admin.example.com"], cidrs: ["203.0.113.200/29"], urls: [] },
    rules: { no_dos: true, no_destructive: true, rate_limit_rps: 20, prod_touch_requires_approval: true, approval_required_phases: ["exploitation", "post-exploitation"] },
    phase_progress: { done: 7, total: 9 },
    starred: true,
  },
  {
    id: "acme-api-2026-10", name: "Acme API — authz & injection", target: "api.example.com",
    goal: "Evaluate object/function-level authorization (BOLA/BFLA) and injection on the order & user APIs.",
    status: "running", authorized_by: "Acme Corp Security",
    window: { start: "2026-10-14T00:00:00Z", end: "2026-10-28T23:59:59Z" },
    in_scope: { domains: ["api.example.com"], cidrs: [], urls: [] }, out_of_scope: { domains: [], cidrs: [], urls: [] },
    rules: { no_dos: true, no_destructive: true, rate_limit_rps: 20 },
    phase_progress: { done: 2, total: 6 },
    summary: { findings: 6, critical: 1, high: 2, medium: 2, low: 1, chains: 1 },
  },
  {
    id: "acme-shop-2026-10", name: "Acme Shop — payments & order flow", target: "shop.example.com",
    goal: "Assess payment, checkout and order endpoints for authorization, price tampering and race conditions.",
    status: "paused", authorized_by: "Acme Corp Security",
    window: { start: "2026-10-10T00:00:00Z", end: "2026-10-24T23:59:59Z" },
    in_scope: { domains: ["shop.example.com"], cidrs: [], urls: [] }, out_of_scope: { domains: [], cidrs: [], urls: [] },
    rules: { no_dos: true, no_destructive: true, rate_limit_rps: 10, prod_touch_requires_approval: true },
    phase_progress: { done: 3, total: 7 },
    summary: { findings: 4, critical: 0, high: 1, medium: 2, low: 1, chains: 0 },
  },
  {
    id: "acme-edge-2026-10", name: "Acme Edge — exposed surface recon", target: "example.com",
    goal: "Identify externally exposed, exploitable edge services (VPN / gateways).",
    status: "completed", authorized_by: "Acme Corp Security",
    window: { start: "2026-10-05T00:00:00Z", end: "2026-10-12T23:59:59Z" },
    in_scope: { domains: ["*.example.com"], cidrs: ["203.0.113.0/24"], urls: [] }, out_of_scope: { domains: [], cidrs: [], urls: [] },
    rules: { no_dos: true, no_destructive: true, rate_limit_rps: 20 },
    phase_progress: { done: 3, total: 3 },
    summary: { findings: 3, critical: 0, high: 0, medium: 2, low: 1, chains: 0 },
  },
];

// ---- findings (mirror finding.schema.json) ----
export const findings: Finding[] = [
  {
    id: "RS-2026-001", title: "SQL injection in product search (UNION-based)", asset: "https://api.example.com/v2/search",
    category: { cwe: "CWE-89", owasp: "A03:2021", wstg: "WSTG-INPV-05" }, attack_mapping: ["T1190"],
    severity: "critical", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    impact: "Full read/write access to the primary application database, including the users table (password hashes, PII).",
    reproduction: ["GET /v2/search?q=widget' UNION SELECT NULL,version(),NULL-- -", "Observe the DB version string rendered in the results list", "Enumerate information_schema.tables via the same injection point"],
    evidence: [{ type: "request_response", ref: "sqli-inband/poc/union-search.http" }, { type: "tool_output", ref: "sqli-inband/poc/sqlmap-redacted.txt" }],
    remediation: "Use parameterized queries / prepared statements for the search handler; apply least-privilege to the DB role. Do not concatenate user input into SQL.",
    references: ["https://owasp.org/www-community/attacks/SQL_Injection"],
    review: { verdict: "accepted", reviewer: "sqli-inband-verify", reviewed_at: "2026-10-18T10:00:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-002", title: "Authentication bypass → administrator account takeover", asset: "https://app.example.com/login",
    category: { cwe: "CWE-287", owasp: "A07:2021", wstg: "WSTG-ATHN-04" }, attack_mapping: ["T1078", "T1548"],
    severity: "critical", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N",
    impact: "An unauthenticated attacker can assume any account, including administrators, and reach the full admin console.",
    reproduction: ["Submit login with a crafted JWT whose 'role' claim is elevated and 'alg' set to none", "Server accepts the unsigned token", "Navigate to /admin — full access granted"],
    evidence: [{ type: "request_response", ref: "auth-bypass/poc/alg-none.http" }, { type: "screenshot", ref: "auth-bypass/poc/admin-console.png" }],
    remediation: "Reject tokens with alg=none; pin the expected algorithm server-side; verify signatures against the correct key.",
    references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    review: { verdict: "accepted", reviewer: "auth-bypass-verify", reviewed_at: "2026-10-18T10:20:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-003", title: "SSRF to cloud metadata → temporary credential theft", asset: "https://api.example.com/v2/fetch",
    category: { cwe: "CWE-918", owasp: "A10:2021", wstg: "WSTG-INPV-19" }, attack_mapping: ["T1552.005"],
    severity: "critical", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N",
    impact: "The 'fetch' feature reaches the cloud metadata endpoint, exposing short-lived IAM credentials for the app role.",
    reproduction: ['POST /v2/fetch {"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}', "Role name returned", "Request the role path to retrieve (redacted) temporary credentials"],
    evidence: [{ type: "request_response", ref: "ssrf-cloud/poc/imds.http" }, { type: "log", ref: "ssrf-cloud/poc/collaborator-hit.txt" }],
    remediation: "Allowlist egress destinations; block link-local/metadata ranges; require IMDSv2; isolate the fetch service.",
    references: ["https://owasp.org/www-community/attacks/Server_Side_Request_Forgery"],
    review: { verdict: "accepted", reviewer: "ssrf-cloud-verify", reviewed_at: "2026-10-18T10:40:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-004", title: "Stored XSS in support-ticket body (renders in agent console)", asset: "https://app.example.com/support/tickets",
    category: { cwe: "CWE-79", owasp: "A03:2021", wstg: "WSTG-INPV-02" }, attack_mapping: ["T1059.007"],
    severity: "high", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N",
    impact: "A customer-submitted ticket executes script in the support agent's authenticated session (session theft, actions as agent).",
    reproduction: ["Create a ticket whose body is an img tag with an onerror handler exfiltrating document.cookie", "A support agent opens the ticket in the console", "The payload fires in the agent's origin"],
    evidence: [{ type: "dom_capture", ref: "xss-stored/poc/ticket-dom.html" }, { type: "screenshot", ref: "xss-stored/poc/agent-alert.png" }],
    remediation: "Context-aware output encoding when rendering ticket content; a strict CSP; sanitize HTML on input.",
    references: ["https://owasp.org/www-community/attacks/xss/"],
    review: { verdict: "accepted", reviewer: "xss-stored-verify", reviewed_at: "2026-10-18T11:00:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-005", title: "Insecure deserialization in session cookie", asset: "https://app.example.com/",
    category: { cwe: "CWE-502", owasp: "A08:2021", wstg: "WSTG-INPV-11" }, attack_mapping: ["T1190"],
    severity: "high", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
    impact: "The session cookie is a serialized object; a benign URLDNS gadget proves attacker-controlled data is deserialized (RCE-adjacent).",
    reproduction: ["Decode the session cookie — it is a serialized object", "Replace with a URLDNS gadget pointing at the OOB host", "Observe the DNS callback on cookie processing"],
    evidence: [{ type: "poc_script", ref: "deserialization/poc/urldns.py" }, { type: "log", ref: "deserialization/poc/dns-callback.txt" }],
    remediation: "Do not deserialize untrusted data; use signed, opaque session identifiers; restrict gadget classes.",
    references: ["https://owasp.org/www-community/vulnerabilities/Deserialization_of_untrusted_data"],
    review: { verdict: "accepted", reviewer: "deserialization-verify", reviewed_at: "2026-10-18T11:30:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-006", title: "Reflected XSS in marketing campaign parameter", asset: "https://www.example.com/promo",
    category: { cwe: "CWE-79", owasp: "A03:2021", wstg: "WSTG-INPV-01" }, attack_mapping: ["T1059.007"],
    severity: "medium", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
    impact: "A crafted link executes attacker script in a victim's browser in the example.com origin.",
    reproduction: ["Request /promo with a ref parameter breaking out of the attribute into a script context", "The ref value is reflected unencoded in the page", "Script executes on load"],
    evidence: [{ type: "request_response", ref: "xss-reflected/poc/promo-ref.http" }],
    remediation: "HTML-encode reflected parameters; add a CSP; validate the 'ref' allowlist.",
    references: ["https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"],
    review: { verdict: "accepted", reviewer: "xss-reflected-verify", reviewed_at: "2026-10-18T11:45:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-007", title: "CSRF on email-change endpoint (no anti-CSRF token)", asset: "https://app.example.com/account/email",
    category: { cwe: "CWE-352", owasp: "A01:2021", wstg: "WSTG-SESS-05" }, attack_mapping: ["T1548"],
    severity: "medium", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:N",
    impact: "A cross-origin page can change a logged-in user's account email, enabling a password-reset takeover.",
    reproduction: ["Host an auto-submitting form POSTing to /account/email", "Logged-in victim visits the page", "Email changes with no token challenge; SameSite does not block it"],
    evidence: [{ type: "poc_script", ref: "csrf/poc/email-change.html" }],
    remediation: "Require a per-request anti-CSRF token; set SameSite=Lax/Strict; re-authenticate for sensitive changes.",
    references: ["https://owasp.org/www-community/attacks/csrf"],
    review: { verdict: "accepted", reviewer: "csrf-verify", reviewed_at: "2026-10-18T11:55:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-008", title: "Clickjacking — missing frame-ancestors / X-Frame-Options", asset: "https://www.example.com/account",
    category: { cwe: "CWE-1021", owasp: "A05:2021", wstg: "WSTG-CLNT-09" },
    severity: "low", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    impact: "Sensitive pages are framable, enabling UI-redress against state-changing actions.",
    reproduction: ["Frame /account in an attacker page", "No frame protections present", "Overlay a decoy to drive a sensitive click"],
    evidence: [{ type: "poc_script", ref: "clickjacking/poc/frame.html" }, { type: "screenshot", ref: "clickjacking/poc/overlay.png" }],
    remediation: "Set Content-Security-Policy: frame-ancestors 'self'; add X-Frame-Options: DENY on sensitive routes.",
    references: ["https://owasp.org/www-community/attacks/Clickjacking"],
    review: { verdict: "accepted", reviewer: "clickjacking-verify", reviewed_at: "2026-10-18T12:00:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-009", title: "Server technology & version disclosure", asset: "https://www.example.com/",
    category: { cwe: "CWE-200", owasp: "A05:2021", wstg: "WSTG-INFO-02" },
    severity: "info", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
    impact: "Response headers disclose the exact server and framework versions, easing targeted exploit selection.",
    reproduction: ["HEAD /", "Inspect Server and X-Powered-By headers"],
    evidence: [{ type: "request_response", ref: "security-headers/poc/banner.http" }],
    remediation: "Suppress or genericize version banners (Server, X-Powered-By).",
    references: ["https://owasp.org/www-project-web-security-testing-guide/"],
    review: { verdict: "accepted", reviewer: "security-headers-verify", reviewed_at: "2026-10-18T12:05:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-010", title: "Blind SQL injection (time-based) in report filter", asset: "https://api.example.com/v2/reports",
    category: { cwe: "CWE-89", owasp: "A03:2021", wstg: "WSTG-INPV-05" }, attack_mapping: ["T1190"],
    severity: "medium", potential_severity: "high", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
    impact: "A reliable time-based boolean differential confirms injection. Data extraction could not be shown because the staging DB is unseeded.",
    reproduction: ["POST a filter with a conditional time delay → +5s response", "Control with zero delay → baseline latency", "Differential reproducible across 10 trials"],
    evidence: [{ type: "tool_output", ref: "sqli-blind/poc/timing.txt" }],
    remediation: "Parameterize the report filter; least-privilege DB role.",
    references: ["https://owasp.org/www-community/attacks/Blind_SQL_Injection"],
    review: { verdict: "blocked", reviewer: "sqli-blind-verify", reviewed_at: "2026-10-18T12:20:00Z", scope_ok: true, notes: "Injection confirmed by timing; extraction blocked by unseeded staging DB — reported as demonstration-limited." }, engagement_id: ENG,
  },
  {
    id: "RS-2026-011", title: "Unauthenticated → cloud account compromise", asset: "https://api.example.com/v2/fetch",
    category: { cwe: "CWE-918", owasp: "A10:2021" }, composite: true,
    severity: "critical", confidence: "confirmed", status: "verified", cvss_vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    impact: "Chaining SSRF→metadata (RS-2026-003) with the leaked role enables pivot into the cloud account.",
    reproduction: ["See chain-001"], evidence: [{ type: "log", ref: "attack-chain/poc/chain-001.md" }],
    review: { verdict: "accepted", reviewer: "attack-chain-discovery-verify", reviewed_at: "2026-10-19T09:00:00Z", scope_ok: true }, engagement_id: ENG,
  },
  {
    id: "RS-2026-012", title: "Self-XSS in developer console paste", asset: "https://app.example.com/",
    category: { cwe: "CWE-79" }, severity: "low", confidence: "tentative", status: "rejected", cvss_vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
    impact: "Requires the victim to paste attacker code into their own console — no cross-user vector.",
    reproduction: ["Paste payload into DevTools console"], evidence: [{ type: "screenshot", ref: "xss-dom/poc/self-xss.png" }],
    review: { verdict: "rejected", reviewer: "xss-dom-verify", reviewed_at: "2026-10-17T15:00:00Z", scope_ok: true, notes: "No delivery path to another user; self-XSS is not a reportable vulnerability." }, engagement_id: ENG,
  },
];

// ---- attack chains (mirror attack_chain.schema.json) ----
export const chains: AttackChain[] = [
  {
    id: "chain-001", title: "Unauthenticated → cloud account compromise", feasibility: "demonstrated",
    steps: [
      { finding_id: "RS-2026-003", role: "entry", enables: "reach cloud metadata via SSRF" },
      { finding_id: "RS-2026-011", role: "escalation", enables: "use leaked role for cloud access" },
    ],
    preconditions: ["app IAM role has metadata-reachable permissions"],
    impact: "An external attacker with no credentials reaches the cloud control plane via the fetch feature.",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  },
  {
    id: "chain-002", title: "SQLi → admin takeover → console execution", feasibility: "plausible",
    steps: [
      { finding_id: "RS-2026-001", role: "entry", enables: "read admin password hashes" },
      { finding_id: "RS-2026-002", role: "pivot", enables: "assume an admin session" },
      { finding_id: "RS-2026-004", role: "escalation", enables: "execute in agent/admin console" },
    ],
    preconditions: ["admin hashes are crackable or session forgeable"],
    impact: "Database read via SQLi feeds the auth bypass, culminating in full admin console control.",
    cvss: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  },
];

// ---- agent fleet (executor + independent reviewer per skill) ----
const A = (
  slug: string, name: string, family: Agent["family"], tier: Agent["tier"], summary: string,
  status: Agent["status"], produced = 0, accepted = 0, rejected = 0, approvalGated = false
): Agent => ({ slug, name, family, tier, summary, reviewer: `${slug}-verify`, status, produced, accepted, rejected, approvalGated });

export const agents: Agent[] = [
  // Recon feeders (no reviewer gate — feed context)
  A("osint", "OSINT", "Recon", "Feeder", "Passive public intelligence on the org & domain.", "done"),
  A("host-discovery", "Host discovery", "Recon", "Feeder", "Subdomains, live hosts, ports, services, host tech.", "done"),
  A("content-discovery", "Content discovery", "Recon", "Feeder", "Crawl + historical URLs + custom wordlist brute-force.", "done"),
  A("js-analysis", "JS analysis", "Recon", "Feeder", "Endpoints, params, secrets, DOM sinks, libraries.", "done"),
  // Web vuln agents
  A("sqli-inband", "SQLi (in-band)", "Web", "Tier-1", "Error/union SQL injection returning data in-band.", "done", 1, 1, 0),
  A("sqli-blind", "SQLi (blind)", "Web", "Tier-1", "Boolean/time/OOB blind SQL injection.", "done", 1, 0, 0),
  A("auth-bypass", "Auth bypass", "Web", "Tier-1", "Forced browsing, response tampering, 2FA skip, reset flaws.", "done", 1, 1, 0),
  A("ssrf-cloud", "SSRF (cloud)", "Web", "Tier-1", "SSRF → cloud metadata credential theft.", "done", 1, 1, 0),
  A("xss-stored", "XSS (stored)", "Web", "Tier-1", "Cross-user stored script execution.", "done", 1, 1, 0),
  A("xss-reflected", "XSS (reflected)", "Web", "Tier-2", "Reflected script execution with context match.", "done", 1, 1, 0),
  A("xss-dom", "XSS (DOM)", "Web", "Tier-2", "Client-side source→sink taint execution.", "done", 1, 0, 1),
  A("deserialization", "Deserialization", "Web", "Tier-1", "Benign gadget proves the sink deserializes attacker data.", "done", 1, 1, 0),
  A("csrf", "CSRF", "Web", "Tier-2", "State-changing requests lacking effective anti-CSRF.", "done", 1, 1, 0),
  A("clickjacking", "Clickjacking", "Web", "Tier-2", "Frameable sensitive actions + UI-redress PoC.", "done", 1, 1, 0),
  A("security-headers", "Security headers", "Web", "Tier-2", "Missing/weak headers enabling a contextual attack.", "done", 1, 1, 0),
  A("idor", "IDOR", "Web", "Tier-1", "Object-level access control across two identities.", "running"),
  A("command-injection", "Command injection", "Web", "Tier-1", "OS command execution confirmed via OOB/timing.", "idle"),
  A("ssti", "SSTI", "Web", "Tier-1", "Server-side template expression evaluation.", "idle"),
  A("path-traversal-lfi", "Path traversal / LFI", "Web", "Tier-1", "Read a file outside the base dir; assess LFI-RCE.", "idle"),
  A("upload-rce", "Upload → RCE", "Web", "Tier-1", "Uploaded file executes server-side.", "idle"),
  A("jwt", "JWT attacks", "Web", "Tier-2", "alg:none / weak secret / key confusion / claim tamper.", "idle"),
  A("business-logic", "Business logic", "Web", "Tier-2", "Model workflows + invariants, break them for impact.", "idle"),
  A("race-condition", "Race condition", "Web", "Tier-2", "TOCTOU + limit-overrun on single-use actions.", "idle"),
  // AI / LLM
  A("prompt-injection", "Prompt injection", "AI / LLM", "Tier-2", "Direct/indirect/role injection past a guardrail (OWASP LLM01).", "idle"),
  A("sensitive-disclosure", "Sensitive disclosure", "AI / LLM", "Tier-2", "Real sensitive-data disclosure, corroborated (LLM02/07/08).", "idle"),
  A("excessive-agency", "Excessive agency", "AI / LLM", "Tier-2", "Drive the LLM's tools to a benign unauthorized action (LLM06).", "idle"),
  A("llm-output-handling", "LLM output handling", "AI / LLM", "Tier-2", "Model output executes at a downstream sink (LLM05).", "idle"),
  // Active Directory (approval-gated)
  A("ad-initial-access", "AD initial access", "Active Directory", "Tier-2", "Unauth → first valid domain credential.", "idle", 0, 0, 0, true),
  A("ad-kerberos", "AD Kerberos", "Active Directory", "Tier-2", "Kerberoast / AS-REP / delegation abuse.", "idle", 0, 0, 0, true),
  A("ad-adcs", "AD ADCS (ESC1-8)", "Active Directory", "Tier-2", "Abuse a vulnerable template/CA to issue + auth a cert.", "idle", 0, 0, 0, true),
  // Post-exploitation (approval-gated)
  A("linux-privesc", "Linux privesc", "Post-Exploitation", "Tier-2", "Enumerate + confirm a vector to root benignly.", "idle", 0, 0, 0, true),
  A("windows-privesc", "Windows privesc", "Post-Exploitation", "Tier-2", "Benign SYSTEM/admin via the claimed vector.", "idle", 0, 0, 0, true),
  A("container-escape", "Container escape", "Post-Exploitation", "Tier-2", "Break out to the host benignly via a named misconfig.", "idle", 0, 0, 0, true),
  // Smart contract
  A("sc-reentrancy", "SC reentrancy", "Smart Contract", "Tier-2", "CEI violation drains funds on a local fork.", "idle"),
  A("sc-access-control", "SC access control", "Smart Contract", "Tier-2", "Unauthorized privileged on-chain action.", "idle"),
  // Mobile / IoT
  A("mobile", "Mobile app", "Mobile / IoT", "Tier-2", "Android/iOS static+dynamic, mapped to OWASP MASVS.", "idle", 0, 0, 0, true),
  A("iot", "IoT / embedded", "Mobile / IoT", "Tier-2", "Firmware extraction, hardcoded creds, update flaws.", "idle", 0, 0, 0, true),
  // Capabilities (Tier-3)
  A("attack-chain-discovery", "Attack-chain discovery", "Capabilities", "Tier-3", "Compose accepted findings into kill chains.", "done", 1, 1, 0),
  A("cve-intelligence", "CVE intelligence", "Capabilities", "Tier-3", "Map components to version-matched reachable CVEs.", "done"),
  A("exploit-generator", "Exploit generator", "Capabilities", "Tier-3", "Turn an accepted finding into a scoped benign PoC.", "idle"),
  A("exploit-dev", "Exploit dev", "Capabilities", "Tier-3", "Triaged crash → benign control-of-execution PoC.", "idle", 0, 0, 0, true),
];

// ---- activity timeline ----
export const activity: ActivityEvent[] = [
  { id: "ev-01", ts: "2026-10-12T08:02:00Z", actor: "orchestrator", kind: "note", title: "Engagement authorized & scope locked", detail: "RoE accepted · rate limit 20 rps · exploitation + post-exploitation gated." },
  { id: "ev-02", ts: "2026-10-12T08:15:00Z", actor: "host-discovery", kind: "recon", title: "18 assets discovered across example.com", detail: "5 subdomains · 3 IPs · 2 services · 4 endpoints." },
  { id: "ev-03", ts: "2026-10-12T09:40:00Z", actor: "js-analysis", kind: "recon", title: "Extracted 42 endpoints and 6 params from bundles", detail: "Flagged /v2/fetch and /v2/search as injectable candidates." },
  { id: "ev-04", ts: "2026-10-15T13:10:00Z", actor: "sqli-inband", kind: "finding", title: "SQL injection in product search", refId: "RS-2026-001", severity: "critical" },
  { id: "ev-05", ts: "2026-10-18T10:00:00Z", actor: "sqli-inband-verify", kind: "review", title: "Reviewer accepted RS-2026-001", refId: "RS-2026-001", verdict: "accepted", detail: "Data returned via union; read-only & minimal." },
  { id: "ev-06", ts: "2026-10-16T11:25:00Z", actor: "ssrf-cloud", kind: "approval", title: "Approval requested: exploitation phase", detail: "SSRF → metadata credential retrieval requires sign-off." },
  { id: "ev-07", ts: "2026-10-16T11:40:00Z", actor: "orchestrator", kind: "approval", title: "Exploitation approved by operator", verdict: "accepted" },
  { id: "ev-08", ts: "2026-10-16T12:05:00Z", actor: "ssrf-cloud", kind: "finding", title: "SSRF to cloud metadata → credential theft", refId: "RS-2026-003", severity: "critical" },
  { id: "ev-09", ts: "2026-10-17T09:30:00Z", actor: "auth-bypass", kind: "finding", title: "Authentication bypass → admin takeover", refId: "RS-2026-002", severity: "critical" },
  { id: "ev-10", ts: "2026-10-17T15:00:00Z", actor: "xss-dom-verify", kind: "review", title: "Reviewer rejected RS-2026-012 (self-XSS)", refId: "RS-2026-012", verdict: "rejected", detail: "No cross-user delivery path." },
  { id: "ev-11", ts: "2026-10-18T12:20:00Z", actor: "sqli-blind-verify", kind: "review", title: "RS-2026-010 marked demonstration-limited", refId: "RS-2026-010", verdict: "blocked", detail: "Injection confirmed; extraction blocked by unseeded DB." },
  { id: "ev-12", ts: "2026-10-19T09:00:00Z", actor: "attack-chain-discovery", kind: "chain", title: "Kill chain composed: unauth → cloud compromise", refId: "chain-001", detail: "SSRF (RS-2026-003) → leaked role → cloud control plane." },
  { id: "ev-13", ts: "2026-10-19T14:30:00Z", actor: "idor", kind: "tool_use", title: "IDOR agent probing /v1/orders across two identities", detail: "Running — enumerating object references." },
];

// ---- assets ----
const mkAsset = (id: string, value: string, kind: Asset["kind"], scope: Asset["scope"], coverage: Asset["coverage"], f = 0, tech?: string[], parent?: string): Asset =>
  ({ id, value, kind, scope, coverage, findings: f, tech, parent });
export const assets: Asset[] = [
  mkAsset("as-root", "example.com", "domain", "in", "tested", 0, ["DNS"]),
  mkAsset("as-www", "www.example.com", "subdomain", "in", "tested", 3, ["nginx", "React"], "example.com"),
  mkAsset("as-api", "api.example.com", "subdomain", "in", "tested", 3, ["Express", "MSSQL"], "example.com"),
  mkAsset("as-app", "app.example.com", "subdomain", "in", "tested", 4, ["nginx", "Java"], "example.com"),
  mkAsset("as-shop", "shop.example.com", "subdomain", "in", "in-progress", 0, ["Magento"], "example.com"),
  mkAsset("as-admin", "admin.example.com", "subdomain", "out", "untested", 0, ["Element-UI"], "example.com"),
  mkAsset("as-ip1", "203.0.113.10", "ip", "in", "tested", 0, ["HTTP", "HTTPS"]),
  mkAsset("as-ip2", "203.0.113.24", "ip", "in", "in-progress", 0, ["SSH"]),
  mkAsset("as-ip3", "203.0.113.205", "ip", "out", "untested", 0),
  mkAsset("as-cidr", "203.0.113.0/24", "cidr", "in", "in-progress", 0),
  mkAsset("as-svc1", "api.example.com:443", "service", "in", "tested", 6, ["TLS 1.3"], "api.example.com"),
  mkAsset("as-svc2", "app.example.com:443", "service", "in", "tested", 5, ["TLS 1.3"], "app.example.com"),
  mkAsset("as-ep1", "/v2/search", "endpoint", "in", "tested", 1, ["GET"], "api.example.com"),
  mkAsset("as-ep2", "/v2/fetch", "endpoint", "in", "tested", 2, ["POST"], "api.example.com"),
  mkAsset("as-ep3", "/v2/reports", "endpoint", "in", "tested", 1, ["POST"], "api.example.com"),
  mkAsset("as-ep4", "/login", "endpoint", "in", "tested", 1, ["POST"], "app.example.com"),
  mkAsset("as-ep5", "/support/tickets", "endpoint", "in", "tested", 1, ["GET", "POST"], "app.example.com"),
  mkAsset("as-ep6", "/account/email", "endpoint", "in", "tested", 1, ["POST"], "app.example.com"),
];

// ---- open ports + services (from host-discovery / host_discovery.json) ----
export const services: Service[] = [
  { id: "sv-01", host: "www.example.com", ip: "203.0.113.10", port: 80, proto: "tcp", service: "http", product: "nginx", version: "1.25.3", state: "open", title: "Acme Corp", findings: 0 },
  { id: "sv-02", host: "www.example.com", ip: "203.0.113.10", port: 443, proto: "tcp", service: "https", product: "nginx", version: "1.25.3", state: "open", tls: "TLS 1.3", title: "Acme Corp", findings: 3 },
  { id: "sv-03", host: "api.example.com", ip: "203.0.113.11", port: 443, proto: "tcp", service: "https", product: "Express", version: "4.17.1", state: "open", tls: "TLS 1.3", title: "Acme API v2", findings: 6, flagged: "outdated" },
  { id: "sv-04", host: "api.example.com", ip: "203.0.113.11", port: 80, proto: "tcp", service: "http", product: "nginx", version: "1.25.3", state: "open", title: "301 → https", findings: 0 },
  { id: "sv-05", host: "app.example.com", ip: "203.0.113.12", port: 443, proto: "tcp", service: "https", product: "Apache Tomcat", version: "9.0.71", state: "open", tls: "TLS 1.2", title: "Acme App", findings: 5 },
  { id: "sv-06", host: "app.example.com", ip: "203.0.113.12", port: 8080, proto: "tcp", service: "http-proxy", product: "Apache Tomcat", version: "9.0.71", state: "open", title: "Manager console", findings: 0, flagged: "exposed" },
  { id: "sv-07", host: "shop.example.com", ip: "203.0.113.13", port: 443, proto: "tcp", service: "https", product: "Apache httpd", version: "2.4.57", state: "open", tls: "TLS 1.3", title: "Acme Shop", findings: 0 },
  { id: "sv-08", host: "203.0.113.24", ip: "203.0.113.24", port: 22, proto: "tcp", service: "ssh", product: "OpenSSH", version: "8.9p1", state: "open", findings: 0, flagged: "exposed" },
  { id: "sv-09", host: "203.0.113.24", ip: "203.0.113.24", port: 3306, proto: "tcp", service: "mysql", product: "MySQL", version: "8.0.34", state: "filtered", findings: 0 },
  { id: "sv-10", host: "vpn.example.com", ip: "203.0.113.25", port: 443, proto: "tcp", service: "https", product: "SSL-VPN portal", state: "open", tls: "TLS 1.2", title: "VPN login", findings: 0, flagged: "edge" },
  { id: "sv-11", host: "vpn.example.com", ip: "203.0.113.25", port: 500, proto: "udp", service: "isakmp", product: "IKE", state: "open", findings: 0, flagged: "edge" },
  { id: "sv-12", host: "mail.example.com", ip: "203.0.113.14", port: 25, proto: "tcp", service: "smtp", product: "Postfix", version: "3.7.4", state: "open", findings: 0 },
  { id: "sv-13", host: "mail.example.com", ip: "203.0.113.14", port: 993, proto: "tcp", service: "imaps", product: "Dovecot", state: "open", tls: "TLS 1.3", findings: 0 },
  { id: "sv-14", host: "admin.example.com", ip: "203.0.113.205", port: 443, proto: "tcp", service: "https", product: "Element-UI", state: "open", tls: "TLS 1.2", title: "Admin", findings: 0, flagged: "out-of-scope" },
];

export const sampleData: ConsoleData = {
  engagements,
  activeEngagementId: ENG,
  findings,
  chains,
  agents,
  activity,
  assets,
  services,
};

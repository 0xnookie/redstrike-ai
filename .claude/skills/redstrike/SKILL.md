---
name: redstrike
description: Start and run a full web penetration test / security assessment end-to-end. Invoke this whenever the user asks to pentest, security-test, assess, audit, or "conduct a penetration test against" a website they own or are authorized to test — e.g. "I'm a pentester, my company owns <site>, conduct a penetration test against it", "run a full web pentest on <site>", "test the security of our website <site>", "assess <site> for vulnerabilities". It confirms AUTHORIZATION + scope first, then runs recon (OSINT + host/content discovery + JS analysis), routes to the vulnerability-category agents (each gated by its independent reviewer subagent), chains findings, and assembles the report. The Redstrike entry point / engagement orchestrator.
---

You are the **Redstrike Engagement Orchestrator** (Tier-3 mission agent; see `skills/_contract/agent-tiers.md`).
Drive the whole engagement through the gates — never skip a gate, never scan without authorization.

**NO-AD-HOC INVARIANT.** Every active probe runs **inside its executor skill**, which persists to that
skill's `findings.json` and is gated by its independent `*-verify` reviewer. **Never break out of the
framework to run a loose `curl`/`python`/`urllib` probe whose output lands only in the terminal** — an
unpersisted, unreviewed probe *did not happen*: it is invisible to the coverage/surface ledgers,
unreproducible, and can never become a finding. The ONLY exception is a single one-off `curl` to confirm a
signature (`skills/_contract/tooling.md`). This is *why the framework exists* — ad-hoc throws its value
(persistence, review, ledgers, chain-of-custody) away. Per `skills/_contract/engagement-discipline.md`.

## 0. Authorization & scope intake — MANDATORY, before anything active
This is a real offensive test. **Establish authorization before any active scanning.**

**Launched by the `redstrike` CLI?** If this engagement dir already holds a filled `scope.yaml`
and `runtime/authorization.json` (and the appended RoE states §0 is satisfied), the operator
recorded authorization + scope + the go-ahead at launcher init — treat steps 3–4 as **DONE**:
read `scope.yaml`, confirm the window is open, and proceed. Do **not** re-ask for a go-ahead
(interactive prompts aren't available in every launch context). STOP only if `scope.yaml` is
missing/incomplete, the window is closed, or a target falls outside scope.

1. **Target** — extract the website(s) from the request.
2. **Authorization** — the user must OWN the target or hold written authorization. If the request states
   it (e.g. "my company owns <site>"), record that as `authorized_by`. If authorization is unclear,
   **STOP and ask** — do not scan. Passive OSINT may begin; active scanning waits for step 4.
3. **Scope** — create `engagements/<client>-<date>/` and write `scope.yaml` (copy `engagements/_template/scope.yaml`):
   `in_scope.domains` = the target (+ ask which subdomains are in scope); `out_of_scope` = anything the
   user excludes; RoE defaults `no_dos: true`, a conservative `rate_limit_rps`, and
   `approval_required_phases: [exploitation, post-exploitation]`; set `window` + `authorized_by`; add an
   `oob.collaborator` if the user has one (needed for blind SSRF/XSS/XXE/SQLi — otherwise note those are limited).
4. **Confirm** — summarize the target, scope, and plan back to the user and get an explicit **go for active
   scanning**. (This is the human approval the RoE gate requires.) `skills/_contract/roe-gate.md` governs everything. Generate the formal **Rules of Engagement** document now with `redstrike-engagement-docs` (pre-engagement mode) from the scope.

**Preflight — execution environment + transport (before any active work).** Establish these alongside
scope/authorization, before the first active request:
- **Execution environment** — detect where tools run. On a native Linux/Kali host, run directly; on
  **Windows/macOS the redstrike docker container IS the toolchain — route every tool call through it**
  (`docker exec <container> …`), never the host shell. Per `skills/_contract/tooling.md` → "Execution
  environment — on non-Linux, the container IS the toolchain".
- **Proxy** — **ask the operator whether Burp or Caido is running and on what host:port**; if so, route all
  traffic through it (set `RS_PROXY` + `HTTP(S)_PROXY`). Always ask — the operator may decline. Per
  `skills/_contract/proxy.md §0`.
- **Rate cap** — read `scope.yaml`'s `rate_limit_rps` and carry it as a hard ceiling into every scan flag
  (`nuclei -rl`, `ffuf -rate`, …). Per `skills/_contract/roe-gate.md` (rate-limit enforcement).
(If launched by the `redstrike` CLI with these already recorded in `runtime/`, treat as **DONE** — mirror the
"Launched by the `redstrike` CLI?" logic above.)

## 1. Recon (Tier 1)  → into the engagement dir, each mechanical-gated
`redstrike-osint` (passive) → `redstrike-host-discovery` → `redstrike-content-discovery`
(builds the custom wordlist) → `redstrike-js-analysis` *(CONDITIONAL — only if the target serves
client-side JS; for a pure API / JS-less target, skip it with an explicit N/A note)*.
Run `redstrike-cve-intelligence` to prioritize.

**After recon, build the surface-coverage ledger — MANDATORY, every engagement:**
`python scripts/surface.py --plan --engagement <dir>` enumerates every discovered surface element
(endpoint/param/identity/form/API/sink/header/upload/auth-flow) as `discovered`. It is **idempotent** —
re-run it as late feeders (authz-context identities, js-analysis) and the re-convergence loop add surface;
it preserves marks and only appends new elements (`--fresh` forces a rebuild). As each executor consumes an
element, mark it (`surface.py --mark <id> --status tested --by <skill>`), or `--status skipped --reason …`.
This is the capstone recall control: category coverage proves which CLASSES ran; this proves how much of the
real SURFACE each was tested against. A surface left `discovered` at close is an `untested-surface` recall
gap. **The gate is strict:** once a report exists, `verify_completion.py` hard-fails if the ledger is
MISSING, empty-but-present, or still has untested routed surface — so emitting it is not optional. See
`skills/_contract/surface-ledger.md`.

**After recon, also build the engagement notebook — every engagement:** `python scripts/notebook.py --plan
--engagement <dir>` aggregates the recon intel (subdomains, DNS, network, content) + seeds leads (source-audit
candidates, dangling DNS, the re-convergence inbox), and write the **RoE + test accounts** into it at scope
time. Where the ledgers answer *"did we cover this?"*, the notebook answers *"what did we learn and what are we
chasing?"* — leads (open→testing→`promoted`/`dead`-with-verdict), evidence, RoE, accounts. As the hunt runs,
mark each lead (`notebook.py --mark L-<n> --status promoted --finding RS-… | --status dead --verdict …`). It is
the one artifact that makes a **zero-finding engagement legible** (the recon + the killed leads still show in
the console). Gate is **soft** — encouraged, never fails. See `skills/_contract/notebook.md`.

**Host-discovery MUST persist `<engagement>/host-discovery/host_discovery.json`** (the structured
`{live_hosts, api_endpoints}` map) — even for a single in-scope host. It is what populates the console's
Assets/Ports views; a recon pass that only saves pages + `signals.json` leaves them empty, and the
engagement gate warns when it is missing.

**Provision ≥2 test identities + an authenticated recon pass.** The multi-identity classes (IDOR/BOLA/BFLA
via `authz-context`/`api-context`) need **two accounts**; without them that whole surface is unmapped and the
classes are starved. Do NOT surrender those classes just because accounts weren't handed in:
- Recon emits **`flow:registration`** (content-discovery / js-analysis emit it into `signals.json` when a
  **public self-service signup** exists — see their "Signals emitted" sections). When it is present,
  **self-provision two test accounts** (register them yourself, TEST accounts only), **record each with
  `redstrike accounts add <eng> …`** — the launcher then auto-materializes `runtime/auth.env` so BOTH
  identities actually reach the authz/api executors (never hand-edit `auth.env`). Then content-discovery
  crawls the **authenticated** surface and diffs it against unauth, and the ≥2 identities IDOR/BOLA/BFLA
  require are available.
- A **`blocked: needs accounts`** terminal state for authz/api is permitted **ONLY after a registration
  attempt actually failed** (signup gated/invite-only/CAPTCHA-walled, recorded as the block reason) — never
  as a first resort when `flow:registration` was signalled. If there is no public signup and the operator
  supplied no accounts, record the block with that concrete reason.
- If the operator supplied accounts, register them with `redstrike accounts add` (same auto-materialize
  path) and use them. Map multi-step workflows (checkout/reset/upload/admin) as state for
  `business-logic`/`race-condition`. **Never authenticate with found or real credentials.**

## 2. Vuln categories (Tier 2)  → route DETERMINISTICALLY, then track coverage
Routing is **deterministic, not improvised.** The authoritative source is
`skills/_contract/routing-map.json` (every category, the recon **signals** that trigger it, its phase).

**a. Plan the coverage ledger.** After recon, gather the recon signals and run:
`python scripts/coverage.py --plan --signals <signals.json|-> --phases web[,ai-llm,web3,…] --engagement <dir>`
The recon feeders emit the signals; e.g. host-discovery's dangling-DNS triage (`scripts/dangling_dns.py`,
`dangling_dns.json`) emits **`asset:dangling-dns`** when a takeover candidate surfaces, so
`subdomain-takeover` is routed rather than skipped — fold every feeder's emitted signals into `signals.json`.
→ writes `<dir>/coverage_ledger.json`, marking every category `pending` (routed → **must run**),
`skipped` (no trigger matched — **with a stated reason**), or `n/a` (phase not in scope). With no signals
it attempts every in-scope category (recall-safe default). **A category is never skipped silently** — only
with a recorded reason. The formerly un-triggered classes are now wired in: `nosql-injection`,
`ldap-injection`, `prototype-pollution`, `race-condition`, `parameter-pollution`, `crypto-attacks`,
`tls-attacks`, `supply-chain`. (`ai-llm`/`web3`/internal phases auto-activate from their signal.)

**b. Run every `pending` category — as CONCURRENT, model-diverse WAVES (not one at a time).** The hunt is
a parallel multi-model swarm batched by rank, not a single serial pass. This is the DEFAULT, in-process:
- **Batch by rank into waves.** Take the `pending` categories in ascending `hunt_plan.json` `rank` (§2.5;
  fall back to routing-map order when no plan) and split them into WAVES of a handful of classes each —
  the highest-value, best-evidenced classes in the first wave.
- **Fan out each wave as CONCURRENT, PER-CLASS-LABELLED units — one trackable unit per class.** The
  console Task-flow view folds the live `autorun.jsonl` tool-call stream (`console/lib/control.ts`
  `foldRunObject`), and it renders a DISTINCT per-class node only when the class is NAMED in the stream, so
  dispatch each class as its own labelled unit, NOT as one umbrella "hunt everything" task:
  - **Emit one `TaskCreate` per class FIRST, with the class slug in the subject.** Lead the subject with
    that class's executor skill slug as a literal hyphenated token — a real slug from the category's
    routing-map `agents[]` (e.g. `xss-reflected: hunt the search param`, `sqli-inband: probe the id param`,
    `idor: cross-identity object access`, `ssrf-inband: fetch-param test`). `control.ts` `startTask` names
    the node `skillForSubject(subject)`, which resolves that slug to a `redstrike-<slug>` node — so every
    class becomes its own visible node. Without the slug in a subject the whole hunt collapses to ONE
    umbrella node and the per-class xss/sqli/ssrf/… nodes never appear.
  - **Then run that class concurrently with the others in the wave.** Each class runs its `<class>-context`
    feeder (if any) → the variant/category agents for its class, spawned as parallel `Agent`/Task subagents
    that run at the SAME time (the same mechanism the `*-verify` reviewers use) — do NOT run them one after
    another. When you spawn an executor subagent, carry the class in its label (description) so a spawned
    `Agent` node is also class-attributable, since the fold names a spawned subagent by its `subagent_type`.
- **NEVER collapse classes into anonymous `general-purpose` batches.** Do NOT run N classes as a handful of
  generic `subagent_type: general-purpose` family batches under one top-level task: the fold names a spawned
  subagent by its `subagent_type`, so family batches all render as identical, class-less "general-purpose"
  nodes — the stream can no longer tell which classes ran, and that anonymity is exactly where the
  `*-verify` gate got silently skipped in a live headless run. A handful-at-a-time wave is fine; the
  requirement is that EACH class is its own slug-named, independently-reviewed unit in the stream (a
  per-class `TaskCreate` and/or a class-labelled subagent), never folded into a nameless batch.
- **Model diversity across a wave.** Spawn the executors on a MIX of models (set each subagent's model on
  the `Agent` tool) — the higher-value / `deep` / high-`severity_ceiling` classes on the stronger model
  (`opus`), the rest on `sonnet` — because a differently-modelled pass catches bugs one model misses
  (this is what the manual hunter swarm did, and it is what raised recall on the large engagement). For a
  class whose `hunt_plan.json` `depth_budget.diversity_pass` is true (typical of a `deep` budget), run a
  SECOND pass over the same sinks on a DIFFERENT model. Reviewer (`*-verify`) subagents may run on the
  cheaper model per the routing policy.
- **Each executor writes ITS OWN `<skill>/findings.json`** — never a shared file — so concurrent executors
  in a wave never collide on a write.
- **A FORK/SUBAGENT-RUN EXECUTOR CANNOT SELF-GATE — the PARENT owns the reviewer gate AND `report.md`.**
  When an executor skill runs inside a `fork`/`Agent` subagent (the autonomous parallel-hunt mode above), that
  subagent **cannot spawn its own `<class>-verify` reviewer** (no nested delegation — a subagent can't launch a
  subagent) and **cannot write `report.md`** (the harness blocks subagent report writes). So a subagent executor
  must **hand its findings back to you (the parent)** by writing only its `<skill>/findings.json` with the
  `review{}` block **UNSET** (`review.reviewer` left blank — it must NEVER self-attest a verdict), and **you,
  the parent, then (1) spawn the `<class>-verify` reviewer** (the MERGE/DEDUP checkpoint below) **and (2) write
  the executor's `report.md`.** If the parent skips this, the reviewer gate — the whole point of the gated-
  executor discipline — is silently skipped for every finding a fork produced. **The mechanical backstop:** a
  subagent-produced finding carries no real `*-verify` `review.reviewer`, and `verify_completion.py --engagement`
  HARD-FAILS any reportable finding whose reviewer is not a roster `*-verify` agent (§2 "After EACH findings-
  producing skill"; `verify-base.md` "Independent review is mandatory") — so an un-reviewed fork finding can
  never reach a report. Treat an un-reviewed `findings.json` returned from a subagent as the flag "reviewer not
  yet run": run it before the wave is complete.
- **MERGE / DEDUP CHECKPOINT after each wave (before the next one).** When the wave's executors return:
  **hand every executor's findings to its matching independent `<skill>-verify` reviewer FIRST — spawn each
  as its own `Agent` subagent (`subagent_type: <skill>-verify`, e.g. `xss-reflected-verify`,
  `sqli-inband-verify`, `idor-verify`). The fold renders each as a DISTINCT per-class reviewer node, and the
  spawn is what enforces the executor→reviewer trust contract. This gate is NON-SKIPPABLE: only reviewer-
  `accepted` findings advance, and the verdict MUST come from that independent `*-verify` agent — never your
  own self-attestation (§2 "After EACH findings-producing skill"). A wave is not complete until every
  executor that produced findings has had its `<skill>-verify` reviewer run.** Then reconcile the ledgers by
  CALLING the scripts (never hand-editing the JSON): `scripts/coverage.py --mark <class> --status attempted|blocked
  --count N [--escalations …]` for each class, `scripts/surface.py --mark` for the surface each executor
  consumed, and `scripts/dedup.py --engagement <dir>` to collapse the same bug found by two executors.
  These writers are concurrency-safe; `coverage.py` stays the SOLE ledger owner. Then re-invoke
  `redstrike-strategist` (§2.5) to re-rank the REMAINING queue and run the next wave — until no `pending`
  category remains.
- **Depth per class.** Let each class's `hunt_plan.json` `depth_budget` tune how much breadth beyond the
  escalation floor its executor spends (`standard`/`deep` → invoke `parameter-optimization` proactively on
  high-value sinks; `deep` → the diversity pass above). The depth budget can only ADD effort — every
  `pending` class still owes the full escalation floor below, whatever rank or budget it got.

**When a class returns EMPTY on a recon-signalled surface, climb the `scripts/escalation.py` ladder before
calling it clean, and RECORD each technique you tried:**
`python scripts/coverage.py --mark <class> --status attempted --count 0 --escalations derive-not-assume,encoding-ladder`
— this persists ladder progress on the ledger entry so the recall-audit shallow-clear gate (§2d) can tell an
exhausted, honest clear from an untrustworthy first-payload clear. An empty high-prior class with an
UNEXHAUSTED ladder is a HARD recall gap at report time.
**Record ONLY techniques you ACTUALLY ran** — never bulk-stamp the full ladder across classes to clear a
gap you didn't work (the safety classifier flags that as undermining oversight). If a residual ladder step
is genuinely environment-blocked (no OOB collaborator, single identity, browser declined), don't fake it —
honest-close it with the recall-audit `--accept` writer (§2d).
Human-readable mirror of the map:
- **white-box (ONLY if `scope.yaml` grants authorized source access — a `scope.source` block / `source:available`):** run `redstrike-source-audit` once in recon → `source-audit/source_context.json`, a routed `file:line → vuln class → executor` candidate map. Its per-class dangerous-sink candidates feed the matching `<class>-context` feeder below as higher-confidence leads (a grep hit is a LEAD the executor must still PROVE at runtime); secret candidates → `redstrike-secrets`, dependency candidates → `redstrike-cve-intelligence`. Then, in the SAME source-granted path, run `redstrike-code-audit` **AFTER** `source-audit` (repo at `scope.source.local_path`, default `engagements/<id>/source/`): it CONFIRMS those leads by inter-procedural, framework-aware reasoning (not re-grep) into reviewer-gated findings and emits `code-audit/fuzz_targets.jsonl`. Hand `fuzz_targets.jsonl` to `redstrike-fuzzing` (white-box seed targets; `fuzzing` runs/minimizes/proves the crash, gated by `fuzzing-verify`); then `redstrike-attack-chain-discovery` composes the confirmed chains (`code-audit/chains.jsonl`) with the rest of the accepted-findings corpus; then reporting. No source access ⇒ skip the whole white-box path (pure black-box run).
- reflected/stored/dom input + sinks → `redstrike-xss-context` → `xss-*`
- injectable params → `redstrike-sqli-context` → `sqli-*` **and** `redstrike-nosql-injection` ; interpreter sinks → `redstrike-injection-context` → `ssti`/`command-injection`/`deserialization`. **Black-box caveat:** `sink:template`/`sink:command` are only emitted by a white-box source-audit (or limited js-analysis), so on a pure black-box run the injection family can SKIP for lack of a sink signal even though a server-side sink may exist. Do not treat that as a proven negative — probe `ssti`/`command-injection`/`deserialization` behaviorally (timing/OOB) on injectable params; recall-audit flags a `sink-class-skipped-blackbox` medium gap for exactly this.
- URL-fetching params → `redstrike-ssrf-context` → `ssrf-*` ; `redstrike-open-redirect`
- object ids + roles (≥2 accounts) → `redstrike-authz-context` → `idor`/`privesc` ; APIs → `redstrike-api-context` → `bola-bfla`/`graphql`
- XML endpoints → `redstrike-xxe-context` → `xxe-*` ; file/upload params → `redstrike-file-context` → `path-traversal-lfi`/`upload-rce`
- auth flows → `redstrike-auth-context` → `auth-bypass`/`jwt`/`oauth` ; opaque non-JWT tokens → `redstrike-crypto-attacks`
- login/search forms → `redstrike-ldap-injection` ; JS/Node + object params → `redstrike-prototype-pollution` ; single-use/limited actions → `redstrike-race-condition`
- exposed files/dirs/panels surfaced by content-discovery (`/.git`, `.env`, backups, actuators, dir listing) → `redstrike-exposed-surface`
- **baseline (always run):** `redstrike-security-headers`, `redstrike-secrets`, `redstrike-exposed-surface`, `redstrike-cors`, `redstrike-clickjacking`, `redstrike-cve-intelligence`, `redstrike-tls-attacks` (if HTTPS), `redstrike-parameter-pollution` (if params)
- plus as triggered: `csrf`, `host-header`, `cache-poisoning`, `request-smuggling`*, `subdomain-takeover`, `business-logic`, `supply-chain`
- **AI/LLM** (chat/assistant/LLM feature) → `redstrike-llm-context` → `prompt-injection` (LLM01) / `sensitive-disclosure` (LLM02/07/08) / `excessive-agency` (LLM06) / `llm-output-handling` (LLM05)

**Ledger-writer discipline (HARD).** The coverage, surface and re-convergence ledgers are written ONLY by
their scripts (`scripts/coverage.py`, `scripts/surface.py`, `scripts/reconverge.py`) — **never hand-edit the
JSON.** The scripts enforce the status/kind enums and the closed signal vocabulary at write time; a
hand-edit bypasses that and can fold an out-of-vocab signal or non-enum surface kind into a ledger, where it
routes to nothing and masks a recall gap. Once a report exists, `verify_completion.py`'s
coordination-integrity gate HARD-fails on exactly that — an out-of-vocab signal in `signals_used` /
`triggers_matched` / the inbox, or a non-enum surface kind in the ledger/inbox.

**c. Gate on coverage.** `python scripts/coverage.py --validate --engagement <dir>` must pass before
reporting: every map category is accounted for and **nothing is left `pending`**. Once a consolidated
report exists, `verify_completion.py --engagement` HARD-FAILS on any unaccounted category.

**d. Recall audit — the "what did we miss?" altitude (before reporting).** Coverage proves categories ran;
this checks the clears are REAL. Launch the independent **`recall-audit`** reviewer subagent
(`skills/_contract/recall-audit.md`; deterministic engine `scripts/recall_audit.py <dir>`). It flags
`shallow-clear` (empty on a recon-signalled surface with the `escalation.md` ladder unexhausted — read
from each category's persisted `escalations` list, §2b), `skipped-but-signalled`, and never-run routes.
Every **REAL-MISS** it returns must be re-hunted (run the next escalation step — and record it with
`coverage.py --mark … --escalations …` — / un-skip the route) or, when it is genuinely unclosable
(no OOB collaborator, single identity, browser declined, CAPTCHA-walled signup), **honest-closed with the
accept writer: `python scripts/recall_audit.py --accept <type:category> --engagement <dir> --blocker
<named-blocker> --reason <why>`** — the `--blocker` is a REQUIRED closed-vocabulary reason, so an accept
states "couldn't, because X", never "tried, trust us"; the writer refuses a non-gap or a blank/off-vocab
blocker, and (for `shallow-clear`) requires `--ladder-run` techniques validated against the real ladder —
**before reporting**. Then run `python scripts/close.py --engagement <dir>` before the completion gate so
the diagnostics record and the recall accepts the gate reads are both current.

**e. Re-convergence — feed findings BACK into recon until a fixpoint (before reporting).** The hunt
DISCOVERS new surface the initial recon never saw: an SSRF reaching an internal host / cloud metadata, a
finding leaking an API base-url / vhost / subdomain / new params, an auth bypass yielding the second
identity, a config leak exposing new endpoints. **When an executor discovers new surface/signal it appends
an observation to `<engagement>/reconvergence/inbox.jsonl`** (`{"source","signals":[…],"surface":[{kind,
value}]}`). Then loop: `python scripts/reconverge.py --plan --engagement <dir>` → `--apply` flips the
classes that new signal/surface routes to back to `pending` and folds the delta into both ledgers → **run
those re-opened classes against the new surface** → repeat until `reconverge.py --validate` passes (the
fixpoint — a pass that adds nothing new). A new signal that matches an **out-of-phase** class (e.g.
`asset:smart-contract` ⇒ web3) is a `replan_candidate` for YOU to decide on (scope), never auto-activated.
A **`content`-kind** discovery (a sitemap/robots/API schema) is NOT a testable surface element and is never
dropped: `--apply` routes it to `reconvergence/content_followups.jsonl` for **content-discovery** to re-run
URL/object-ref extraction over it (the extracted endpoints/params then flow back as normal surface).
Once a report exists over a non-empty inbox that hasn't re-converged, `verify_completion.py` hard-fails.
See `skills/_contract/reconvergence.md`. This is breadth DISCOVERED DURING the hunt — the symmetric control
to the escalation ladder (depth) and the surface ledger (recon-time breadth).

**After EACH findings-producing skill:** run its mechanical gate (`verify_completion.py`), then launch its
`<skill>-verify` reviewer subagent. **Only `accepted` findings advance.** The verdict must come from that
**independent `<class>-verify` agent — never your own self-attestation**: once a report exists,
`verify_completion.py --engagement` HARD-FAILS any reportable finding whose `review.reviewer` is not a real
`*-verify` agent (`orchestrator-self-verify`, a human, blank). If a finding's class genuinely has no reviewer
in the roster, that is a roster gap — route it to the closest reviewer, or record an explicit, auditable
operator-accept in `<eng>/reviews/self_verified_accepts.json` (`{"RS-…": "why no reviewer covers this class"}`)
that names the reviewer to backfill. See `_contract/verify-base.md` → "Independent review is mandatory".
**If a finding reveals new surface
(internal host, new identity, API base-url, subdomain, new params), append it to the re-convergence inbox
(§2e) so it gets routed — a finding is also a recon signal.**

## 2.5 Hunt ordering — the strategist  (ORDER + DEPTH-BUDGET only; never a gate)
After `coverage.py --plan` and `surface.py --plan` build the ledgers (§2a), run **`redstrike-strategist`**
once more before the §2b pending-class loop. It reads the post-recon state (`coverage_ledger.json`,
`surface_ledger.json`, the `*_context.json` feeders, `notebook.json`, `cve_intel.json`) and emits
**`<engagement>/hunt_plan.json`** (schema `skills/_contract/hunt_plan.schema.json`): a **ranked hunt
queue** over the `pending` classes plus a **per-class depth budget** (`floor`/`standard`/`deep`) and a
rationale.

**CONSUME it for ORDERING the §2b loop:** iterate "run every `pending` category" in ascending
`hunt_plan.json` `rank` (highest-value, best-evidenced classes first) instead of map order, and let each
class's `depth_budget` tune how much breadth beyond the escalation floor its executor spends — a
`standard`/`deep` budget is the cue to invoke `parameter-optimization` proactively on high-value sinks
and (for `deep`) run a diversity pass. **Re-invoke the strategist after each wave of findings** to
re-rank the REMAINING (not-yet-`done`) queue — a confirmed finding can raise a related class for chaining
or let an exhausted one fall.

**ABSOLUTE INVARIANT — the strategist changes ONLY the order and depth of work, never the scope of it:**
it never marks a class `skipped` (`hunt_plan.json` has no such state) and **never writes any ledger** —
`coverage.py` stays the SOLE ledger owner. Ordering and budget are an **optimization on top of a
recall-safe floor, not a replacement for it**: every `pending` class in the coverage ledger must still
run (the §2c coverage gate is unchanged) and every high-prior surface still owes the full escalation
ladder (the §2d recall audit + `verify-base.md` check #5 are unchanged), whatever rank or budget it got.
A class the strategist mis-ranks low or under-budgets therefore still surfaces as a **shallow-clear** and
is caught before reporting. If `hunt_plan.json` is missing or stale, fall back to map order — hunt
ordering is an efficiency aid, **never a gate**, so its absence can never block or shrink the hunt.

## 2.6 Zero-finding close — classify degraded vs clean (reliability; empty ≠ clean)
A hunt that produced nothing has TWO very different meanings and they must never be conflated: a **real
clean test** (the surface was reached and exercised, nothing found) vs a **degraded/blocked run** (a WAF
or gateway blocked the requests, a dependency failed, recon came back empty). The run engine records this
in `runtime/diagnostics.json` (latest `runs[]` entry — schema `skills/_contract/diagnostics.schema.json`;
the `redstrike run` runloop writes it automatically, and the interactive Skill path writes it via
`scripts/close.py` — see below); your job is to make the close **honest and explicit**.

- **Executors note blocked-response observations.** When a `<class>` executor sees sustained blocking —
  `403`/`429`, a JS/CAPTCHA challenge page, or a provider block banner on a large share of requests — it
  records that as a reliability observation (it is both an escalation cue AND a transport-health signal),
  so the run's `transport_health` reflects the block and the clear is attributable, not silently "clean".
  A **sudden estate-wide 403** — hosts recon saw as `200` now uniformly denied — is the signature of a **WAF
  IP-reputation ban** (per `skills/_contract/anti-automation-ladder.md`): the egress is burned, so the close
  is `degraded-empty`/`blocked`, **never clean**, and recovery is halt/back-off/rotate egress, never evade.
- **Write + classify the close before reporting.** The interactive Skill path writes no run record by
  itself, so at EVERY close run **`python scripts/close.py --engagement <dir>`** — it reads findings +
  rate/transport state off disk and appends an honest `runs[]` entry (`produced-findings` with the real
  count across root / per-skill / consolidated layouts; else `clean-tested` ONLY when the surface was
  genuinely reached and exercised; else `degraded-empty` / `failed` with a concrete `degraded_reason`, e.g.
  "gateway blocked 95% of requests on app.example.com"). A transport-`blocked` host means the clear is
  **inconclusive, not clean** — carry that into §4. Run close.py BEFORE the completion gate (§2d) so the
  diagnostics gate reads THIS engagement's real outcome, not a stale CLI-init leg.
- **Enforced, not advisory.** The completion gate auto-marks a WAF-blocked host's web coverage categories
  `blocked` (transport-sourced reason), HARD-fails a zero-finding report whose diagnostics outcome is
  missing or an unexplained empty, **and HARD-fails a report WITH findings whose latest diagnostics run
  contradicts it** (a stale `degraded-empty`/`0` while the report carries findings). So neither an empty
  close that cannot say *why* nor a stale record that contradicts the findings can ship — run
  `scripts/close.py` and align the diagnostics outcome with reality before `redstrike-reporting`.

## 3. Chain + exploit  (approval-gated)
`redstrike-attack-chain-discovery` composes accepted findings into kill chains. For high-value accepted
findings, `redstrike-exploit-generator` produces a benign working PoC (**approval + kill switch**).

**Post-exploitation (approval-gated):** on a landed host → `redstrike-linux-privesc` / `redstrike-windows-privesc`.
For internal / assumed-breach / **Active Directory** engagements → `redstrike-ad-context` →
`ad-kerberos` / `ad-acl-abuse` / `ad-adcs` / `ad-lateral-movement` (requires an authorized foothold).

## 3.5 Cross-model exhaustion adversary — disprove "engagement complete" (HARD, LAST before reporting)
Every gate up to here faces PRECISION ("is each reported finding real?") or the recall RULES it has; none
independently disproves the top-level claim that **the engagement is complete / every class is exhausted**,
and a same-model "are we done?" check is worthless (the model that called it done agrees with itself). So
after the coverage gate (§2c), the recall audit (§2d), re-convergence (§2e) and chaining (§3) all pass,
spawn the **model-pinned `exhaustion-adversary`** subagent (`.claude/agents/exhaustion-adversary.md`) — it
runs on a **DIFFERENT model** than the executors + their `*-verify` reviewers, in a fresh context, with the
default stance "there IS a gap". It reads the coverage + surface ledgers, `findings.json`, the deterministic
recall-audit output (`scripts/recall_audit.py <dir>`) and the audit trail, and hunts the gaps the
deterministic gates can't see — a category `attempted`/`done` with no depth substance, a surface marked
`tested` with no evidence artifact, a `blocked` mark never re-driven, a signalled surface shallow-cleared, a
feeder finding never chained — then writes **`<engagement>/runtime/exhaustion_review.json`** (schema
`skills/_contract/exhaustion_review.schema.json`) with a `no_gaps_found` / `found_gaps` verdict.

- **On `found_gaps`:** re-drive EXACTLY the categories/surfaces each gap names (escalate / un-block / chain /
  test the host), then **re-run the adversary** — repeat until it returns `no_gaps_found`.
- **On `no_gaps_found`:** the adversary could not disprove "complete" (every gap it raised is closed, or is
  genuinely-unclosable with a named blocker) → report-ready.
- **Enforced, not advisory + UN-ROUTABLE:** once a report exists `verify_completion.py --engagement`
  HARD-FAILS unless `runtime/exhaustion_review.json` carries `verdict=no_gaps_found` with every gap closed.
  There is **no operator-accept hatch** (mirrors the cross-model secondary-review gate) — only the
  adversary's OWN `no_gaps_found` concession passes it, so the "done" claim can never be self-attested.

## 4. Report
`redstrike-reporting` consolidates accepted findings → `<engagement>/report/findings_consolidated.json`.
Then `redstrike-engagement-docs` writes the full deliverable suite — the formal **report** + **attestation**
+ **retest** (alongside the **RoE**) → `<engagement>/docs/`. Accepted findings only.

## Gating & safety
A skill is done only when its checklist is all `- [x]`, `review.md` passes (exit 0), and — for findings
skills — every finding is `accepted`. Re-run failed/`needs-evidence` steps. **`exploitation` /
`post-exploitation` and anything RCE-class pause for explicit human approval.** Everything is scope-gated
and audit-logged in the engagement dir (the chain of custody). Honor the kill switch.

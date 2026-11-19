# Code audit — the reasoning arsenal (beyond grep)

White-box PROVING. `source-audit` already grepped + ran taint and routed candidates into `source_context.json`;
this agent READS the real code paths to CONFIRM or REFUTE them, reasons about classes a pattern scan can't
assert, and chains confirmed weaknesses. The deliverable is a traced path + a demonstration, not a pattern hit.
Read-only while reasoning; any dynamic step is approval-gated. Redact secret values; hand deps to `cve-intelligence`.

## 1. Model the app FIRST (the frame every judgment needs) → `app_model.json`
You cannot judge authorization or business logic without a model of intent. Build it before tracing:
- **Entry points** — HTTP routes/handlers, GraphQL resolvers, RPC/queue consumers, scheduled jobs, CLI, webhooks,
  framework lifecycle hooks. Each is an untrusted-input boundary. Record `file:line` + the handler symbol.
- **Trust boundaries** — where data crosses from attacker-controlled to trusted (request→service→store, service→
  service, tenant→tenant, user→admin). Note what AUTHN/AUTHZ each boundary is supposed to enforce.
- **Auth / session model** — how identity is established (session cookie / token / header), how roles/scopes are
  represented, and WHERE the check lives (middleware, decorator, per-handler, ORM scope, none). Build the
  identity × capability intent: who is SUPPOSED to be able to do what.
- **Data stores + privileged operations** — DBs, caches, object stores, secret stores; the operations that must
  be gated (money movement, role change, data export, deploy, impersonation, file write/exec).
Suggested `app_model.json` shape (object): `{ "entry_points": [{file,line,symbol,method,route,auth_expected}],
"trust_boundaries": [...], "auth_model": {mechanism, role_repr, guard_sites:[...]}, "data_stores": [...],
"privileged_ops": [{op, guarded_by, file, line}] }`.

## 2. Inter-procedural, framework-aware taint (confirm/refute each lead) → `analysis.jsonl`
A grep/taint scanner marks a sink "present" or "reachable" intra-file; it misses cross-file/cross-function flow,
framework auto-escaping, and context-sensitive sanitizers. For each `source_context.json` candidate (and any new
source you find), TRACE by reading:
- Follow the user-controlled value from the ENTRY POINT through every call, assignment, wrapper, and framework
  binding to the SINK — across files and functions. Record the call chain as `file:line` hops.
- At each hop, NAME any sanitizer / encoder / validator / type-coercion / framework auto-escape and decide if it
  neutralizes THIS value in THIS context (an HTML encoder does nothing for a SQL sink; a validator on a sibling
  field is irrelevant; a guard that runs AFTER the sink fires is too late; fail-open in a `try/except` doesn't
  sanitize). Per `_contract/counterevidence.md`: a safe sibling, a too-late control, a different-route control,
  and "a helper handles it" (unchecked) do NOT rule a candidate out.
- **Framework awareness** — know the defaults: ORM parameterization vs raw/string-built queries; template
  auto-escaping on vs raw/`|safe`/`dangerouslySetInnerHTML`; body-parser/mass-assign binding; default CSRF /
  auth middleware and the routes that OPT OUT. The vuln is usually where code LEAVES the safe default.
- Close each candidate: **confirmed** (traced unsanitized path to a dangerous sink) · **ruled-out** (a control on
  the path neutralizes it — cite it) · **open-proof-gap** (reachable-looking but a precondition blocks proof).
`analysis.jsonl` record (one per candidate): `{id, class, source:{file,line,param}, sink:{file,line,kind},
call_chain:[{file,line,note}], controls:[{file,line,kind,effective,why}], closure:"confirmed|ruled-out|
open-proof-gap", confidence, runtime_guard_uncertainty, lead_ref}`.

## 3. Classes a scanner can't ASSERT (reason against the model)
- **Broken / missing authorization (object-level / IDOR)** — a handler reads an object by a client-supplied id
  and never checks the identity OWNS it (no `where owner = current_user`, no tenant scope). Trace: entry → id read
  → store query → response. The absence is the finding; confirm it with two identities in the PoC.
- **Missing function-level authz (privesc)** — a privileged operation reachable by a lower role because the
  role/scope guard is absent, on the wrong route, or opt-out. Cross-check `app_model.auth_model.guard_sites`
  against `privileged_ops` — a privileged op with no guard site covering its route is the finding.
- **Business-logic invariant violations** — model the intended invariant (price ≥ 0, one coupon per order, balance
  never negative, state machine order) and find the path that breaks it (negative quantity, re-applied discount,
  skipped step, TOCTOU on a limit). Needs the model; grep cannot see intent.
- **Insecure defaults / misconfig in code** — debug on, permissive CORS built in code, default/weak secret,
  disabled cert check, overly broad permission grant, verbose errors.
- **Crypto misuse** — ECB, static/reused IV/nonce, hardcoded/predictable key, unauthenticated encryption,
  homemade MAC, `==` token compare (timing), weak hash for passwords/signatures. (JWT crypto → `jwt`.)
- **Unsafe deserialization** — attacker bytes into a native deserializer / unsafe loader reachable from an entry
  point → `deserialization` to prove; here, trace reachability + gadget availability.
- **SSRF / path traversal / injection** — a user-controlled URL/host the server fetches; a user path into a
  file read/include/write; user data into a command/query/template interpreter — all traced inter-procedurally.
- **Race conditions** — a check-then-act / limit / single-use action with no lock/transaction/idempotency key
  where concurrent requests break the invariant.
- **Mass assignment** — a bind/merge of request body straight into a model/record with no allow-list, letting a
  client set fields it shouldn't (role, owner, price, flags). → confirm reachable sink + unguarded field set.

## 4. Chaining confirmed weaknesses → `chains.jsonl`
Compose CONFIRMED findings (not candidates) into higher-impact kill-chains, **each leg a confirmed finding**:
- IDOR (read another user's record) + mass-assignment (set `role`) → account takeover / privesc.
- SSRF (server fetches attacker URL) + cloud metadata reachability → credential theft.
- Path traversal (write) + a code/exec path over the written file → RCE.
- Auth-bypass + a privileged op with no second check → full compromise.
Each `chains.jsonl` record: `{id, name, impact, legs:[{finding_id, role_in_chain}], precondition_notes}`. Every
`finding_id` MUST resolve to a confirmed entry in `findings.json`. A chain with any unconfirmed/assumed leg is
DROPPED (it may be seeded to `attack-chain-discovery` only as a candidate, never emitted as a finding here).
These confirmed chains SEED `attack-chain-discovery`, which composes cross-skill accepted findings post-review.

## 5. Evidence + confidence discipline (what the reviewer enforces)
- A finding = **(a)** a traced reachable path at `file:line` across the call chain + **(b)** a PoC/exploit sketch
  (or executed PoC / fuzz crash). Both halves, every time.
- Static-only path ⇒ `confidence: probable` + a stated runtime-guard uncertainty; `confirmed` needs dynamic proof.
- Precondition-blocked exploitation ⇒ demonstrated `severity` + `potential_severity`, confidence honest.
- Negative control where feasible: a benign variant of the request is handled correctly while the malicious one
  isn't — the difference is attributable to the bug, not noise.
- Evidence files go under `poc/<id>/` (e.g. `trace.md` with the annotated path, `poc.md`/`poc.*` the sketch or
  driver, dynamic output). Cite them in the finding's `evidence[]`.

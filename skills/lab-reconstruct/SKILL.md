# Lab Reconstruct (white-box lab bench)

> TIER-3 capability, REVIEW-ONLY. Given a WHITE-BOX engagement whose target repo is already cloned to
> `engagements/<id>/source/` + a dependency lockfile, rebuilds a LOCAL, OFFLINE Docker lab that mirrors the
> target stack so exploit-dev / fuzzing / destructive tests run against a replica instead of the live target.
> Makes NO security claim → `review.md` only (NO `verify.md`, NO reviewer, NO findings.json). The build is
> local + benign (no RoE/approval gate), but the lab RUNS THE TARGET'S CODE → honors container-safety posture.
> IRON GUARDRAIL: the lab is NEVER an oracle — see `## Safety`.
> Output: `lab/` (docker-compose.yml + Dockerfile(s) + lab_manifest.json + README.md).

## Interview
- **STEPS:** confirm white-box preconditions (`engagements/<id>/source/` present + a dependency lockfile) → ingest the recon artifacts (`source_context.json`, `host_discovery.json`, `cve_intel.json`, `content.json`) → derive the app framework + exact version from the lockfile (ground truth over any banner) → map each detected open backing port (db/cache/mail/search) to a backing service + a version-evidenced image → emit `lab/Dockerfile` (app built from `source/`, pinned to the lockfile) + `lab/docker-compose.yml` (app + one backing service per port, loopback-only, no `--privileged`/host-net) → record the HONESTY LAYER (`lab/lab_manifest.json`: per service → recon field + confidence + `mode` + `fidelity_tier`) → write `lab/README.md` (real-vs-stub + the IRON GUARDRAIL) → review.
- **TOOLS:** `jq` (parse the recon JSON), lockfile parse (`composer.lock`/`package-lock.json`/`yarn.lock`/`poetry.lock`/`Gemfile.lock`), `docker` / `docker compose` **config/build only** (validate the emitted compose; a run is operator-driven). Tool-first — `_contract/tooling.md`.
- **GOAL:** Turn an authorized white-box clone + its recon into a SAFE, OFFLINE replica bench that `exploit-generator` / `exploit-dev` / `code-audit` can develop and fuzz against — so a destructive or high-rate probe never touches the live target. Done = checklist `- [x]`, review passes.
- **OUTPUT:** `lab/docker-compose.yml`, `lab/Dockerfile` (+ per-service as needed), `lab/lab_manifest.json`, `lab/README.md`, `summary.md`, `logs/`.
- **DATA / RAG:** inputs = `engagements/<id>/source/` (the cloned target repo) + its lockfile + `source_context.json` (languages/deps/framework) + `host_discovery.json` (`live_hosts[].ports[]` → backing services) + `cve_intel.json` (component+version evidence) + `content.json` (routes/entry points, for a smoke check only). `refs/` = `lab_reconstruct.md` (the port→service matrix + base-image selection + the container-safety baseline). Chains FROM `source-audit` / `host-discovery` / `cve-intelligence` / `content-discovery`; chains TO `exploit-generator`, `exploit-dev`, `code-audit` (their one approval-gated step — the dynamic PoC / fuzz run — now has a LOCAL target).
- **DECOMPOSITION:** WHITE-BOX MODE ONLY for this MVP. No black-box facade (HTTP-replay / stub-route) mode — when `source/` + a lockfile are absent, this skill records the missing preconditions in `summary.md` and emits no lab (that is not a clean result). A future black-box facade is a separate capability.

## Goal
Produce a runnable, OFFLINE `lab/` that mirrors the target's app framework + version (from the real lockfile)
and its backing services (one per detected open port), with an honest `lab_manifest.json` that labels every
reconstruction's fidelity. DONE = `checklist.md` `- [x]` · `review.md` PASS (`lab_manifest.json` validates
against `_contract/lab_manifest.schema.json`).

## What do we want
- **App service** — built from `engagements/<id>/source/` (the real cloned code), base image at the framework +
  EXACT version the lockfile pins (a lockfile is ground truth; a `Server`/banner version is distro-backport-unreliable).
- **Backing services** — one per detected open port in `host_discovery.json` `live_hosts[].ports[]`: a database
  (3306/5432/1433/27017), a cache (6379/11211), a mail sink (25/587/1025), a search engine (9200/9300) —
  each at the version evidenced from `host_discovery`/`cve_intel`/`source_context`, or an honest inferred stub.
- **Honesty layer** — `lab_manifest.json`: for every service/image/version, the RECON FIELD + CONFIDENCE that
  justified it, the `mode` (always `white-box-exact` here), and the `fidelity_tier`
  (`exact-pin` / `version-matched` / `inferred-stub` / `placeholder`). Known gaps go in `unresolved[]`.
- **Container-safety posture** — loopback-only port exposure, no `--privileged`, no host networking, no real
  secrets baked in (redacted fingerprints only, fresh benign test secrets in their place).
- **README** — what is real (the app code) vs a stub (the backing services), the IRON GUARDRAIL, and that the
  lab is a DEV / REPRODUCTION bench, not a target.

## Fidelity tiers (label every reconstruction honestly — a stub is never dressed up as the real thing)
- **`exact-pin`** — the app, built from the real cloned `source/` and pinned to the real lockfile. Highest fidelity.
- **`version-matched`** — a backing service image at a version EVIDENCED from recon (a service+version banner in
  `host_discovery`, or a `cve_intel` component+version). The protocol + major version match; data/config do not.
- **`inferred-stub`** — a backing service inferred from an open PORT whose exact product/version was NOT evidenced
  (e.g. a generic `redis:7` for an open 6379 with no banner). The ROLE is reproduced; the version is a best guess.
- **`placeholder`** — recon surfaced only the role's presence, not its identity; a minimal stand-in so the app boots.
Confidence tracks the tier: `high` for a lockfile pin or a service+version banner; `medium` for presence + a
strong version signal; `low` for a port with no version evidence (which must read as `inferred-stub`/`placeholder`).

## Steps  (action · tool · output)
1. Confirm white-box preconditions — `engagements/<id>/source/` present AND a dependency lockfile exists · `ls` + lockfile detect · (gate; if absent → record in `summary.md`, emit no lab)
2. Ingest recon — `source_context.json`, `host_discovery.json`, `cve_intel.json`, `content.json` · `jq` · (seed)
3. Derive the app framework + EXACT version from the lockfile (prefer the lockfile over any banner) · lockfile parse · (into manifest)
4. Map each open backing port (`host_discovery.live_hosts[].ports[]`) → a backing service + a version-evidenced image per `refs/lab_reconstruct.md` · synth · (into manifest)
5. Emit `lab/Dockerfile` — app base image at the pinned framework version, COPY the cloned `source/`, install deps from the lockfile; NO secrets baked (redacted fingerprints only) · write · `lab/Dockerfile`
6. Emit `lab/docker-compose.yml` — the app service (build from `../source`) + one backing service per port; loopback-only (`127.0.0.1:`) exposure, NO `--privileged`, NO host networking · write · `lab/docker-compose.yml`
7. Emit `lab/lab_manifest.json` — per service: recon field + confidence + `mode` + `fidelity_tier`; `unresolved[]` for gaps; validate vs `_contract/lab_manifest.schema.json` · synth · `lab/lab_manifest.json`
8. Emit `lab/README.md` — real-vs-stub, the IRON GUARDRAIL, DEV/REPRO-bench framing · write · `lab/README.md`
9. Validate the emitted compose statically (`docker compose config`) — config-only, no up/run · `docker` · `logs/`
10. Emit summary · synth · `summary.md`
11. /REVIEW SKILL · `review.md`

## Tools
- `jq` (parse `source_context.json` / `host_discovery.json` / `cve_intel.json` / `content.json`)
- lockfile parse (`composer.lock` / `package-lock.json` / `yarn.lock` / `poetry.lock` / `Gemfile.lock`) — the EXACT version pins
- `docker` / `docker compose` — **`config` / `build` only** to validate the emitted files; a lab `up`/run is an operator step, never auto-fired here
- **Tool-first rule + roster:** `_contract/tooling.md`

## Inputs
- `engagements/<id>/source/` (the cloned target repo) + its dependency lockfile
- `source_context.json` (`_contract/source_context.schema.json`) · `host_discovery.json` (`_contract/host_discovery.schema.json`) · `cve_intel.json` (`_contract/cve_intel.schema.json`) · `content.json`
- `refs/lab_reconstruct.md` (port→service matrix · base-image selection · container-safety baseline)

## Outputs
`lab/docker-compose.yml` · `lab/Dockerfile` (+ per-service) · `lab/lab_manifest.json` · `lab/README.md` · `summary.md` · `logs/`

## Phases
- **Phase 1 (generic):** confirm white-box preconditions + ingest recon + derive the app framework/version from the lockfile.
- **Phase 2 (target-specific):** map open ports → backing services, emit the compose/Dockerfile(s) + the honesty manifest + README, and statically validate the compose.

## Safety
**IRON GUARDRAIL — the lab is NEVER an oracle.** Anything developed, triggered, or observed on the
reconstructed lab is **`replica-only`**: it is DEVELOPMENT evidence, not a finding. A replica result must be
**RE-CONFIRMED BENIGNLY on the live authorized target** before it can become a finding, and a replica
**NEGATIVE never marks a vuln class exhausted** (the replica can diverge from production — different data, config,
patch level, WAF, build flags — so a class that looks clean on the lab may still be live on the target). This is
baked into `lab/lab_manifest.json` (`never_an_oracle: true` + the per-service `fidelity_tier`), restated in
`lab/README.md`, and enforced at the reviewer layer by the additive guardrail in `_contract/verify-base.md`
(a finding whose ONLY proof is a local reconstructed lab/replica is NOT acceptable).

**A white-box rebuild RUNS THE TARGET'S CODE locally → treat `source/` and the built container as UNTRUSTED.**
Reuse the `docker/` bundle's conventions:
- **No `--privileged`**, no added capabilities, no host networking — the app and backing services run with
  Docker's default dropped-capability posture.
- **Loopback-only exposure** — publish every port to the host LOOPBACK (`127.0.0.1:`) only, never `0.0.0.0`;
  the lab is for your machine alone, not your network.
- **Never bake real secrets / credentials into the image or compose** — recon surfaces secrets as REDACTED
  FINGERPRINTS only (`lab_manifest.json` `redacted_secret_fingerprints`); the lab uses fresh BENIGN test
  secrets in their place. No client credential, token, or key is ever written into `lab/`.
- **The lab runs OFFLINE** — no egress to the live target or the internet is required to develop against it;
  keep it isolated so a replica probe can never reach production.

**`lab/` is a client-infra blueprint → it MUST NOT be committed.** The engagement directory
`engagements/<id>/` is already fully git-ignored (`engagements/.gitignore` ignores `*` except the template),
so `engagements/<id>/lab/` is covered. Confirm this holds; keep `lab/` under the engagement dir (never at the
repo root). This skill makes NO security claim and emits NO findings — so it has no RoE/approval gate (the
build is local + benign), but these container-safety + no-secrets + do-not-commit rules are mandatory.

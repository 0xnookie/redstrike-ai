# Lab Reconstruct — method, port→service matrix, base-image selection, container-safety baseline
# White-box MODE ONLY. Build a LOCAL, OFFLINE replica of an authorized target from its cloned source +
# recon. The lab is a DEV / REPRO bench, NEVER an oracle (see SKILL.md ## Safety).

## 0. Preconditions (hard gate)
White-box mode needs BOTH:
1. `engagements/<id>/source/` — the target repo, already cloned by the framework.
2. A dependency lockfile in that tree — the EXACT version pins (ground truth over any banner/Server header):
   `composer.lock` (PHP) · `package-lock.json` / `yarn.lock` / `pnpm-lock.yaml` (Node) · `poetry.lock` /
   `requirements.txt` with pins (Python) · `Gemfile.lock` (Ruby) · `go.sum` (Go) · `Cargo.lock` (Rust).
If either is missing, record it in `summary.md` and emit NO lab — an absent lab is a known gap, not a clean
result. (A black-box HTTP-replay facade is OUT OF SCOPE for this MVP — a separate future capability.)

## 1. Deriving the app framework + exact version (lockfile is ground truth)
Read the framework + runtime version from the lockfile, not a banner. Examples (TARGET-DESCRIPTIVE FACTS —
the base image is derived from the target's own recon, it credits no external project):
- `composer.lock` → `platform.php` / the `php` require + the framework package (e.g. a storefront/CMS package)
  and its version → app base image `FROM php:<x.y>-apache` (or `-fpm`), framework version from the package pin.
- `package-lock.json` / `yarn.lock` → the `engines.node` / the lockfile's resolved framework version →
  `FROM node:<major>-slim`.
- `poetry.lock` / pinned `requirements.txt` → the Python version marker + the web-framework pin →
  `FROM python:<x.y>-slim`.
- `Gemfile.lock` → `RUBY VERSION` + the framework gem → `FROM ruby:<x.y>-slim`.
Cross-check the derived version against `cve_intel.json` `components[].version` and `source_context.json`
`dependencies[]` — they should agree; if the lockfile and a recon banner disagree, PREFER THE LOCKFILE and note
the divergence in `lab_manifest.json` notes.

## 2. Port → backing-service matrix (from host_discovery.live_hosts[].ports[])
One backing service per DETECTED OPEN port. Pick the image version from the port's `service`+`version` banner
(host_discovery) or a matching `cve_intel` component; with no version evidence, use a current major and label it
`inferred-stub`. (Base images below are target-descriptive facts derived from recon.)

| Detected port(s)        | role     | backing image (version from recon, else a current major) | fidelity when version evidenced / not |
|-------------------------|----------|-----------------------------------------------------------|---------------------------------------|
| 3306                    | database | `mysql:<maj.min>` / `mariadb:<maj.min>`                    | version-matched / inferred-stub       |
| 5432                    | database | `postgres:<maj>`                                          | version-matched / inferred-stub       |
| 1433                    | database | `mcr.microsoft.com/mssql/server:<year>`                  | version-matched / inferred-stub       |
| 27017                   | database | `mongo:<maj>`                                            | version-matched / inferred-stub       |
| 6379                    | cache    | `redis:<maj>`                                            | version-matched / inferred-stub       |
| 11211                   | cache    | `memcached:<maj>`                                        | version-matched / inferred-stub       |
| 25 / 587 / 1025         | mail     | a local SMTP sink image (catch-all, web UI on a side port) | version-matched / inferred-stub       |
| 9200 / 9300             | search   | `elasticsearch:<maj.min>` / `opensearchproject/opensearch:<maj>` | version-matched / inferred-stub |
| 5672 / 15672            | queue    | `rabbitmq:<maj>-management`                             | version-matched / inferred-stub       |

Rules:
- Only emit a backing service for a port that host_discovery actually reports OPEN against an in-scope host —
  do not invent services the target doesn't run.
- A port with a crisp `service`+`version` banner → `version-matched`, `confidence: high`.
- A port open but with no version (banner suppressed / generic) → `inferred-stub`, `confidence: low`.
- A role whose identity recon couldn't pin at all → `placeholder` + an `unresolved[]` note.

## 3. Emitting lab/Dockerfile (the app)
```dockerfile
# syntax=docker/dockerfile:1
# App base at the framework+version the lockfile pins (derived from the target's own recon).
FROM php:8.1-apache            # <- example; your value comes from the lockfile
WORKDIR /app
# Deps pinned to the REAL lockfile (reproducible — the lockfile is ground truth, not `install` latest).
COPY source/composer.json source/composer.lock ./
RUN composer install --no-dev --no-interaction --prefer-dist   # or: npm ci / poetry install / bundle install --deployment
COPY source/ ./
# NO secrets baked. Benign TEST values only; real secrets stay as redacted fingerprints in lab_manifest.json.
ENV APP_ENV=local
EXPOSE 80
```
- Use `npm ci` / `composer install --locked` / `poetry install` / `bundle install --deployment` — the lockfile-
  enforcing install, so the replica matches the pinned dependency tree, not a fresh resolve.
- COPY the cloned `source/` as the app code — this is the ONLY `exact-pin` service (the real target code).

## 4. Emitting lab/docker-compose.yml (topology + the container-safety baseline)
```yaml
# OFFLINE DEV/REPRO bench for an authorized engagement. NEVER an oracle — re-confirm on the live target.
services:
  app:
    build:
      context: ..            # engagement dir; the Dockerfile COPYs source/
      dockerfile: lab/Dockerfile
    ports:
      - "127.0.0.1:8080:80"  # LOOPBACK ONLY — never 0.0.0.0
    environment:
      APP_ENV: local
      # benign TEST secrets only — no client credential/token/key
    depends_on: [db]
    # no privileged, no cap_add, no network_mode: host
  db:                        # one per detected open backing port
    image: mysql:8.0         # version from host_discovery/cve_intel, else a current major (inferred-stub)
    ports:
      - "127.0.0.1:3306:3306"
    environment:
      MYSQL_ROOT_PASSWORD: labtest-not-the-real-secret   # fresh benign test value
# no top-level `privileged`, no host networking, no shared host mounts beyond the build context.
```
Container-safety baseline (reuse the `docker/` bundle's conventions):
- **Loopback only** — every published port is `127.0.0.1:<host>:<container>`. Never bind `0.0.0.0`.
- **No `--privileged`**, no `cap_add`, no `security_opt` relaxations, no `network_mode: host`, no docker.sock mount.
- **No real secrets** — fresh benign test credentials in the compose/env; the target's real secrets live only as
  REDACTED FINGERPRINTS in `lab_manifest.json` (`redacted_secret_fingerprints`), never as a value anywhere in `lab/`.
- **Offline** — the app does not need egress to the live target or the internet to be developed against.

## 5. lab_manifest.json — the honesty layer (validate vs _contract/lab_manifest.schema.json)
Every service records WHY it was chosen so a consumer knows real-vs-stub at a glance:
```json
{
  "version": 1,
  "engagement": "<id>",
  "generated_at": "<ISO-8601>",
  "scope_ref": "engagements/<id>/scope.yaml",
  "mode": "white-box-exact",
  "never_an_oracle": true,
  "source_ref": "engagements/<id>/source",
  "lockfile": { "name": "composer.lock", "path": "source/composer.lock" },
  "services": [
    { "name": "app", "role": "app", "image": "php:8.1-apache", "version": "8.1", "stub": false,
      "build": { "context": "../source", "dockerfile": "Dockerfile" },
      "justification": { "recon_field": "source_context.dependencies[].name=php version=8.1",
        "recon_source": "lockfile", "confidence": "high", "mode": "white-box-exact", "fidelity_tier": "exact-pin" } },
    { "name": "db", "role": "database", "image": "mysql:8.0", "version": "8.0", "stub": true,
      "ports": [3306],
      "justification": { "recon_field": "host_discovery.live_hosts[].ports[].service=mysql version=8.0 @3306",
        "recon_source": "host_discovery", "confidence": "high", "mode": "white-box-exact", "fidelity_tier": "version-matched" } }
  ],
  "unresolved": ["port 6379 open but no version banner — emitted redis as inferred-stub"],
  "guardrail": "Replica-only. Re-confirm every observation benignly on the live authorized target before it is a finding; a replica negative never closes a class."
}
```

## 6. lab/README.md — must say
- What is REAL (the app service — the target's own code from `source/`) vs a STUB (the backing services —
  protocol/role stand-ins, not the target's data/config).
- The IRON GUARDRAIL: anything developed/observed here is REPLICA-ONLY; re-confirm benignly on the live
  authorized target before it is a finding; a replica NEGATIVE never marks a class exhausted.
- That the lab is a DEV / REPRODUCTION bench (exploit-dev / fuzz / destructive test offline), not a target,
  and not an authorization to touch anything outside `scope.yaml`.
- How to run it locally (`docker compose -f lab/docker-compose.yml up`) and that it is loopback-only.

## 7. Who consumes the lab
- `exploit-generator` — develop a benign PoC offline, then re-confirm it on the live target before it is a finding.
- `exploit-dev` — triage a crash + build a control-of-execution PoC against the replica binary/stack.
- `code-audit` — its ONE approval-gated step (the dynamic PoC / fuzz run) now has a LOCAL target instead of
  needing to fuzz the live site; the replica result is development evidence, re-confirmed on the target.
Each consumer treats a lab result as `replica-only` — development evidence that must be re-confirmed benignly
on the live authorized target before it becomes a finding.

# Lab Reconstruct — completion ledger
# `- [ ]` = NOT done, MUST be re-run · `- [x]` = done.

## Preconditions (white-box mode only)
- [ ] `engagements/<id>/source/` present (the cloned target repo)
- [ ] A dependency lockfile detected (`composer.lock`/`package-lock.json`/`yarn.lock`/`poetry.lock`/`Gemfile.lock`)
- [ ] If either is absent → recorded in `summary.md` as missing preconditions; NO lab emitted (not a clean result)

## Ingest + derive
- [ ] Recon ingested (`source_context.json`, `host_discovery.json`, `cve_intel.json`, `content.json`)
- [ ] App framework + EXACT version derived from the lockfile (lockfile ground truth, not a banner/Server header)
- [ ] Each open backing port (`host_discovery.live_hosts[].ports[]`) mapped → a backing service (db/cache/mail/search)

## Emit lab/
- [ ] `lab/Dockerfile` — app base image at the pinned framework version, builds from the cloned `source/`, deps from the lockfile
- [ ] `lab/docker-compose.yml` — app + one backing service per detected port
- [ ] Loopback-only exposure (`127.0.0.1:`), NO `--privileged`, NO host networking (container-safety baseline)
- [ ] NO real secrets baked (redacted fingerprints only; fresh benign test secrets in their place)
- [ ] `lab/lab_manifest.json` — per service: recon field + confidence + `mode: white-box-exact` + `fidelity_tier`; gaps in `unresolved[]`
- [ ] `lab/lab_manifest.json` validates against `_contract/lab_manifest.schema.json`
- [ ] `lab/README.md` — real-vs-stub + the IRON GUARDRAIL + DEV/REPRO-bench framing

## Guardrail + safety
- [ ] IRON GUARDRAIL present in BOTH `SKILL.md ## Safety` + `lab/README.md` (replica-only; re-confirm on the live target; a replica negative never closes a class)
- [ ] `lab_manifest.json` carries `never_an_oracle: true`
- [ ] Verified `engagements/<id>/lab/` is git-ignored (engagement dir already ignored; `lab/` not committed)

## Validate + emit
- [ ] Emitted compose statically validated (`docker compose config` — config-only, no `up`/run)
- [ ] summary.md
- [ ] /REVIEW SKILL passes

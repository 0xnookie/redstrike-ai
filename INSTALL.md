# Installing the Redstrike toolchain

Redstrike is **tool-first**: every skill drives real, battle-tested binaries (`nmap`, `ffuf`, `sqlmap`,
`impacket`, `nuclei`, …) rather than re-implementing them (see `skills/_contract/tooling.md`). Those tools
must be on the host that runs the engagement.

- **Platform:** Linux — **Kali** (recommended; ships most of these), Debian, or Parrot.
- **Windows:** run inside **WSL2 with Kali** (`wsl --install -d kali-linux`), then follow the Linux steps
  below. The native Windows checkout is fine for *developing* the framework, but engagements run on Linux.
- The roster is defined once in **`scripts/tools.manifest`** (168 tools across 19 categories) and consumed by
  both scripts below — add a tool there and both pick it up.
- To run engagements through the **`redstrike` CLI launcher** (Claude Code as the engine), see
  *The `redstrike` CLI* at the bottom of this file.

## Quickstart

```bash
# 1. See what you already have vs. what's missing
scripts/doctor.sh                 # checks every category, read-only

# 2. Install the everyday web-pentest set (glue + recon + web + password + interceptors)
scripts/install.sh                # == --core

# 3. …or install everything (adds AD, cloud, container, mobile, iot, wireless, binary, fuzzing, llm…)
scripts/install.sh --all

# 4. Confirm
scripts/doctor.sh
```

Add `~/.local/bin`, `~/go/bin`, and `~/.cargo/bin` to your `PATH` (the pipx/go/cargo installers drop
binaries there). `pipx ensurepath` handles the first.

## The two scripts

| Script | What it does |
|---|---|
| `scripts/doctor.sh` | **Read-only.** Reports present ✓ / missing ✗ / manual ⚙ per category and exits non-zero if anything auto-installable is missing — safe to run anywhere, and CI-friendly. |
| `scripts/install.sh` | Installs the missing tools by each one's declared method (`apt`, `pipx`, `go`, `cargo`, `gem`, `npm`, `pdtm`, vendor `script`, `git`). Idempotent (skips what's present), **non-fatal** (logs a failure and continues), Kali/Debian-guarded. |

Both accept the same scope arguments:

```bash
scripts/doctor.sh  --core            # glue + recon + web + password + intercept
scripts/install.sh --all             # every category
scripts/install.sh ad cloud          # only the named categories
scripts/install.sh --all --dry-run   # print the plan, change nothing
scripts/doctor.sh  --missing         # list only what's absent
```

**Categories:** `glue recon web password binary fuzzing ad cloud container mobile iot wireless llm aimodel
crypto sca intercept wordlists`.

## Tools you install by hand (`⚙ manual`)

These can't be dropped by `apt` on the tester host — GUI apps, vendor installers, or Windows/.NET agents you
stage onto a *target*. `doctor.sh` lists them but never counts them as failures.

| Tool | Why manual | Get it |
|---|---|---|
| Burp Suite | GUI proxy (Community ships with Kali) | https://portswigger.net/burp |
| Caido | GUI proxy | https://caido.io |
| Azure CLI (`az`) | vendor installer | https://learn.microsoft.com/cli/azure/install-azure-cli-linux |
| gcloud SDK | vendor installer | https://cloud.google.com/sdk/docs/install |
| `kubectl` | vendor / k8s apt repo | https://kubernetes.io/docs/tasks/tools/ |
| kubeletctl · peirates · amicontained | release binaries | their GitHub releases |
| MobSF | run via Docker | https://github.com/MobSF/Mobile-Security-Framework-MobSF |
| SharpHound · Rubeus · SharpSCCM | Windows .NET, staged on the target | their GitHub projects |
| RESTler | `dotnet build` | https://github.com/microsoft/restler-fuzzer |

Some `git`-method tools (jwt_tool, smuggler, krbrelayx, sccmhunter, cloud_enum, firmwalker, …) are cloned into
`~/redstrike-tools/` by `install.sh`; finish them per their README (`pip install -r requirements.txt`, `make`).
Override the clone dir with `REDSTRIKE_TOOLS_DIR`.

## Notes

- On **Debian/Parrot** (not Kali) some `apt` names won't exist. `install.sh` logs those as failures and keeps
  going — install them by the method `doctor.sh` prints, or add the Kali repo.
- ProjectDiscovery tools (`httpx`, `naabu`, `dnsx`, `subfinder`, `katana`, `nuclei`, `interactsh-client`) are
  installed together via `pdtm -ia`. If a Python `httpx` library shadows the PD binary, keep `~/go/bin` ahead
  of it on `PATH`.
- `REDSTRIKE_MANIFEST=/path/to/tools.manifest` points either script at an alternate roster.

## The `redstrike` CLI (launcher)

`cli/` provides **`redstrike`** — the launcher that runs **Claude Code as the engagement engine**,
scoped and human-gated (full docs: `cli/README.md`). It is separate from the tool roster above.

```bash
./cli/install.sh            # one command (Linux/macOS/WSL) — installs the `redstrike` command, repo baked in
#   (alt: pipx install ./cli, or run in place: PYTHONPATH=cli python3 -m redstrike_cli ...)
redstrike doctor            # engine + auth + platform + tool-roster preflight
redstrike install --core    # install the tool roster (wraps scripts/install.sh; --all or category names)
redstrike init "Acme Corp" --authorized-by "sec@acme / auth-ref" --domain '*.acme.com' \
  --i-confirm-authorization
redstrike run acme-corp-<date>        # launch Claude Code, scoped + gated (interactive)
```

- Requires the **`claude`** CLI (Claude Code) on `PATH` and **Python 3.10+**. Stdlib-only (PyYAML
  used if present).
- Installed out-of-tree, point it at this repo with `--repo <path>` or `export REDSTRIKE_REPO=<path>`
  (running it from inside the repo also works).
- **Auth:** `claude login` (subscription) or `CLAUDE_CODE_OAUTH_TOKEN` for unattended use.

### WSL2 specifics

Engagements run on **WSL2/Linux** (native Windows has no OS sandbox, so the scope gate leans on the
PreToolUse hook only there). On a fresh WSL2 Ubuntu you also want:

```bash
sudo apt install -y python3-venv       # ensurepip, needed by pipx / venv
sudo apt install -y bubblewrap socat   # the Bash sandbox (bwrap + socat) the network boundary uses
```

Install `claude` (Claude Code) **inside** WSL and run `claude login` there — a Windows login does not
carry into WSL.


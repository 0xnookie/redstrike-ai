# syntax=docker/dockerfile:1
#
# Redstrike AI — all-in-one image: the full tool roster + the web console + the
# control plane (launch & steer an authorized engagement from the browser), with
# Claude Code as the live engine (the lab-only Codex / Gemini CLIs are opt-in —
# build with REDSTRIKE_EXTRA_ENGINES=1).
#
# Build (from the repo root):   docker compose -f docker/docker-compose.yml build
# The tool scope defaults to --core (the everyday web-pentest set): a few GB, minutes.
# The full --all roster (~168 tools) is opt-in via REDSTRIKE_INSTALL_ARGS — see below
# and docker/README.md (it is large and compiles many tools from source).
#
# AUTHORIZED TESTING ONLY. The scope gate, launch gate, allowlist and audit trail
# are enforced by the redstrike launcher inside the container — unchanged here.

# Pinned by digest for reproducible builds (the rolling tag moves; the digest does not).
# To refresh: docker buildx imagetools inspect kalilinux/kali-rolling:latest  -> new digest.
FROM kalilinux/kali-rolling@sha256:1ff4a2be3849333687b3ed2b31bb5af0cd1b7c0a11ec7713feb5abe5a6b2795c

LABEL org.opencontainers.image.title="Redstrike AI" \
      org.opencontainers.image.description="Redstrike AI offensive-security framework — console + control plane + full toolchain (authorized testing only)" \
      org.opencontainers.image.source="https://github.com/0xnookie/redstrike-ai"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    REDSTRIKE_REPO=/opt/redstrike \
    GOPATH=/root/go \
    PATH=/usr/local/bin:/root/.local/bin:/root/go/bin:/root/.cargo/bin:/root/.pdtm/go/bin:/root/redstrike-tools/bin:/usr/bin:/bin:/usr/sbin:/sbin

# 1) Base prerequisites: package managers (for the tool installers) + the Bash-sandbox deps the
#    network boundary uses (bubblewrap + socat) + the libpcap RUNTIME lib. The heavy build
#    toolchain (Go/Rust/C/Ruby headers) is NOT installed here — it is installed, used, and purged
#    inside the tool-roster layer (step 3) so the compilers never persist in the runtime image.
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash sudo ca-certificates curl wget git unzip jq \
      python3 python3-venv python3-pip pipx \
      libpcap0.8 \
      bubblewrap socat dnsutils \
    && rm -rf /var/lib/apt/lists/*

# 2) Node.js 20 (covers claude-code / codex / gemini-cli; Node 20+ required by gemini).
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/redstrike

# 3) The tool roster FIRST, keyed only on the installer inputs, so editing the framework (or
#    refreshing the engine in step 4) does not bust this big, slow layer. install.sh is non-fatal
#    (it logs a miss and continues); `|| true` guards the build against a hard stop.
#    Scope defaults to --core (fast). Build the full roster, or named categories, with:
#      docker compose -f docker/docker-compose.yml build --build-arg REDSTRIKE_INSTALL_ARGS=--all
#      docker compose -f docker/docker-compose.yml build --build-arg REDSTRIKE_INSTALL_ARGS="recon web ad cloud"
ARG REDSTRIKE_INSTALL_ARGS=--core
COPY scripts/tools.manifest scripts/install.sh scripts/doctor.sh /opt/redstrike/scripts/
# The build toolchain (Go/Rust/C compilers + Ruby headers) is needed ONLY to COMPILE the Go/Rust/C
# tools in the roster. Install it, build the roster, then PURGE the compilers in the SAME layer so
# they do not bloat the final single-stage image — the compiled tool binaries and the Ruby runtime
# stay. (A later runtime `install.sh` re-adds a toolchain on demand, so nothing is lost for opt-ins.)
RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
      golang-go rustc cargo ruby ruby-dev \
      build-essential pkg-config libpcap-dev; \
    bash scripts/install.sh ${REDSTRIKE_INSTALL_ARGS} -y || true; \
    apt-get purge -y golang-go rustc cargo ruby-dev build-essential pkg-config libpcap-dev; \
    apt-get autoremove -y; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /root/go/pkg /root/.cargo/registry /root/.cargo/git \
           /root/.cache/go-build /tmp/* /var/tmp/*

# 4) Provider CLIs — AFTER the toolchain, so refreshing the engine doesn't rebuild the big layer.
#    - Claude Code  -> the ONE live engine today; always installed.
#    - Codex / Gemini -> OPT-IN (REDSTRIKE_EXTRA_ENGINES=1). When enabled, they are installed so
#      their auth (login or key) works; they are NOT yet live-capable engines (see cli/ENGINES.md +
#      docker/README.md). The default image omits them to stay lean.
#    CLI_CHANNEL pins/refreshes the Claude engine (a dist-tag like `latest`/`stable`, or an exact
#    version). Bumping it busts only this layer (+ the fast ones after it), so a rebuild can't keep
#    shipping a stale `claude` — the floor check in step 6b fails the build if the baked one is too old.
ARG CLI_CHANNEL=latest
# The lab-only extra engines (Codex / Gemini) are gated OFF by default, so the stock image ships
# ONLY the one live engine (Claude). They are pinned to exact versions for reproducibility. Opt in:
#   docker compose -f docker/docker-compose.yml build --build-arg REDSTRIKE_EXTRA_ENGINES=1
ARG REDSTRIKE_EXTRA_ENGINES=0
ARG CODEX_VERSION=0.169.0
ARG GEMINI_CLI_VERSION=0.68.0
RUN npm install -g "@anthropic-ai/claude-code@${CLI_CHANNEL}"; \
    if [ "${REDSTRIKE_EXTRA_ENGINES}" = "1" ]; then \
      npm install -g "@openai/codex@${CODEX_VERSION}" "@google/gemini-cli@${GEMINI_CLI_VERSION}"; \
    fi; \
    npm cache clean --force

# 5) The rest of the framework.
COPY . /opt/redstrike

# 6) The redstrike CLI on PATH, with this repo baked in as the engagement home.
RUN REDSTRIKE_PREFIX=/usr/local bash cli/install.sh || true

# 6b) Fail the build if the baked-in `claude` is below the launcher's required floor
#     (cli/redstrike_cli MIN_CLAUDE_VERSION) — this defeats a stale npm layer silently shipping an
#     old engine (which `redstrike doctor` would then reject at run time). Bump CLI_CHANNEL (step 3)
#     or rebuild that layer to refresh.
RUN python3 <<'PY'
import subprocess, re, sys
floor = tuple(map(int, re.search(r"MIN_CLAUDE_VERSION\s*=\s*\((\d+),\s*(\d+),\s*(\d+)\)",
               open("cli/redstrike_cli/__init__.py").read()).groups()))
out = subprocess.run(["claude", "--version"], capture_output=True, text=True).stdout
m = re.search(r"(\d+)\.(\d+)\.(\d+)", out)
got = tuple(map(int, m.groups())) if m else (0, 0, 0)
print(f"baked claude {got}, launcher floor {floor}")
if got < floor:
    sys.exit(f"ERROR: claude {got} < floor {floor} -- bump CLI_CHANNEL or rebuild the CLI layer (--no-cache)")
PY

# 7) Prebuild the console (Next.js static export) so the first open is instant.
#    `npm ci` enforces console/package-lock.json (reproducible), unlike `npm install`.
RUN npm --prefix console ci && npm --prefix console run build \
    && npm cache clean --force

# 8) Entrypoint: start the control plane (or exec a passed command, e.g. `claude login`).
RUN install -m 0755 docker/entrypoint.sh /usr/local/bin/redstrike-entrypoint

EXPOSE 8788
ENTRYPOINT ["/usr/local/bin/redstrike-entrypoint"]

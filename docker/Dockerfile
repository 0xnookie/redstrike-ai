# syntax=docker/dockerfile:1
#
# Redstrike AI — all-in-one image: the full tool roster + the web console + the
# control plane (launch & steer an authorized engagement from the browser), with
# Claude Code as the live engine and the Codex / Gemini CLIs installed for auth.
#
# Build (from the repo root):   docker compose -f docker/docker-compose.yml build
# The tool scope defaults to --core (the everyday web-pentest set): a few GB, minutes.
# The full --all roster (~168 tools) is opt-in via REDSTRIKE_INSTALL_ARGS — see below
# and docker/README.md (it is large and compiles many tools from source).
#
# AUTHORIZED TESTING ONLY. The scope gate, launch gate, allowlist and audit trail
# are enforced by the redstrike launcher inside the container — unchanged here.

FROM kalilinux/kali-rolling

LABEL org.opencontainers.image.title="Redstrike AI" \
      org.opencontainers.image.description="Redstrike AI offensive-security framework — console + control plane + full toolchain (authorized testing only)" \
      org.opencontainers.image.source="https://github.com/0xnookie/redstrike-ai"

ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    REDSTRIKE_REPO=/opt/redstrike \
    GOPATH=/root/go \
    PATH=/usr/local/bin:/root/.local/bin:/root/go/bin:/root/.cargo/bin:/root/.pdtm/go/bin:/root/redstrike-tools/bin:/usr/bin:/bin:/usr/sbin:/sbin

# 1) Base prerequisites: package managers (for the tool installers) + build deps +
#    the Bash-sandbox deps the network boundary uses (bubblewrap + socat).
RUN apt-get update && apt-get install -y --no-install-recommends \
      bash sudo ca-certificates curl wget git unzip jq \
      python3 python3-venv python3-pip pipx \
      golang-go rustc cargo ruby ruby-dev \
      build-essential pkg-config libpcap-dev \
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
RUN bash scripts/install.sh ${REDSTRIKE_INSTALL_ARGS} -y || true

# 4) Provider CLIs — AFTER the toolchain, so refreshing the engine doesn't rebuild the big layer.
#    - Claude Code  -> the ONE live engine today.
#    - Codex / Gemini -> installed so their auth (login or key) works in this image;
#      they are NOT yet live-capable engines (see cli/ENGINES.md + docker/README.md).
#    CLI_CHANNEL pins/refreshes the Claude engine (a dist-tag like `latest`/`stable`, or an exact
#    version). Bumping it busts only this layer (+ the fast ones after it), so a rebuild can't keep
#    shipping a stale `claude` — the floor check in step 6b fails the build if the baked one is too old.
ARG CLI_CHANNEL=latest
RUN npm install -g "@anthropic-ai/claude-code@${CLI_CHANNEL}" @openai/codex @google/gemini-cli \
    && npm cache clean --force

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
RUN npm --prefix console install && npm --prefix console run build \
    && npm cache clean --force

# 8) Entrypoint: start the control plane (or exec a passed command, e.g. `claude login`).
RUN install -m 0755 docker/entrypoint.sh /usr/local/bin/redstrike-entrypoint

EXPOSE 8788
ENTRYPOINT ["/usr/local/bin/redstrike-entrypoint"]

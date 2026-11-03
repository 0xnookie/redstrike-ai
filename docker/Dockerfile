# syntax=docker/dockerfile:1
#
# Redstrike AI — all-in-one image: the full tool roster + the web console + the
# control plane (launch & steer an authorized engagement from the browser), with
# Claude Code as the live engine and the Codex / Gemini CLIs installed for auth.
#
# Build (from the repo root):   docker compose -f docker/docker-compose.yml build
# This is a LARGE image (the `--all` tool roster is ~168 tools): expect several GB
# and a long first build. See docker/README.md.
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

# 3) Provider CLIs.
#    - Claude Code  -> the ONE live engine today.
#    - Codex / Gemini -> installed so their auth (login or key) works in this image;
#      they are NOT yet live-capable engines (see cli/ENGINES.md + docker/README.md).
RUN npm install -g @anthropic-ai/claude-code @openai/codex @google/gemini-cli \
    && npm cache clean --force

WORKDIR /opt/redstrike

# 4) The tool roster FIRST, keyed only on the installer inputs, so editing the
#    framework later does not bust this big, slow layer. install.sh is non-fatal
#    (it logs a miss and continues); `|| true` guards the build against a hard stop.
COPY scripts/tools.manifest scripts/install.sh scripts/doctor.sh /opt/redstrike/scripts/
RUN bash scripts/install.sh --all -y || true

# 5) The rest of the framework.
COPY . /opt/redstrike

# 6) The redstrike CLI on PATH, with this repo baked in as the engagement home.
RUN REDSTRIKE_PREFIX=/usr/local bash cli/install.sh || true

# 7) Prebuild the console (Next.js static export) so the first open is instant.
RUN npm --prefix console install && npm --prefix console run build \
    && npm cache clean --force

# 8) Entrypoint: start the control plane (or exec a passed command, e.g. `claude login`).
RUN install -m 0755 docker/entrypoint.sh /usr/local/bin/redstrike-entrypoint

EXPOSE 8788
ENTRYPOINT ["/usr/local/bin/redstrike-entrypoint"]

# Redstrike AI — Docker bundle

Run the whole thing from a browser: the **console** + the **control plane** (launch & steer an
authorized engagement) + the **full tool roster**, in one container, on **macOS, Linux, or
Windows**. Download the repo, set your auth, `docker compose up`, open the console, authorize a
scope, and run.

> **Authorized testing only.** This image launches real offensive tooling. Only point it at
> assets you own or have **written authorization** to test. The scope gate, launch gate,
> deny-by-default allowlist and audit trail are all enforced by the `redstrike` launcher inside
> the container — the console does not bypass them.

---

## What you get

| Piece | In the image |
|---|---|
| Web console (dashboard, findings, assets, coverage, CVE intel, …) | ✅ prebuilt |
| Control plane (init engagement, launch autonomous run, live stream, approvals, stop) | ✅ |
| Tool roster — `--core` web-pentest set by default (`--all` ~168 tools is opt-in) | ✅ |
| **Claude** engine | ✅ **live** (authorized runs) |
| **Codex** CLI | ✅ installed, auth works — **not a live engine yet** (lab-only until parity) |
| **Gemini** CLI | ✅ installed, auth works — **no redstrike engine yet** |

Only the **Claude** engine can drive a live engagement today. Codex and Gemini are auth-wired so
they are ready the moment their engine adapters land — see `cli/ENGINES.md`.

---

## Prerequisites

- **macOS / Windows:** [Docker Desktop](https://www.docker.com/products/docker-desktop/) (it runs
  Linux containers via its built-in VM / WSL2 — nothing else to install).
- **Linux:** Docker Engine + the Compose plugin.
- Disk + patience: the default `--core` roster builds in minutes (a few GB). The opt-in `--all`
  roster is a **large image** and a long first build (it compiles many Go/Rust tools from source).
  Subsequent builds are cached.

---

## 1. Get the code & set auth

```sh
git clone https://github.com/0xnookie/redstrike-ai.git
cd redstrike-ai
cp docker/.env.example docker/.env      # then edit docker/.env
```

In `docker/.env`, give Claude **one** of:

- `CLAUDE_CODE_OAUTH_TOKEN` — best for unattended runs. Create it with:
  ```sh
  docker compose -f docker/docker-compose.yml run --rm redstrike claude setup-token
  ```
- `ANTHROPIC_API_KEY` — a plain API key.
- …or persist an interactive login (saved in a volume, reused every start):
  ```sh
  docker compose -f docker/docker-compose.yml run --rm redstrike claude login
  ```

Pin the model with `ANTHROPIC_MODEL=claude-opus-5-5` (already set in the example).

Codex / Gemini auth (optional, staged for later): set `OPENAI_API_KEY` / `GEMINI_API_KEY`, or run
`... run --rm redstrike codex login` / `... run --rm redstrike gemini`.

---

## 2. Build

```sh
docker compose -f docker/docker-compose.yml build                  # default: --core (fast)
```

**Tool scope.** The image bakes in the `--core` web-pentest set by default (glue + recon + web +
password + interceptors). For the full roster or specific categories, set `REDSTRIKE_INSTALL_ARGS`:

```sh
REDSTRIKE_INSTALL_ARGS=--all docker compose -f docker/docker-compose.yml build          # everything (~168 tools; large, slow)
REDSTRIKE_INSTALL_ARGS="recon web ad cloud" docker compose -f docker/docker-compose.yml build   # named categories
```

**Engine version.** The image installs `@anthropic-ai/claude-code@latest`, and the build **fails** if that
version is below the launcher's floor (`MIN_CLAUDE_VERSION`) — so a stale cached layer can't silently ship an
old `claude`. To force a refresh (or pin a channel/version), set `CLI_CHANNEL`:

```sh
docker compose -f docker/docker-compose.yml build --build-arg CLI_CHANNEL=stable
```

---

## 3. Run

```sh
docker compose -f docker/docker-compose.yml up
```

Then:

1. Open **http://localhost:8788** in your browser.
2. Copy the **token** printed in the compose logs.
3. Go to **Control plane** in the sidebar and paste the token (held only in the browser tab).
4. **New engagement** → fill client + in-scope domain(s)/CIDR(s) + who authorized it, and tick the
   written-authorization box (this is the same assertion as the CLI's
   `--i-confirm-authorization`).
5. **Launch** an autonomous run (set the allowlist + turn/budget caps), **watch** the live stream,
   and **approve** any deferred commands. Findings persist on your host under `engagements/`.

Stop with `Ctrl+C`, or `docker compose -f docker/docker-compose.yml down`.

---

## Verify it's wired (smoke test)

```sh
# engine + auth + platform + tool-roster preflight, inside the image:
docker compose -f docker/docker-compose.yml run --rm redstrike redstrike doctor

# the control plane answers (from the host; use the token from the logs):
curl -s -H "Authorization: Bearer <TOKEN>" http://localhost:8788/api/status
```

A healthy `doctor` shows the `claude-code` engine as live-safe and Claude auth present; `/api/status`
returns JSON listing discovered engagements.

---

## Security notes (read these)

- **Loopback only.** The control plane is published to `127.0.0.1:8788` on your host. It is a
  launch-capable endpoint — **do not** republish it on `0.0.0.0` or a public interface. Every
  `/api/*` call needs the bearer token, and the server rejects non-localhost `Host`/cross-origin
  requests.
- **Bind address.** Inside the container the server binds `0.0.0.0` (so Docker's published loopback
  port can reach it); on a bare CLI it still defaults to `127.0.0.1`. The token + Host/Origin checks
  are the access control either way.
- **Defense layers.** Layer 1 = the model's RoE self-refusal; layer 2 = the in-session scope-gate
  hook; layer 3 = the Bash sandbox (bubblewrap/socat). Docker may drop the kernel privileges
  bubblewrap needs — if a run reports a sandbox/bwrap failure, uncomment `cap_add: [SYS_ADMIN]` /
  `security_opt: [seccomp=unconfined]` in `docker-compose.yml`. Without them layer 3 degrades, but
  layers 1–2 still apply.
- **Runs as root** in the container (pentest tools need raw sockets etc.). Keep the image to your
  own machine.
- Secrets live in `docker/.env` (git-ignored) and in the `*-auth` volumes. Don't commit them.

---

## Handy commands

```sh
# a shell in the image:
docker compose -f docker/docker-compose.yml run --rm redstrike bash
# re-install / check the tool roster:
docker compose -f docker/docker-compose.yml run --rm redstrike redstrike doctor
# tear down (keeps auth volumes; add -v to wipe them):
docker compose -f docker/docker-compose.yml down
```

## Limits (honest)

- **Autonomous runs only** over the web (a browser has no TTY for an interactive session).
- **Claude is the only live engine**; Codex/Gemini are auth-ready but not yet live (next stage).
- Engagements run inside the container's Linux userspace — the same model as `INSTALL.md`'s
  WSL2/Kali path, just packaged.

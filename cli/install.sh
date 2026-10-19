#!/usr/bin/env sh
# Install the `redstrike` CLI so it's a global command on Linux (Kali/Ubuntu/Debian),
# macOS, and WSL. After this you just type `redstrike ...` from anywhere.
#
#   git clone https://github.com/0xnookie/redstrike-ai.git
#   cd redstrike-ai && ./cli/install.sh
#
# Needs: python3 (+ its venv module). The `claude` CLI (the engine) is installed separately.
# Override the install prefix with REDSTRIKE_PREFIX (default ~/.local) or the interpreter with PYTHON.
set -eu

CLIDIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)"   # the cli/ directory
REPO="$(dirname -- "$CLIDIR")"                              # the repo root
PREFIX="${REDSTRIKE_PREFIX:-$HOME/.local}"
VENV="$PREFIX/share/redstrike/venv"
BIN="$PREFIX/bin"
PY="${PYTHON:-python3}"

command -v "$PY" >/dev/null 2>&1 || { echo "error: python3 not found on PATH" >&2; exit 1; }
if ! "$PY" -c 'import ensurepip, venv' >/dev/null 2>&1; then
  echo "error: python's venv module is unavailable. Install it and re-run:" >&2
  echo "  Debian / Ubuntu / WSL:  sudo apt install -y python3-venv" >&2
  echo "  (Kali and macOS usually already have it)" >&2
  exit 1
fi

echo ":: installing the redstrike CLI from $CLIDIR"
rm -rf "$VENV"
mkdir -p "$(dirname "$VENV")" "$BIN"
"$PY" -m venv "$VENV"
"$VENV/bin/pip" install -q --upgrade pip >/dev/null 2>&1 || true
"$VENV/bin/pip" install -q "$CLIDIR"

# A tiny wrapper that bakes in the repo location, so `redstrike` works from any directory.
cat > "$BIN/redstrike" <<EOF
#!/bin/sh
export REDSTRIKE_REPO="\${REDSTRIKE_REPO:-$REPO}"
exec "$VENV/bin/redstrike" "\$@"
EOF
chmod +x "$BIN/redstrike"

echo ":: installed  ->  $BIN/redstrike   (repo: $REPO)"

# Put BIN on PATH so `redstrike` is callable. Append (idempotently, with a marker) to the
# shell rc files that apply, then tell the user how to activate it in the current shell.
case ":${PATH:-}:" in
  *":$BIN:"*) : ;;   # already on PATH — nothing to do
  *)
    for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.profile"; do
      # always seed ~/.bashrc (create if absent); touch the others only if they already exist
      [ "$rc" = "$HOME/.bashrc" ] || [ -e "$rc" ] || continue
      grep -qsF "added by redstrike installer" "$rc" 2>/dev/null && continue
      printf '\n# added by redstrike installer\nexport PATH="%s:$PATH"\n' "$BIN" >> "$rc" \
        && echo ":: added $BIN to PATH in $rc"
    done
    echo ":: open a NEW shell (or: . ~/.bashrc) to pick it up."
    echo ":: for THIS shell right now:  export PATH=\"$BIN:\$PATH\""
    ;;
esac
command -v claude >/dev/null 2>&1 || \
  echo ":: NOTE  install Claude Code (the engine) and run 'claude login' — https://claude.ai/install.sh"
echo ":: done.  Run:  redstrike doctor"

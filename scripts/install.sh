#!/usr/bin/env bash
# Redstrike tool installer — category-scoped, idempotent, non-fatal.
# Reads scripts/tools.manifest and installs what's missing via each tool's declared method.
#
#   scripts/install.sh                # --core : glue + recon + web + password + intercept
#   scripts/install.sh --all          # every category (large: adds AD, cloud, mobile, iot, wireless, binary…)
#   scripts/install.sh ad cloud       # only the named categories
#   scripts/install.sh --all --dry-run   # print what WOULD run, change nothing
#
# Target platform: Kali / Debian / Parrot (Linux). On Windows, run inside WSL2 (Kali). See INSTALL.md.
# Already-present tools are skipped. A failure is logged and the run continues; `manual` tools are
# listed at the end for you to install by hand. Re-run scripts/doctor.sh afterwards to confirm.

set -u
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${REDSTRIKE_MANIFEST:-$SELF_DIR/tools.manifest}"
TOOLS_DIR="${REDSTRIKE_TOOLS_DIR:-$HOME/redstrike-tools}"   # where `git` tools are cloned
CORE_CATS="glue recon web password intercept"

WANT=""; want_all=0; DRY=0; ASSUME_YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --all) want_all=1 ;;
    --core) WANT="$WANT $CORE_CATS" ;;
    --dry-run|-n) DRY=1 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --manifest) MANIFEST="$2"; shift ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed '1d'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) WANT="$WANT $1" ;;
  esac; shift
done
# default scope = core
[ "$want_all" = 0 ] && [ -z "${WANT// }" ] && WANT="$CORE_CATS"

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }

say()  { printf '%s\n' "$*"; }
run()  { if [ "$DRY" = 1 ]; then printf '   [dry-run] %s\n' "$*"; return 0; else eval "$@"; fi; }

# --- platform guard --------------------------------------------------------
HAVE_APT=1; command -v apt-get >/dev/null 2>&1 || HAVE_APT=0
if [ "$HAVE_APT" = 0 ]; then
  say "Redstrike tools target Kali/Debian/Parrot Linux (apt)."
  say "This host has no apt-get. On Windows install WSL2 + Kali and run there. See INSTALL.md."
  [ "$DRY" = 1 ] || exit 2
  say "(--dry-run: continuing anyway to preview the plan)"
fi
SUDO=""; [ "$(id -u 2>/dev/null || echo 0)" = 0 ] || SUDO="sudo"

want_cat() { [ "$want_all" = 1 ] && return 0; case " $WANT " in *" $1 "*) return 0;; *) return 1;; esac; }
present() { local f="$1" a; local IFS=','; for a in $f; do case "$a" in @*) [ -e "${a#@}" ] && return 0;; *) command -v "$a" >/dev/null 2>&1 && return 0;; esac; done; return 1; }

say ""
say "Redstrike installer — scope: $([ "$want_all" = 1 ] && echo ALL || echo "$WANT")$([ "$DRY" = 1 ] && echo '  (dry-run)')"

# --- figure out what's in scope + missing ---------------------------------
need_apt=0 need_pipx=0 need_go=0 need_cargo=0 need_gem=0 need_npm=0 need_pdtm=0
declare -a ROWS=()
while IFS='|' read -r cmd cat method spec note; do
  case "$cmd" in ''|'#'*) continue ;; esac
  want_cat "$cat" || continue
  present "$cmd" && continue                       # idempotent: already installed
  ROWS+=("$cmd|$cat|$method|$spec|$note")
  case "$method" in
    apt) need_apt=1 ;; pipx) need_pipx=1 ;; go) need_go=1 ;;
    cargo) need_cargo=1 ;; gem) need_gem=1 ;; npm) need_npm=1 ;; pdtm) need_pdtm=1; need_go=1 ;;
  esac
done < "$MANIFEST"

if [ "${#ROWS[@]}" = 0 ]; then say ""; say "Nothing to do — everything in scope is already present. ✓"; exit 0; fi
say "Missing in scope: ${#ROWS[@]} tool(s)."

# --- ensure base toolchains the selected methods need ----------------------
ensure_apt_pkg() { present "$1" || { say ":: base: $2"; run "$SUDO apt-get install -y $2"; }; }
if [ "$HAVE_APT" = 1 ]; then
  say ":: apt-get update"; run "$SUDO apt-get update -y"
  [ "$need_apt"  = 1 ] && :  # packages installed per-row below
  [ "$need_pipx" = 1 ] && { ensure_apt_pkg pipx pipx; run "pipx ensurepath >/dev/null 2>&1 || true"; }
  [ "$need_go"   = 1 ] && ensure_apt_pkg go golang-go
  [ "$need_cargo" = 1 ] && ensure_apt_pkg cargo cargo
  [ "$need_gem"  = 1 ] && ensure_apt_pkg gem ruby
  [ "$need_npm"  = 1 ] && ensure_apt_pkg npm npm
fi

# PATHs the per-user installers drop binaries into (so later `present` checks + your shell find them)
export PATH="$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin:$PATH"

# --- ProjectDiscovery tools: install the manager once, then the whole set --
if [ "$need_pdtm" = 1 ]; then
  say ""; say ":: ProjectDiscovery tools (pdtm)"
  command -v pdtm >/dev/null 2>&1 || run "go install github.com/projectdiscovery/pdtm/cmd/pdtm@latest"
  run "pdtm -ia"     # install-all; harmless if already installed
fi

# --- per-tool install ------------------------------------------------------
ok=""; fail=""; manual=""
for row in "${ROWS[@]}"; do
  IFS='|' read -r cmd cat method spec note <<< "$row"
  label="${cmd%%,*}"
  case "$method" in
    pdtm) continue ;;                 # handled in the batch above
    manual)
      manual="$manual\n  - $label — ${note:-see} $spec" ; continue ;;
  esac
  say ""; say ":: [$cat] $label  ($method)"
  case "$method" in
    apt)    if [ "$HAVE_APT" = 1 ] || [ "$DRY" = 1 ]; then run "$SUDO apt-get install -y $spec"; else say "   (no apt; skipped)"; fail="$fail $label"; continue; fi ;;
    pipx)   run "pipx install $spec" ;;
    go)     run "go install $spec" ;;
    cargo)  run "cargo install $spec" ;;
    gem)    run "$SUDO gem install $spec" ;;
    npm)    run "$SUDO npm install -g $spec" ;;
    script) run "curl -sSfL $spec | $SUDO sh -s -- -b /usr/local/bin" ;;
    git)
      dest="$TOOLS_DIR/$label"
      run "mkdir -p '$TOOLS_DIR'"
      if [ -d "$dest/.git" ]; then run "git -C '$dest' pull --ff-only"; else run "git clone --depth 1 $spec '$dest'"; fi
      say "   cloned to $dest — follow-up: ${note:-see repo README (pip install -r / make)}" ;;
    *) say "   unknown method '$method' — skipped"; fail="$fail $label"; continue ;;
  esac
  # verify (dry-run can't verify)
  if [ "$DRY" = 1 ]; then ok="$ok $label"
  elif present "$cmd"; then ok="$ok $label"
  elif [ "$method" = git ]; then ok="$ok $label(cloned)"
  else fail="$fail $label"; fi
done

# --- summary ---------------------------------------------------------------
say ""; say "────────── summary ──────────"
say "installed/ok:$([ -n "$ok" ] && echo "$ok" || echo ' none')"
[ -n "$fail" ]   && say "FAILED (install by hand / check method):$fail"
[ -n "$manual" ] && { say ""; say "manual tools in scope (not auto-installable):"; printf "$manual\n"; }
say ""
say "Next: run  scripts/doctor.sh  to confirm. Ensure ~/.local/bin, ~/go/bin, ~/.cargo/bin are on your PATH."
[ -n "$fail" ] && exit 1 || exit 0

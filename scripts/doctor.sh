#!/usr/bin/env bash
# Redstrike doctor — report which tools from tools.manifest are present / missing.
# Read-only: it never installs anything. Use scripts/install.sh for that.
#
#   scripts/doctor.sh                 # check every category (+ an environment section)
#   scripts/doctor.sh --core          # glue + recon + web + password + intercept
#   scripts/doctor.sh ad cloud        # only the named categories
#   scripts/doctor.sh --missing       # list only what's absent
#   scripts/doctor.sh --env           # ONLY the runtime-environment preflight
#
# Exit 0 = nothing missing in scope; 1 = one or more auto-installable tools missing.
# `manual` tools (GUI / Windows / vendor installers) are reported but never fail the run.
# The environment preflight (TLS trust / headless browser / OOB) is informational and never fails the run.

set -u
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${REDSTRIKE_MANIFEST:-$SELF_DIR/tools.manifest}"
CORE_CATS="glue recon web password intercept"

WANT=""          # space-separated categories to include; empty = all
MISSING_ONLY=0
want_all=1
ENV_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --core) WANT="$WANT $CORE_CATS"; want_all=0 ;;
    --all)  want_all=1 ;;
    --missing) MISSING_ONLY=1 ;;
    --env) ENV_ONLY=1 ;;
    --manifest) MANIFEST="$2"; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed '1d'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *)  WANT="$WANT $1"; want_all=0 ;;
  esac
  shift
done

if [ "$ENV_ONLY" = 0 ]; then
  [ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }
fi

# colour only on a TTY and when NO_COLOR is unset
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; B=$'\033[1m'; X=$'\033[0m'
else G=""; R=""; Y=""; D=""; B=""; X=""; fi

want_cat() { [ "$want_all" = 1 ] && return 0; case " $WANT " in *" $1 "*) return 0;; *) return 1;; esac; }

# Runtime-environment preflight: the things that broke real engagements and that a
# tool-presence check misses — Node/TLS trust, a working headless browser, the Playwright
# driver, and an OOB collaborator. Informational only; never changes the exit code.
env_checks() {
  printf '\n%s== environment ==%s %s(informational — never fails the run)%s\n' "$B" "$X" "$D" "$X"

  # 1) Node/TLS trust. Subagents, Playwright and MCP servers use Node; behind a TLS-inspecting
  #    proxy with an untrusted CA they die with SELF_SIGNED_CERT_IN_CHAIN while `curl -k` still works.
  if command -v node >/dev/null 2>&1; then
    if [ -n "${NODE_EXTRA_CA_CERTS:-}" ] && [ -e "${NODE_EXTRA_CA_CERTS:-/nonexistent}" ]; then
      printf '  %s✓ %-22s%s %sNODE_EXTRA_CA_CERTS set%s\n' "$G" "node TLS CA" "$X" "$D" "$X"
    else
      printf '  %s⚠ %-22s%s %sNODE_EXTRA_CA_CERTS unset: behind a TLS-inspecting proxy, Node clients (subagents/Playwright/MCP) may fail SELF_SIGNED_CERT_IN_CHAIN; point it at the proxy CA bundle%s\n' "$Y" "node TLS CA" "$X" "$D" "$X"
    fi
  else
    printf '  %s⚙ %-22s%s %snode absent — TLS-trust check skipped%s\n' "$D" "node TLS CA" "$X" "$D" "$X"
  fi

  # 2) Headless browser must actually execute JS (the XSS execution-proof path).
  local chrome="" c ud out
  for c in chromium chromium-browser google-chrome chrome; do
    command -v "$c" >/dev/null 2>&1 && { chrome="$c"; break; }
  done
  if [ -n "$chrome" ]; then
    ud="$(mktemp -d)"
    out="$("$chrome" --headless=new --no-sandbox --disable-gpu --user-data-dir="$ud" \
           --dump-dom "data:text/html,<title>x</title><script>document.title='RS_OK'</script>" 2>/dev/null)"
    rm -rf "$ud"
    case "$out" in
      *RS_OK*) printf '  %s✓ %-22s%s %s%s executes JS headless%s\n' "$G" "headless browser" "$X" "$D" "$chrome" "$X" ;;
      *)       printf '  %s⚠ %-22s%s %s%s present but headless dump-dom/JS failed — XSS execution proofs need a working headless browser%s\n' "$Y" "headless browser" "$X" "$D" "$chrome" "$X" ;;
    esac
  else
    printf '  %s⚠ %-22s%s %sno chromium/chrome — XSS execution proofs cannot be captured%s\n' "$Y" "headless browser" "$X" "$D" "$X"
  fi

  # 3) Playwright driver (optional). Import succeeding is not enough — the node driver can be broken.
  if python3 -c 'import playwright' >/dev/null 2>&1; then
    if python3 -m playwright --version >/dev/null 2>&1; then
      printf '  %s✓ %-22s%s %sdriver responds%s\n' "$G" "playwright" "$X" "$D" "$X"
    else
      printf '  %s⚠ %-22s%s %spython package present but node driver fails (run: playwright install)%s\n' "$Y" "playwright" "$X" "$D" "$X"
    fi
  else
    printf '  %s⚙ %-22s%s %snot installed (optional)%s\n' "$D" "playwright" "$X" "$D" "$X"
  fi

  # 4) OOB collaborator is config, not a tool; blind SSRF/XXE/XSS need one.
  if [ -n "${REDSTRIKE_OOB:-}" ]; then
    printf '  %s✓ %-22s%s %sREDSTRIKE_OOB set%s\n' "$G" "OOB collaborator" "$X" "$D" "$X"
  else
    printf '  %s⚙ %-22s%s %snone set (REDSTRIKE_OOB / scope.yaml oob) — blind/OOB checks limited%s\n' "$D" "OOB collaborator" "$X" "$D" "$X"
  fi

  # 5) Python libs for the gate/console. Both optional — the gate ships a built-in validator and
  #    the console a bundled scope reader — but jsonschema gives full-spec finding validation and
  #    PyYAML a correct scope.yaml parse (the mini-reader mangles some inline lists like `cidrs: []`).
  for lib in jsonschema yaml; do
    name="$lib"; [ "$lib" = yaml ] && name="PyYAML"
    if python3 -c "import $lib" >/dev/null 2>&1; then
      printf '  %s✓ %-22s%s %spresent%s\n' "$G" "python: $name" "$X" "$D" "$X"
    else
      printf '  %s⚙ %-22s%s %snot installed — built-in fallback in use (pip install '"'"'redstrike-cli[validate]'"'"')%s\n' "$D" "python: $name" "$X" "$D" "$X"
    fi
  done
}

if [ "$ENV_ONLY" = 1 ]; then
  env_checks
  exit 0
fi

present() {  # $1 = comma-separated command field; @prefix = path test
  local field="$1" alt; local IFS=','
  for alt in $field; do
    case "$alt" in
      @*) [ -e "${alt#@}" ] && return 0 ;;
      *)  command -v "$alt" >/dev/null 2>&1 && return 0 ;;
    esac
  done
  return 1
}

n_present=0; n_missing=0; n_manual=0; last_cat=""
missing_list=""

while IFS='|' read -r cmd cat method spec note; do
  case "$cmd" in ''|'#'*) continue ;; esac
  want_cat "$cat" || continue

  if [ "$cat" != "$last_cat" ]; then
    [ "$MISSING_ONLY" = 0 ] && printf '\n%s== %s ==%s\n' "$B" "$cat" "$X"
    last_cat="$cat"
  fi

  label="${cmd%%,*}"   # first alternative is the display name
  case "$label" in @*) label="$spec" ;; esac   # path-checked entries show their package name
  if [ "$method" = "manual" ]; then
    n_manual=$((n_manual+1))
    [ "$MISSING_ONLY" = 0 ] && printf '  %s⚙ %-22s%s %smanual: %s%s\n' "$Y" "$label" "$X" "$D" "${note:-$spec}" "$X"
    continue
  fi

  if present "$cmd"; then
    n_present=$((n_present+1))
    [ "$MISSING_ONLY" = 0 ] && printf '  %s✓ %-22s%s\n' "$G" "$label" "$X"
  else
    n_missing=$((n_missing+1))
    printf '  %s✗ %-22s%s %s(%s: %s)%s\n' "$R" "$label" "$X" "$D" "$method" "$spec" "$X"
    missing_list="$missing_list $label"
  fi
done < "$MANIFEST"

printf '\n%s—— summary ——%s\n' "$B" "$X"
printf '  %spresent %s%d%s   %smissing %s%d%s   %smanual %s%d%s\n' \
  "$D" "$G" "$n_present" "$X" "$D" "$R" "$n_missing" "$X" "$D" "$Y" "$n_manual" "$X"

# environment preflight on a full run (informational; does not affect the exit code)
if [ "$want_all" = 1 ] && [ "$MISSING_ONLY" = 0 ]; then
  env_checks
fi

if [ "$n_missing" -gt 0 ]; then
  printf '  fix: %sscripts/install.sh%s %s(add --all or a category; manual items are in INSTALL.md)%s\n' "$B" "$X" "$D" "$X"
  exit 1
fi
printf '  %sall auto-installable tools in scope are present.%s\n' "$G" "$X"
exit 0

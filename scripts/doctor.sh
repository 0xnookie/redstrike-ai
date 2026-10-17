#!/usr/bin/env bash
# Redstrike doctor — report which tools from tools.manifest are present / missing.
# Read-only: it never installs anything. Use scripts/install.sh for that.
#
#   scripts/doctor.sh                 # check every category
#   scripts/doctor.sh --core          # glue + recon + web + password + intercept
#   scripts/doctor.sh ad cloud        # only the named categories
#   scripts/doctor.sh --missing       # list only what's absent
#
# Exit 0 = nothing missing in scope; 1 = one or more auto-installable tools missing.
# `manual` tools (GUI / Windows / vendor installers) are reported but never fail the run.

set -u
SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFEST="${REDSTRIKE_MANIFEST:-$SELF_DIR/tools.manifest}"
CORE_CATS="glue recon web password intercept"

WANT=""          # space-separated categories to include; empty = all
MISSING_ONLY=0
want_all=1

while [ $# -gt 0 ]; do
  case "$1" in
    --core) WANT="$WANT $CORE_CATS"; want_all=0 ;;
    --all)  want_all=1 ;;
    --missing) MISSING_ONLY=1 ;;
    --manifest) MANIFEST="$2"; shift ;;
    -h|--help)
      grep '^#' "$0" | sed 's/^# \{0,1\}//' | sed '1d'; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *)  WANT="$WANT $1"; want_all=0 ;;
  esac
  shift
done

[ -f "$MANIFEST" ] || { echo "manifest not found: $MANIFEST" >&2; exit 2; }

# colour only on a TTY and when NO_COLOR is unset
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; B=$'\033[1m'; X=$'\033[0m'
else G=""; R=""; Y=""; D=""; B=""; X=""; fi

want_cat() { [ "$want_all" = 1 ] && return 0; case " $WANT " in *" $1 "*) return 0;; *) return 1;; esac; }

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

if [ "$n_missing" -gt 0 ]; then
  printf '  fix: %sscripts/install.sh%s %s(add --all or a category; manual items are in INSTALL.md)%s\n' "$B" "$X" "$D" "$X"
  exit 1
fi
printf '  %sall auto-installable tools in scope are present.%s\n' "$G" "$X"
exit 0

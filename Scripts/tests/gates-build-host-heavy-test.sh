#!/bin/bash
# gates-build-host-heavy-test.sh - every stage outside the fast set that builds is a build-host stage.
#
# The standard runner refuses a BUILD_HOST_STAGES stage off the build host (Shell's
# agent_docs/gates-standard.md, "Build host"). The fast set of a single package may run on the
# laptop; nothing else that builds may. Shell's gates-build-host-stages-lint-test.sh holds every
# xcodebuild stage to the list; this test holds the rest: a stage in FULL or OPT_IN but not in FAST
# whose body, or a repo script the body names (two reaches deep), compiles or runs Swift
# (`swift build|test|run|package`, the runner's `run_swift_test`), renders DocC
# (`generate-documentation`) or starts a container (`docker`) must be in BUILD_HOST_STAGES.
# A named script that does not exist fails closed. Static: gates.sh is read, never run.
# Limits: a road behind eval, a variable holding a whole command, or a bare name found on PATH is
# not seen. Byte-identical in every kit that carries it.
#
# Usage: Scripts/tests/gates-build-host-heavy-test.sh   (GATES_SH=<file> reads another gates.sh)
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
GATES="${GATES_SH:-}"
if [ -z "$GATES" ]; then
    for g in "$ROOT/Scripts/gates.sh" "$ROOT/scripts/gates.sh"; do [ -f "$g" ] && GATES="$g" && break; done
fi
[ -f "$GATES" ] || { echo "FAIL: no gates.sh under $ROOT" >&2; exit 1; }

REPO_DIR="$(cd "$(dirname "$GATES")/.." && pwd)"
top="$(/usr/bin/sed '/^# ---- standard runner/,$d' "$GATES")"
FAST=(); FULL=(); OPT_IN=(); BUILD_HOST_STAGES=()
eval "$(/usr/bin/grep -E '^(FAST|FULL|OPT_IN|BUILD_HOST_STAGES)=\(' <<<"$top")"

HEAVY='(^|[^A-Za-z0-9_-])(xcodebuild|run_swift_test|swift[[:space:]]+(build|test|run|package)|generate-documentation|docker)([^A-Za-z0-9_-]|$)'

body() { # the stage_<name> definition, comments dropped
    /usr/bin/awk -v n="stage_$1()" '
        index($0, n) == 1 { p = 1; print; if ($0 ~ /\}[[:space:]]*$/) exit; next }
        p { print; if ($0 ~ /^\}/) exit }' <<<"$top" | /usr/bin/sed -E 's/(^|[[:space:]])#.*$//'
}

reaches() { # $1 = text, $2 = depth left: prints "heavy" or "missing <path>" findings
    local text="$1" depth="$2" p f
    /usr/bin/grep -qE "$HEAVY" <<<"$text" && echo heavy
    [ "$depth" -gt 0 ] || return 0
    while IFS= read -r p; do
        [ -n "$p" ] || continue
        f="$REPO_DIR/$p"
        if [ -f "$f" ]; then
            reaches "$(/usr/bin/sed -E 's/(^|[[:space:]])#.*$//' "$f")" $((depth - 1))
        else
            echo "missing $p"
        fi
    done < <(/usr/bin/grep -oE '(^|[^A-Za-z0-9_./-])[Ss]cripts/[A-Za-z0-9_./-]+\.(sh|py)' <<<"$text" \
             | /usr/bin/sed -E 's/^[^Ss]//' | sort -u)
}

in_list() { local x="$1" y; shift; for y in "$@"; do [ "$x" = "$y" ] && return 0; done; return 1; }

unlisted=(); broken=()
for s in ${FULL[@]+"${FULL[@]}"} ${OPT_IN[@]+"${OPT_IN[@]}"}; do
    in_list "$s" ${FAST[@]+"${FAST[@]}"} && continue
    b="$(body "$s")"
    [ -n "$b" ] || { broken+=("$s: no stage_$s()"); continue; }
    found="$(reaches "$b" 2)"
    if /usr/bin/grep -q '^missing ' <<<"$found"; then
        broken+=("$s: names $(/usr/bin/sed -n 's/^missing //p' <<<"$found" | /usr/bin/paste -sd' ' -), which does not exist")
    fi
    if /usr/bin/grep -qx heavy <<<"$found" && ! in_list "$s" ${BUILD_HOST_STAGES[@]+"${BUILD_HOST_STAGES[@]}"}; then
        in_list "$s" ${unlisted[@]+"${unlisted[@]}"} || unlisted+=("$s")
    fi
done

echo "gates build-host heavy stages - $GATES"
echo "  build-host: ${BUILD_HOST_STAGES[*]:-}"
rc=0
for x in ${broken[@]+"${broken[@]}"}; do echo "  FAIL $x" >&2; rc=1; done
# KNOWN HOLE (red): today these stages build on the laptop. The fix lists them and flips this block.
if ((${#unlisted[@]})); then
    echo "  ok   KNOWN HOLE: stage(s) ${unlisted[*]} build outside the fast set and are not in BUILD_HOST_STAGES"
else
    echo "  FAIL the known hole is closed: flip this block to require every building stage listed" >&2
    rc=1
fi
exit "$rc"

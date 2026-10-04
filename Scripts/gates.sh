#!/usr/bin/env bash
# Local merge gates for swift-nio-ssh (fork). The upstream workflows in .github/ are
# kept untouched to avoid sync conflicts; this script is the fork's merge gate.
# Contract: Shell/agent_docs/gates-standard.md.
#
#   Scripts/gates.sh                 # fast gates: build unit
#   Scripts/gates.sh --full          # + release (upstream release-builds check)
#   Scripts/gates.sh --only <stage>  # one stage, including opt-in ones
#   Scripts/gates.sh --list          # print the stage sets
set -uo pipefail
cd "$(dirname "$0")/.."

# ---- repo-specific: name, stage sets, stage bodies -------------------------
REPO=swift-nio-ssh
FAST=(build unit)
FULL=(build unit release)
# Not mapped: Linux unit tests, static SDK, soundness (swiftlang container scripts),
# benchmarks (Benchmarks/ package, needs jemalloc), semver PR label check.
OPT_IN=()   # runnable only via --only (say why next to each one)

stage_build() { swift build --build-tests; }
stage_unit() { swift test; }
stage_release() { swift build -c release; }

# ---- standard runner: keep byte-identical across repos ---------------------

# Judge a swift-testing run by its summary line, never the exit code.
# Usage: judge_swift_testing <log>; prints the last summary line.
judge_swift_testing() {
    grep -E "Test run with [0-9]+ tests?.*(passed|failed)" "$1" | tail -1
    grep -qE "Test run with [0-9]+ tests?.*passed" "$1" \
        && ! grep -qE "Test run with .*failed" "$1"
}

usage() { echo "usage: $0 [--full | --only <stage> | --list]" >&2; exit 64; }

STAGES=("${FAST[@]}")
case "${1:-}" in
    --full) STAGES=("${FULL[@]}") ;;
    --only) [[ -n "${2:-}" ]] || usage; STAGES=("$2") ;;
    --list)
        echo "fast:   ${FAST[*]}"
        echo "full:   ${FULL[*]}"
        echo "opt-in: ${OPT_IN[*]:-}"
        exit 0 ;;
    "") ;;
    *) usage ;;
esac

LOG_DIR="${TMPDIR:-/tmp}"; LOG_DIR="${LOG_DIR%/}/$REPO-gates"
# A shared /tmp lets another user pre-create this path: own it or refuse.
mkdir -p -m 700 "$LOG_DIR"
if [[ -L "$LOG_DIR" || ! -O "$LOG_DIR" ]]; then
    echo "refusing log dir $LOG_DIR: not a directory owned by $(id -un)" >&2
    exit 1
fi
FAILED=()

for stage in "${STAGES[@]}"; do
    if ! declare -F "stage_$stage" >/dev/null; then
        echo "unknown stage: $stage (see --list)" >&2
        exit 64
    fi
    log="$LOG_DIR/$stage.log"
    printf '%-12s ' "$stage"
    if "stage_$stage" >"$log" 2>&1; then
        echo "PASS"
    else
        echo "FAIL  (log: $log)"
        # The log may live on another machine (remote runs): show the first errors.
        grep -E "✘|error: |fatal" "$log" | grep -v "◇" | head -5 | cut -c1-200 | sed 's/^/    /'
        FAILED+=("$stage")
    fi
done

if ((${#FAILED[@]})); then
    echo "Failed gates: ${FAILED[*]}"
    exit 1
fi
echo "All gates passed."

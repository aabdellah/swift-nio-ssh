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
FAST=(scripts build unit)
FULL=(scripts build unit release)
# Not mapped: Linux unit tests, static SDK, soundness (swiftlang container scripts),
# benchmarks (Benchmarks/ package, needs jemalloc), semver PR label check.
OPT_IN=()   # runnable only via --only (say why next to each one)
BUILD_HOST_STAGES=()   # no stage runs xcodebuild here
MEASUREMENTS=()   # scripts that measure a stage run, exempt from the one-check-one-stage lint: none here

# One check, one stage: no hook or second stage re-runs a check (../Shell/agent_docs/gates-standard.md).
stage_scripts() { bash Scripts/tests/gates-dedupe-lint-test.sh && bash Scripts/tests/gates-per-run-logs-test.sh && bash Scripts/tests/gates-build-host-heavy-test.sh; }

stage_build() { swift build --build-tests; }
stage_unit() { run_swift_test; }
stage_release() { swift build -c release; }

# ---- standard runner: keep byte-identical across repos ---------------------

# Run `swift test "$@"`, echo its output into the stage log and judge it with judge_tests.
# Every `swift test` in a stage goes through this; env prefixes work (`VAR=1 run_swift_test`).
run_swift_test() {
    local out="$LOG_DIR/${stage:-adhoc}.test.out" rc
    swift test "$@" >"$out" 2>&1
    rc=$?
    cat "$out"
    judge_tests "$out" "$rc"
}

# Judge a test log, never the exit code alone: some harnesses exit 0 on failure, a filter
# that matches nothing exits 0 too, and a test process that stops mid-suite can exit 0 with no
# summary. Passes only when <rc> is 0, every run that started printed its summary, at least one
# test ran, and neither the Swift Testing nor the XCTest summary reports a failure.
# Usage: judge_tests <log> [<rc>]; prints the summary lines and any verdict reason.
judge_tests() {
    local log="$1" rc="${2:-0}" started finished
    grep -E "Test run with [0-9]+ tests?|Executed [0-9]+ tests?, with" "$log" | tail -3
    if ((rc != 0)); then echo "verdict: swift test exited $rc"; return 1; fi
    if grep -qE "Test run with .*failed|Executed [0-9]+ tests?, with [1-9][0-9]* failures?" "$log"; then
        echo "verdict: the test summary reports failures"; return 1
    fi
    # Every run that started finished: one `swift test` prints several runs, and a test process that
    # exits 0 mid-suite (anything that stops the main run loop) prints no summary of its own. Another
    # run's summary must not stand in for it. A Swift Testing run ends in its `Test run with` line; an
    # XCTest run's top suite ('All tests' or 'Selected tests') ends in passed|failed and `Executed`.
    # Blind spots: a run that exits before it prints its start line is never counted, and the XCTest
    # workers of `swift test --parallel` print no top-suite lines, so this count is not a census of runs.
    started=$(grep -cE "Test run started\.|Test Suite '(All|Selected) tests' started" "$log")
    finished=$(awk '/Test run with [0-9]+ tests? .*(passed|failed)/ { n++ }
        top { if (/Executed [0-9]+ tests?, with/) n++; top = 0 }
        /Test Suite .(All|Selected) tests. (passed|failed)/ { top = 1 }
        END { print n + 0 }' "$log")
    if ((started > finished)); then echo "verdict: $started test runs started, $finished finished"; return 1; fi
    if ! grep -qE "Test run with [1-9][0-9]* tests?.*passed|Executed [1-9][0-9]* tests?, with 0 failures" "$log"; then
        echo "verdict: no tests ran"; return 1
    fi
}

usage() { echo "usage: $0 [--full | --only <stage> | --list]" >&2; exit 64; }

# A stage in BUILD_HOST_STAGES runs xcodebuild on this machine, so it runs only on the build host: LocalHostName
# ahmeds-mac-studio AND the marker file ~/.shell-build-host (Shell's remote_is_build_host; Shell's
# Scripts/tests/gates-build-host-runner-test.sh holds the two equal). Off it, a run that selects one is refused
# before any stage starts, with exit 75 (EX_TEMPFAIL). Every repo declares the set, empty when no stage builds
# with xcodebuild. An undeclared set, or an entry that names no stage_<name>, is a config error: exit 78 (EX_CONFIG),
# checked before anything else, --list included. REPO names the kit in the refusal.
declare -p BUILD_HOST_STAGES >/dev/null 2>&1 || { echo "gates: BUILD_HOST_STAGES is not declared" >&2; exit 78; }
for x in ${BUILD_HOST_STAGES[@]+"${BUILD_HOST_STAGES[@]}"}; do
    declare -F "stage_$x" >/dev/null || { echo "gates: BUILD_HOST_STAGES names '$x', which has no stage_$x" >&2; exit 78; }
done

STAGES=("${FAST[@]}")
case "${1:-}" in
    --full) STAGES=("${FULL[@]}") ;;
    --only) [[ -n "${2:-}" ]] || usage; STAGES=("$2") ;;
    --list)
        echo "fast:       ${FAST[*]}"
        echo "full:       ${FULL[*]}"
        echo "opt-in:     ${OPT_IN[*]:-}"
        echo "build-host: ${BUILD_HOST_STAGES[*]:-}"
        exit 0 ;;
    "") ;;
    *) usage ;;
esac

heavy=()
for stage in "${STAGES[@]}"; do
    for x in ${BUILD_HOST_STAGES[@]+"${BUILD_HOST_STAGES[@]}"}; do [[ "$stage" == "$x" ]] && heavy+=("$stage"); done
done
if ((${#heavy[@]})); then
    here="$(/usr/sbin/scutil --get LocalHostName 2>/dev/null || true)"
    if [[ "$(printf '%s' "$here" | /usr/bin/tr 'A-Z' 'a-z')" != ahmeds-mac-studio \
          || ! -f "${HOME:-/nonexistent}/.shell-build-host" ]]; then
        echo "refusing: $REPO stage(s) ${heavy[*]} run xcodebuild, and ${here:-this machine} is not the build host." >&2
        echo "Run them there, from Shell: Scripts/remote-kit-test.sh $REPO --gates [--full | --only <stage>]" >&2
        echo "From a worktree, prefix SHELL_REMOTE_SRC_$(printf '%s' "$REPO" | /usr/bin/tr -c '[:alnum:]_' '_')=$PWD" >&2
        exit 75
    fi
fi

LOG_ROOT="${TMPDIR:-/tmp}"; LOG_ROOT="${LOG_ROOT%/}/$REPO-gates"
# A shared /tmp lets another user pre-create this path: own it or refuse.
mkdir -p -m 700 "$LOG_ROOT"
if [[ -L "$LOG_ROOT" || ! -O "$LOG_ROOT" ]]; then
    echo "refusing log dir $LOG_ROOT: not a directory owned by $(id -un)" >&2
    exit 1
fi
# One directory per run: concurrent runs (lanes, worktrees) never write each other's logs.
# Runs older than a week are removed.
find "$LOG_ROOT" -mindepth 1 -maxdepth 1 -name 'run.*' -mtime +7 -exec rm -rf {} + 2>/dev/null
LOG_DIR="$(mktemp -d "$LOG_ROOT/run.XXXXXX")" || { echo "cannot create a run log dir under $LOG_ROOT" >&2; exit 1; }
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
        grep -E "✘|error: |fatal|^verdict: " "$log" | grep -v "◇" | head -5 | cut -c1-200 | sed 's/^/    /'
        FAILED+=("$stage")
    fi
done

echo "logs: $LOG_DIR"
if ((${#FAILED[@]})); then
    echo "Failed gates: ${FAILED[*]}"
    exit 1
fi
echo "All gates passed."

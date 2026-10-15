#!/bin/bash
# gates-per-run-logs-test.sh — two gate runs at once keep separate logs.
#
# The standard runner (the section of Scripts/gates.sh after its "standard runner" marker, byte for
# byte the same in every repo) wrote every stage to ${TMPDIR}/<repo>-gates/<stage>.log.
# Two lanes running their gates at once wrote the same file, so a lane reading
# "its" log after a red could quote the other lane's run. Each run now writes a
# directory of its own under <repo>-gates/ and names it on its `logs:` line.
#
# Real runner, planted stage: a demo gates.sh made of a stage section and this
# repo's runner runs twice concurrently with one TMPDIR. Each stage prints
# its run's token, waits for the other run to have started, and prints it again.
#
# The same demo judges a planted `swift test` (a fake swift on PATH) through the runner's
# run_swift_test: one `swift test` prints several runs, and each run that started must
# print its own summary, or the stage fails (review r4 R4-1).
#
# Usage: Scripts/tests/gates-per-run-logs-test.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TEMPLATE="${GATES_TEMPLATE:-$(cd "$(dirname "$0")/.." && pwd)/gates.sh}"
PASS=0; FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $1"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $1"; }

TMP="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/gates-per-run-logs.XXXXXX")" || exit 2
trap '/bin/rm -rf "$TMP"' EXIT
TMP="$(cd "$TMP" && pwd -P)"
mkdir -p "$TMP/repo/Scripts" "$TMP/tmpdir"
{
    cat <<'EOF'
#!/usr/bin/env bash
set -uo pipefail
cd "$(dirname "$0")/.."
REPO=demo
FAST=(a)
FULL=(a)
OPT_IN=()
BUILD_HOST_STAGES=()
# Prints the run's token, waits (bounded) until the other run has started, prints it again.
stage_a() {
    echo "run $TOKEN"
    : > "$BARRIER/$TOKEN"
    local i=0
    while [ "$(/bin/ls "$BARRIER" | /usr/bin/wc -l | /usr/bin/tr -d ' ')" -lt 2 ] && [ $i -lt 100 ]; do
        /bin/sleep 0.05; i=$((i + 1))
    done
    echo "run $TOKEN"
    [ "${STAGE_FAIL:-0}" = 0 ]
}
# One planted `swift test` (the fake swift prints $FAKE_SWIFT_OUT), judged by the runner.
stage_b() { run_swift_test; }

EOF
    /usr/bin/sed -n '/^# ---- standard runner/,$p' "$TEMPLATE"
} > "$TMP/repo/Scripts/gates.sh"
chmod +x "$TMP/repo/Scripts/gates.sh"
mkdir -p "$TMP/barrier"

echo "two concurrent runs, one TMPDIR"
TMPDIR="$TMP/tmpdir" BARRIER="$TMP/barrier" TOKEN=one "$TMP/repo/Scripts/gates.sh" > "$TMP/one.out" 2>&1 &
p1=$!
TMPDIR="$TMP/tmpdir" BARRIER="$TMP/barrier" TOKEN=two STAGE_FAIL=1 "$TMP/repo/Scripts/gates.sh" > "$TMP/two.out" 2>&1 &
p2=$!
wait $p1; rc1=$?; wait $p2; rc2=$?
[ "$rc1" = 0 ] && ok "the passing run exits 0" || bad "the passing run exited $rc1: $(cat "$TMP/one.out")"
[ "$rc2" = 1 ] && ok "the failing run exits 1" || bad "the failing run exited $rc2: $(cat "$TMP/two.out")"

# Where each run's stage log is: the run's `logs:` line, else the shared path
# the runner used before (so the old runner fails on content, not on parsing).
logdir() { local d; d="$(/usr/bin/sed -n 's/^logs: //p' "$1")"; printf '%s' "${d:-$TMP/tmpdir/demo-gates}"; }
d1="$(logdir "$TMP/one.out")"; d2="$(logdir "$TMP/two.out")"
[ "$d1" != "$d2" ] && ok "the two runs name different log dirs" || bad "both runs log to $d1"
case "$d1/" in "$TMP/tmpdir/demo-gates/"?*) ok "a run's log dir is under <TMPDIR>/<repo>-gates/" ;;
    *) bad "the log dir $d1 is not a run dir under $TMP/tmpdir/demo-gates/" ;; esac
[ "$(cat "$d1/a.log" 2>/dev/null)" = "$(printf 'run one\nrun one')" ] \
    && ok "the passing run's log holds only its own stage output" || bad "the passing run's log: $(cat "$d1/a.log" 2>&1)"
[ "$(cat "$d2/a.log" 2>/dev/null)" = "$(printf 'run two\nrun two')" ] \
    && ok "the failing run's log holds only its own stage output" || bad "the failing run's log: $(cat "$d2/a.log" 2>&1)"
grep -q "a            FAIL  (log: $d2/a.log)" "$TMP/two.out" \
    && ok "the FAIL line names the failing run's own log" || bad "the FAIL line: $(grep FAIL "$TMP/two.out")"

echo "the owner check still refuses a log root that is a symlink"
mkdir -p "$TMP/tmp2" "$TMP/elsewhere"; ln -s "$TMP/elsewhere" "$TMP/tmp2/demo-gates"
if TMPDIR="$TMP/tmp2" BARRIER="$TMP/barrier" TOKEN=x "$TMP/repo/Scripts/gates.sh" > "$TMP/sym.out" 2>&1; then
    bad "a symlinked log root was used"
else
    grep -q 'refusing log dir' "$TMP/sym.out" && ok "a symlinked log root is refused" || bad "unexpected: $(cat "$TMP/sym.out")"
fi

echo "a swift test passes only when every run that started printed its summary"
mkdir -p "$TMP/bin"
printf '#!/bin/sh\n/bin/cat "$FAKE_SWIFT_OUT"\n' > "$TMP/bin/swift"; chmod +x "$TMP/bin/swift"
printf '%s\n' '◇ Test run started.' '✔ Test run with 9 tests in 2 suites passed after 0.1 seconds.' \
    '◇ Test run started.' '✔ Test run with 6 tests in 1 suite passed after 0.1 seconds.' > "$TMP/whole.out"
printf '%s\n' '◇ Test run started.' '◇ Test run started.' \
    '✔ Test run with 6 tests in 1 suite passed after 0.1 seconds.' > "$TMP/cut.out"
judge_run() { TMPDIR="$TMP/tmpdir" PATH="$TMP/bin:$PATH" FAKE_SWIFT_OUT="$1" "$TMP/repo/Scripts/gates.sh" --only b > "$2" 2>&1; }
judge_run "$TMP/whole.out" "$TMP/whole.run"; rc=$?
[ "$rc" = 0 ] && ok "two runs, both finished: the stage passes" || bad "two finished runs exited $rc: $(cat "$TMP/whole.run")"
judge_run "$TMP/cut.out" "$TMP/cut.run"; rc=$?
# Exit 0 and one run's summary must not stand in for a run that never finished.
[ "$rc" = 1 ] && ok "two runs started, one finished: the stage fails" \
    || bad "two runs started and one finished exited $rc: $(cat "$TMP/cut.run")"
grep -q '^    verdict: 2 test runs started, 1 finished$' "$TMP/cut.run" \
    && ok "the FAIL names the runs that started and finished" || bad "no run-count verdict: $(cat "$TMP/cut.run")"

echo
if [ "$PASS" -eq 0 ] && [ "$FAIL" -eq 0 ]; then echo "gates per-run logs: no assertions ran" >&2; exit 2; fi
if [ "$FAIL" -eq 0 ]; then echo "gates per-run logs: $PASS/$PASS PASS"; exit 0; fi
echo "gates per-run logs: $PASS pass, $FAIL FAIL" >&2; exit 1

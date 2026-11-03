#!/bin/bash
# heavy-build-guard-test.sh - swift-nio-ssh's rows for .claude/hooks/local-heavy-build-guard.sh.
# build-tools' tests/test-heavy-build-guard.sh holds the engine's universal table; lib/heavy-guard-test.sh there holds
# what every adopter's stub must do. Needs a build-tools with the engine.
#
# Usage: Scripts/tests/heavy-build-guard-test.sh
set -uo pipefail
ROOT="$(cd "$(/usr/bin/dirname "$0")/../.." && pwd)"
HARNESS=""
for d in "${BUILD_TOOLS:-}" "${BUILD_LANE_ROOT:-}/build-tools" "$HOME/Developer/private/build-tools"; do
    [ -n "$d" ] && [ -f "$d/lib/heavy-guard-test.sh" ] && { HARNESS="$d/lib/heavy-guard-test.sh"; break; }
done
[ -n "$HARNESS" ] || { echo "FAIL: no build-tools with lib/heavy-guard-test.sh; set BUILD_TOOLS to a checkout that has it" >&2; exit 1; }
# shellcheck source=/dev/null
. "$HARNESS"
hg_begin "$ROOT"
hg_core_rows
hg_no_engine_rows
says "the refusal names the offload" yes "remote-kit-test.sh swift-nio-ssh --gates" 'xcodebuild build -scheme swift-nio-ssh'
hg_finish

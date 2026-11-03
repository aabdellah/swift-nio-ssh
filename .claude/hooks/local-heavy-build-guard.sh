#!/bin/bash
# Entry to build-tools' heavy-build guard (its README, "The heavy-build guard"). Only swift-nio-ssh's own words live here.
# Test: Scripts/tests/heavy-build-guard-test.sh.
engine="${HOME:-/nonexistent}/.local/libexec/build-tools/heavy-build-guard"
if [ -x "$engine" ]; then
    "$engine" \
        --hint '  ../Shell/Scripts/remote-kit-test.sh swift-nio-ssh --gates [--full | --only <stage>]
Each run leases its own lane on the build host, so concurrent workers need no setup.' && exit 0
    exit 2   # A broken engine refuses too: Claude Code blocks only on exit 2.
fi
case "$(/bin/cat)" in
    *xcodebuild*)
        echo "local-heavy-build-guard: no engine at $engine, so this command is refused. Install it: ${BUILD_TOOLS:-$HOME/Developer/private/build-tools}/bin/host-install --guard-only (bin/doctor checks it)." >&2
        exit 2 ;;
esac
exit 0

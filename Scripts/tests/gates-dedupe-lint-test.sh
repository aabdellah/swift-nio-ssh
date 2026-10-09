#!/bin/bash
# gates-dedupe-lint-test.sh - every check runs from exactly one gate stage, and no hook runs it again.
#
# The contract (../Shell/agent_docs/gates-standard.md): a check lives in ONE script, reached from ONE stage of
# Scripts/gates.sh; everything else - hooks, docs, wrappers - reaches it as `Scripts/gates.sh --only
# <stage>`. This gate fails when
#   1. a script is invoked from two stages of Scripts/gates.sh (helpers a stage calls count as the stage);
#   2. a git hook (.githooks/*) invokes a stage's script, or a script that script runs, directly
#      instead of through `Scripts/gates.sh --only <stage>`;
#   3. a Claude Code hook (.claude/hooks/*, .claude/settings.json) runs a stage's check at all - a hook
#      fires on every tool call or turn, so it would pay for the check again and again;
#   4. a Swift test re-runs the script gates (a `*-test.sh` or `run-all.sh` named in code, not a comment).
# Comments, heredoc text and echo/printf lines are prose, not invocations. Paths under `../` belong to a
# sibling repo and are ignored. One perl pass; it proves it can go red on a planted tree before it
# reads the real one. Usage: gates-dedupe-lint-test.sh [--root DIR]  (DIR scanned alone, no self-test)
set -uo pipefail

scan() { # $1 = repo root; prints violations, exits 1 on any
    local root="$1"
    [ -f "$root/Scripts/gates.sh" ] || [ -f "$root/scripts/gates.sh" ] || { echo "gates-dedupe: $root/Scripts/gates.sh is missing"; return 2; }
    (
        cd "$root" || exit 2
        { /usr/bin/find .githooks .claude/hooks -type f 2>/dev/null
          [ -f .claude/settings.json ] && echo .claude/settings.json
          /usr/bin/find Tests Packages/*/Tests -name '*.swift' -type f 2>/dev/null
          true  # a repo without Tests/ is not a failure; the perl verdict is the exit status
        } | /usr/bin/perl -e '
            use strict; use warnings;
            my $REF = qr{((?:\S*?/)?[Ss]cripts/[\w./-]+\.(?:sh|py))};
            sub calls {  # [script, arguments] on the command lines of a shell text
                my ($text) = @_; my (@out, $doc);
                $text =~ s/\\\n\s*/ /g;
                for my $line (split /\n/, $text) {
                    if (defined $doc) { undef $doc if $line =~ /^\s*\Q$doc\E\s*$/; next }
                    $doc = $1 if $line =~ /<<-?\s*["\x27]?(\w+)/;
                    next if $line =~ /^\s*#/ || $line =~ /^\s*(?:echo|printf)\b/;
                    $line =~ s/\s#\s.*$//;
                    while ($line =~ /$REF([^;&|)}]*)/g) {
                        my ($r, $args) = ($1, $2); next if $r =~ m{(?:^|/)\.\./};
                        $r =~ s{^.*?([Ss]cripts/)}{$1}; $args =~ s/^\s+|\s+$//g; $args =~ s/\s+/ /g;
                        push @out, [$r, $args];
                    }
                }
                return @out;
            }
            sub refs { return map { $_->[0] } calls(@_) }
            sub slurp { my ($f) = @_; open my $h, "<", $f or return ""; local $/; my $t = <$h>; return $t }
            sub stage_list { my ($m) = @_; return map { "stage_$_" } split " ", $m // "" }

            # 1. stage bodies (plus the helpers each calls, one level) -> scripts
            my $G = -d "Scripts" ? "Scripts/gates.sh" : "scripts/gates.sh";  # ShellKit spells it lower-case
            my $gates = slurp($G);
            my (%body, $cur);
            for my $line (split /\n/, $gates) {
                if (!defined $cur && $line =~ /^([A-Za-z_][\w-]*)\(\)\s*\{(.*)$/) {
                    my ($name, $rest) = ($1, $2);
                    if ($rest =~ /\}\s*$/) { $body{$name} = $rest; next }
                    $cur = $name; $body{$cur} = $rest; next;
                }
                if (defined $cur) { if ($line =~ /^\}/) { undef $cur } else { $body{$cur} .= "\n$line" } }
            }
            my %stages = map { $_ => 1 } grep { /^stage_/ } keys %body;
            my (%owner, %first, @bad);
            for my $s (sort keys %stages) {
                my %seen;
                my $text = $body{$s};
                for my $h (grep { !/^stage_/ } keys %body) { $text .= "\n$body{$h}" if $body{$s} =~ /(?<![\w-])\Q$h\E(?![\w-])/ }
                for my $c (calls($text)) {
                    my ($r, $args) = @$c;
                    next if $r eq $G || $seen{"$r $args"}++;
                    (my $st = $s) =~ s/^stage_//;
                    push @{ $owner{$r}{$args} }, $st;
                    $first{$r} //= $st;
                }
            }
            # one check = one script with one argument list (a platform flag makes a different check)
            for my $r (sort keys %owner) {
                for my $a (sort keys %{ $owner{$r} }) {
                    my @st = @{ $owner{$r}{$a} };
                    push @bad, "Scripts/gates.sh: $r" . ($a eq "" ? "" : " $a") . " is run by stages @st - one check, one stage"
                        if @st > 1;
                }
            }
            # the scripts each stage script runs, and the members run-all.sh discovers
            my %reach = %first;
            for my $r (keys %first) {
                for my $sub (refs(slurp($r))) { $reach{$sub} //= $first{$r} }
                if ($r =~ m{^([Ss]cripts/tests)/run-all\.sh$}) {
                    for my $t (glob("$1/*-test.sh")) {
                        $reach{$t} //= $first{$r};
                        for my $sub (refs(slurp($t))) { $reach{$sub} //= $first{$r} }
                    }
                }
            }
            # 2-4. hooks and Swift tests
            while (my $f = <STDIN>) {
                chomp $f; my $t = slurp($f);
                if ($f =~ /\.swift$/) {
                    for my $line (split /\n/, $t) {
                        next if $line =~ m{^\s*//};
                        push @bad, "$f: re-runs the script gates from a Swift test (that is the scripts stage)"
                            if $line =~ /-test\.sh"|run-all\.sh"/;
                    }
                    next;
                }
                if ($f eq ".claude/settings.json") {
                    my $cmds = join "\n", $t =~ /"command"\s*:\s*"((?:[^"\\]|\\.)*)"/g;
                    $t = $cmds;
                }
                my $claude = $f =~ m{^\.claude/};
                for my $r (refs($t)) {
                    if ($r eq $G) {
                        push @bad, "$f: a Claude Code hook runs Scripts/gates.sh - hooks fire every turn; gates run on demand"
                            if $claude;
                        next;
                    }
                    next unless exists $reach{$r};
                    push @bad, $claude
                        ? "$f: a Claude Code hook runs $r, which stage $reach{$r} already runs - delete the hook"
                        : "$f: runs $r directly - reach it as Scripts/gates.sh --only $reach{$r}";
                }
            }
            if (!%stages) { print "Scripts/gates.sh: no stage_* functions found - nothing scanned\n"; exit 2 }
            print "$_\n" for @bad;
            printf "gates-dedupe: %d stage(s), %d staged script(s), %d violation(s)\n",
                scalar(keys %stages), scalar(keys %first), scalar(@bad);
            exit(@bad ? 1 : 0);
        '
    )
}

if [ "${1:-}" = "--root" ]; then scan "${2:?--root needs a directory}"; exit $?; fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FIX="$(/usr/bin/mktemp -d "${TMPDIR:-/tmp}/gates-dedupe.XXXXXX")"
trap '/bin/rm -rf "$FIX"' EXIT
mkdir -p "$FIX/Scripts/tests" "$FIX/.githooks" "$FIX/.claude/hooks" "$FIX/Tests/T"
printf 'helper() { bash Scripts/x-lint.sh; }\nstage_a() { helper; }\nstage_b() {\n    bash Scripts/x-lint.sh\n}\nstage_c() { bash Scripts/tests/run-all.sh; }\n' > "$FIX/Scripts/gates.sh"
printf '#!/bin/bash\nexec Scripts/tests/run-all.sh\n' > "$FIX/.githooks/pre-commit"
printf '#!/bin/bash\nout="$(bash Scripts/y-lint.sh)"\n' > "$FIX/.claude/hooks/guard.sh"
printf '#!/bin/bash\nbash "$ROOT/Scripts/y-lint.sh" --fixture\n' > "$FIX/Scripts/tests/y-lint-test.sh"
printf 'let gate = "Scripts/tests/z-test.sh"\n' > "$FIX/Tests/T/Gate.swift"
out="$(scan "$FIX")"; rc=$?
fails=0
for want in "x-lint.sh is run by stages a b" ".githooks/pre-commit: runs Scripts/tests/run-all.sh" \
    ".claude/hooks/guard.sh: a Claude Code hook runs Scripts/y-lint.sh" "Gate.swift: re-runs the script gates"; do
    [[ "$out" == *"$want"* ]] || { echo "FAIL: the planted tree did not report: $want"; fails=1; }
done
[ "$rc" -eq 1 ] || { echo "FAIL: the planted tree exited $rc, want 1"; fails=1; }
((fails)) && { printf '%s\n' "$out"; exit 1; }

scan "$ROOT"

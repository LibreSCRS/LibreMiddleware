#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-release-lockstep.sh.
#
# Four cases, each one a mistake the original inline step's own comments name
# as real. A check that has never failed is not a check.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-release-lockstep.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fails=0
run() {   # run <name> <expected-rc> <dir>  [args...]
    name=$1; want=$2; dir=$3; shift 3
    ( cd "$dir" && sh "$subject" "$@" ) > "$work/out" 2>&1
    got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-52s rc=%s\n' "$name" "$got"
    else
        printf '  FAIL  %-52s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_1 -- a heading with nothing under it must FAIL. This is the one that
# actually shipped: testing for the header alone let it pass and the release
# went out with generic auto-notes.
d=$work/case_1; mkdir -p "$d"
printf '# Changelog\n\n## [Unreleased] — 5.0.0\n\n## [4.2.0]\n\n- something\n' > "$d/CHANGELOG.md"
printf '5.0.0\n' > "$d/VERSION"
run "case_1 empty section under the heading" 1 "$d" 5.0.0

# case_2 -- a bracket-less heading must PASS. The extractor reads it correctly;
# a near-miss pattern once reported it as missing, and that was the bug.
d=$work/case_2; mkdir -p "$d"
printf '# Changelog\n\n## 5.0.0\n\n- a real entry\n' > "$d/CHANGELOG.md"
printf '5.0.0\n' > "$d/VERSION"
run "case_2 bracket-less heading is found" 0 "$d" 5.0.0

# case_3 -- 5.0.0 must NOT match a [500.0] heading. Without escaping the dots
# the regex's `.` matches the `0` and the wrong section is accepted.
d=$work/case_3; mkdir -p "$d"
printf '# Changelog\n\n## [500.0]\n\n- the wrong section\n' > "$d/CHANGELOG.md"
printf '5.0.0\n' > "$d/VERSION"
run "case_3 unescaped dot must not match [500.0]" 1 "$d" 5.0.0

# case_4 -- a VERSION that disagrees must fail, and say so about VERSION.
d=$work/case_4; mkdir -p "$d"
printf '# Changelog\n\n## [Unreleased] — 5.0.0\n\n- a real entry\n' > "$d/CHANGELOG.md"
printf '4.2.0\n' > "$d/VERSION"
run "case_4 VERSION disagrees with the version asked for" 1 "$d" 5.0.0
( cd "$d" && sh "$subject" 5.0.0 2>&1 ) | grep -q "VERSION file holds '4.2.0'" \
    && printf '  ok    %-52s\n' "case_4 the message names VERSION, not the changelog" \
    || { printf '  FAIL  %-52s\n' "case_4 the message names VERSION, not the changelog"; fails=$((fails + 1)); }

# case_5 -- an absent CHANGELOG is the no-section case, reported, not a crash.
d=$work/case_5; mkdir -p "$d"
printf '5.0.0\n' > "$d/VERSION"
run "case_5 absent CHANGELOG is reported, not fatal" 1 "$d" 5.0.0

# case_6 -- the happy path, so a check that fails everything cannot pass this.
d=$work/case_6; mkdir -p "$d"
printf '# Changelog\n\n## [Unreleased] — 5.0.0\n\n- a real entry\n' > "$d/CHANGELOG.md"
printf '5.0.0\n' > "$d/VERSION"
run "case_6 agreeing changelog and VERSION" 0 "$d" 5.0.0

# case_7 -- no argument is a usage error, not a silent pass.
run "case_7 no version argument" 2 "$d"

if [ "$fails" -eq 0 ]; then
    echo "check-release-lockstep selftest: all cases passed"
    exit 0
fi
echo "check-release-lockstep selftest: $fails case(s) failed"
exit 1

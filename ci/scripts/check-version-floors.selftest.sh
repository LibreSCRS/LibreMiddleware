#!/usr/bin/env sh
# Selftest for check-version-floors.sh.
#
# Every case is a shape that actually occurred in this project, or a way this
# gate could pass on a tree it did not measure. A gate nobody has seen fail is
# a line in a workflow file.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-version-floors.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
cases=0
red=0

mkrepo() {  # mkrepo <dir> <version>
    mkdir -p "$1"
    ( cd "$1" && git init -q . && printf '%s\n' "$2" > VERSION && git add VERSION ) >/dev/null 2>&1
}
add() {     # add <dir> <relpath> <content>   -- `git add` is enough; git grep reads the index
    mkdir -p "$(dirname -- "$1/$2")"
    printf '%s\n' "$3" > "$1/$2"
    ( cd "$1" && git add -- "$2" ) >/dev/null 2>&1
}
says() {    # says <name> <yes|no> <pattern> -- judge the LAST run's output
    name=$1; want=$2; pat=$3
    if grep -q -- "$pat" "$work/out"; then got=yes; else got=no; fi
    if [ "$got" = "$want" ]; then
        printf '  ok    %-56s said=%s\n' "$name" "$got"
    else
        printf '  FAIL  %-56s said=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}
run() {     # run <name> <expected-rc> <dir> [args...]
    name=$1; want=$2; dir=$3; shift 3
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$want" != 0 ]; then red=$((red + 1)); fi
    ( cd "$dir" && sh "$subject" "$@" ) > "$work/out" 2>&1
    got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-56s rc=%s\n' "$name" "$got"
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_1 -- the line that shipped: the SDK example floored a whole major below
# the package it is built against. This is the case the gate exists for.
d=$work/case_1; mkrepo "$d" 5.0.0
add "$d" examples/sdk/CMakeLists.txt 'find_package(LibreMiddleware 4.0 REQUIRED CONFIG)'
run "case_1 floor a major below VERSION" 1 "$d"

# case_2 -- a floor ABOVE VERSION is exactly as unsatisfiable under
# SameMajorVersion, so ">=" would be the wrong comparison.
d=$work/case_2; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'find_package(LibreAgent 6.0 REQUIRED CONFIG)'
run "case_2 floor a major above VERSION" 1 "$d"

# case_3 -- the happy path, so a gate that fails everything cannot pass this.
d=$work/case_3; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'find_package(LibreMiddleware 5.0 REQUIRED CONFIG)'
run "case_3 agreeing floor" 0 "$d"

# case_4 -- the VERSION_RANGE shape that shipped in the consumer docs. Its
# floor is the FIRST token; a scanner that reads the last one calls 4.1...<5.0
# a 5.x floor and passes the worst line in the document.
d=$work/case_4; mkrepo "$d" 5.0.0
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 4.1...<5.0 REQUIRED CONFIG)'
run "case_4 range floor reads the low end" 1 "$d"

# case_5 -- the same shape with the low end inside the major. This fixture has
# no project() name, so LibreMiddleware is a FOREIGN package here and only the
# major is comparable; case_19 is the same line in the repository that publishes
# that package, where it is a failure.
d=$work/case_5; mkrepo "$d" 5.0.0
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.1...<6.0 REQUIRED CONFIG)'
run "case_5 range floor inside the major, foreign package" 0 "$d"

# case_6 -- `4.x`. A `git grep 4.2` sweep does not see this and neither does a
# scanner that insists on three numeric components.
d=$work/case_6; mkrepo "$d" 5.0.0
add "$d" cmake/GitVersion.cmake '# breaks find_package(LibreMiddleware 4.x CONFIG) at configure time'
run "case_6 the 4.x shape" 1 "$d"

# case_7 -- CHANGELOG.md is a historical record. "a find_package(LibreAgent 4.2
# ...) floor no longer applies" is a true sentence about a past release and
# must not fail the gate, or the release note that removes a floor becomes the
# reason the gate is red.
d=$work/case_7; mkrepo "$d" 5.0.0
add "$d" CHANGELOG.md '- a `find_package(LibreAgent 4.2 ...)` floor no longer applies'
run "case_7 CHANGELOG is exempt" 0 "$d"

# case_8 -- vendored code carries its own versions.
d=$work/case_8; mkrepo "$d" 5.0.0
add "$d" thirdparty/foo/CMakeLists.txt 'find_package(LibreMiddleware 4.0 REQUIRED CONFIG)'
run "case_8 thirdparty is exempt" 0 "$d"

# case_9 -- a bare call carries no floor and must not be invented into one.
d=$work/case_9; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'find_package(LibreMiddleware REQUIRED CONFIG)'
run "case_9 a versionless call is not a floor" 0 "$d"

# case_10 -- find_dependency() inside a Config package is the same contract
# under a different verb.
d=$work/case_10; mkrepo "$d" 5.0.0
add "$d" cmake/Config.cmake.in 'find_dependency(LibreMiddleware 4.2 REQUIRED CONFIG)'
run "case_10 find_dependency counts" 1 "$d"

# case_11 -- the vacuum. A repository whose scan matches nothing is not proved
# clean, it is unmeasured; --min says how many floors the caller knows exist.
d=$work/case_11; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" README.md 'no floors here at all'
run "case_11 no floors, --min 1, is a failure" 1 "$d" --min 1
run "case_11b no floors, no --min, is a pass"  0 "$d"

# case_12 -- not a git checkout: the scan cannot run, and "cannot judge" must
# not be spelled the same as "clean".
d=$work/case_12; mkdir -p "$d"; printf '5.0.0\n' > "$d/VERSION"
run "case_12 outside a git checkout is rc=2, not a pass" 2 "$d"

# case_13 -- VERSION unreadable: same rule, the gate must refuse to judge.
d=$work/case_13; mkrepo "$d" 5.0.0
rm -f "$d/VERSION"
add "$d" CMakeLists.txt 'find_package(LibreMiddleware 4.0 REQUIRED CONFIG)'
run "case_13 no VERSION is rc=2, not a pass" 2 "$d"

# case_14 -- two calls on one line; a scanner that stops at the first match
# passes the second one.
d=$work/case_14; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'find_package(LibreAgent 5.0 CONFIG) find_package(LibreMiddleware 4.0 CONFIG)'
run "case_14 second call on the same line is seen" 1 "$d"

# case_15 -- the gate's own text carries wrong floors as fixtures and must not
# fail on itself.
d=$work/case_15; mkrepo "$d" 5.0.0
mkdir -p "$d/ci/scripts"
cp "$subject" "$d/ci/scripts/check-version-floors.sh"
cp "$here/check-version-floors.selftest.sh" "$d/ci/scripts/check-version-floors.selftest.sh"
( cd "$d" && git add ci/scripts ) >/dev/null 2>&1
run "case_15 the gate does not fail on its own fixtures" 0 "$d"

# case_16 -- the window a major bump opens: this repository is still on 5, the
# package it floors against has already moved to 6. Without saying so the tree
# is a failure; naming the expectation per package describes it instead. Both
# halves are asserted, because an override that made everything green would be
# a way of not running the gate.
d=$work/case_16; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'find_package(LibreMiddleware 6.0 REQUIRED CONFIG)'
add "$d" cmake/Config.cmake.in 'find_dependency(LibreAgent 5.0 REQUIRED CONFIG)'
run "case_16 mixed majors without an override is a failure" 1 "$d"
LIBRESCRS_FLOOR_MAJOR="LibreMiddleware=6"; export LIBRESCRS_FLOOR_MAJOR
run "case_16b the same tree, expectation keyed per package" 0 "$d"
unset LIBRESCRS_FLOOR_MAJOR

# case_17 -- the override names one package and must not cover the others: a
# blanket skip and a per-package expectation are the same green otherwise.
d=$work/case_17; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'find_package(LibreMiddleware 6.0 REQUIRED CONFIG)'
add "$d" src/CMakeLists.txt 'find_package(LibreCelik 4.0 REQUIRED CONFIG)'
LIBRESCRS_FLOOR_MAJOR="LibreMiddleware=6"; export LIBRESCRS_FLOOR_MAJOR
run "case_17 an override for one package covers only that one" 1 "$d"
unset LIBRESCRS_FLOOR_MAJOR

# case_18 -- an override nobody can parse is not an override; refusing to judge
# is rc=2, never a pass.
d=$work/case_18; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'find_package(LibreMiddleware 5.0 REQUIRED CONFIG)'
LIBRESCRS_FLOOR_MAJOR="LibreMiddleware=six"; export LIBRESCRS_FLOOR_MAJOR
run "case_18 an unparsable override is rc=2, not a pass" 2 "$d"
unset LIBRESCRS_FLOOR_MAJOR

# case_19 -- the line that shipped in the consumer guide: a minor pin whose low
# end is above the version this repository installs. Its major agrees, so a gate
# comparing majors calls it clean, and the generated SameMajorVersion file
# refuses it anyway. Measured against a real install: `5.1...<6.0` against 5.0.0
# is "no configuration file compatible with requested version range".
d=$work/case_19; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.1...<6.0 REQUIRED CONFIG)'
run "case_19 a minor pin above what this repository ships" 1 "$d"

# case_20 -- the satisfiable spelling of the same recipe, so a gate that failed
# every range would pass case_19 for the wrong reason.
d=$work/case_20; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...<6.0 REQUIRED CONFIG)'
run "case_20 a minor pin the shipped package satisfies" 0 "$d"

# case_21 -- the limit, asserted rather than assumed: a minor pin on ANOTHER
# component cannot be judged here, because this checkout does not know that
# component's minor. Turning this into a failure would make every lockstep
# window red for a floor that is correct.
d=$work/case_21; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" src/CMakeLists.txt 'find_package(LibreAgent 5.4 REQUIRED CONFIG)'
run "case_21 a minor pin on another component is not judged" 0 "$d"

# case_22 -- a per-package override naming a DIFFERENT major says the shipped
# version is not what VERSION says, so the whole-version comparison must stand
# down with the major one. case_23b is the spelling that says nothing new.
d=$work/case_22; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 6.1...<7.0 REQUIRED CONFIG)'
run "case_22 without the override the pin is a failure" 1 "$d"
LIBRESCRS_FLOOR_MAJOR="LibreMiddleware=6"; export LIBRESCRS_FLOOR_MAJOR
run "case_22b the override covers the whole comparison" 0 "$d"
unset LIBRESCRS_FLOOR_MAJOR

# case_23 -- an override that REPEATS the major already in VERSION contradicts
# nothing, so it must not make the whole-version comparison disappear. It did:
# the expectation was read before VERSION was, and any spelling of the override
# switched the comparison off with the ordinary green line. An env var that
# removes a check without saying so is a way of not running the gate.
d=$work/case_23; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.1...<6.0 REQUIRED CONFIG)'
LIBRESCRS_FLOOR_MAJOR="5"; export LIBRESCRS_FLOOR_MAJOR
run "case_23 repeating VERSION's own major is not a change" 1 "$d"
unset LIBRESCRS_FLOOR_MAJOR
LIBRESCRS_FLOOR_MAJOR="LibreMiddleware=5"; export LIBRESCRS_FLOOR_MAJOR
run "case_23b the per-package spelling of the same non-change" 1 "$d"
unset LIBRESCRS_FLOOR_MAJOR

# case_24 -- the other half: an override naming a DIFFERENT major does say
# VERSION is not the shipped truth, so there the comparison must stand down --
# in the bare spelling too, not only the per-package one case_22b covers.
d=$work/case_24; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 6.1...<7.0 REQUIRED CONFIG)'
LIBRESCRS_FLOOR_MAJOR="6"; export LIBRESCRS_FLOOR_MAJOR
run "case_24 a bare override on another major stands it down" 0 "$d"
# and it must say so: a comparison that disappears without a word is the shape
# this gate was written against.
says "case_24b the stand-down names itself" yes "compared by major only"
unset LIBRESCRS_FLOOR_MAJOR
run  "case_24c without the override the same tree is a failure" 1 "$d"
says "case_24d ... and nothing was stood down" no "compared by major only"

# case_25 -- a range has two ends and the generated ConfigVersion file checks
# both. This is the drift shape: a range written correctly at 5.0 goes
# unsatisfiable the day VERSION reaches 5.1, with no digit in the line changing
# and its major still agreeing. Asserted at both VERSIONs so a gate that failed
# every range could not pass the second half.
d=$work/case_25; mkrepo "$d" 5.1.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.1.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...<5.1 REQUIRED CONFIG)'
run "case_25 a range whose top excludes what this tree ships" 1 "$d"
d=$work/case_25b; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...<5.1 REQUIRED CONFIG)'
run "case_25b the same line while the tree still ships 5.0.0" 0 "$d"

# case_26 -- the inclusive spelling of a range excludes by being BELOW the
# shipped version rather than equal to it, which is a different comparison.
d=$work/case_26; mkrepo "$d" 5.1.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.1.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...5.0 REQUIRED CONFIG)'
run "case_26 an inclusive range ending below what we ship" 1 "$d"

# case_27 -- the limit again, on the upper bound this time: another component's
# range cannot be judged here either, for the same reason case_21 gives.
d=$work/case_27; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" src/CMakeLists.txt 'find_package(LibreAgent 5.0...<5.0 REQUIRED CONFIG)'
run "case_27 another component's range top is not judged" 0 "$d"

# case_28 -- the top of a range has a major rule of its own, on top of the value
# one case_25/case_26 cover: an inclusive top must stay inside the installed
# major, an exclusive top may reach the next major exactly and no further. Both
# shapes below floor at 5.0 and lead with the agreeing major, so nothing but the
# top end distinguishes them from the recipe the guide ships. Measured against a
# real install of 5.0.0: `5.0...6.0` and `5.0...<7.0` are refused, `5.0...<6.0`
# (case_20) and `5.0...5.9` (case_28d) configure.
d=$work/case_28; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...6.0 REQUIRED CONFIG)'
run  "case_28 an inclusive top in the next major" 1 "$d"
says "case_28b ... and the message names the line it left" yes "outside the major 5 line"
d=$work/case_28c; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...<7.0 REQUIRED CONFIG)'
run "case_28c an exclusive top past the next major" 1 "$d"
d=$work/case_28d; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...5.9 REQUIRED CONFIG)'
run "case_28d an inclusive top inside the major is satisfiable" 0 "$d"
# ... and the same limit as case_21/case_27: another component's top is not ours
# to judge, so a gate failing every high end could not pass this.
d=$work/case_28e; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" src/CMakeLists.txt 'find_package(LibreAgent 5.0...7.0 REQUIRED CONFIG)'
run "case_28e another component's top is not judged" 0 "$d"

# case_29 -- inspection mode and check mode must not tell a reader different
# things about the same line: the --list row for a floor the check rejects
# carries that verdict, instead of a bare "major 5 expected 5".
d=$work/case_29; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.1...<6.0 REQUIRED CONFIG)'
run  "case_29 --list is inspection, so it still exits 0" 0 "$d" --list
says "case_29b --list names the verdict the check reaches" yes "UNSATISFIABLE"
run  "case_29c the same tree in check mode is a failure" 1 "$d"
d=$work/case_29d; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.0...<6.0 REQUIRED CONFIG)'
run  "case_29d a satisfiable floor lists clean" 0 "$d" --list
says "case_29e ... and carries no verdict marker" no "UNSATISFIABLE"

# case_30 -- the whole-floor comparison rests on a package name read from
# `project()`. Without it the check falls back to the major-only one it replaced
# and says so on stderr -- a comparison disappearing while the job stays green,
# which is the shape this gate exists to remove. `--min` is the caller saying
# this repository IS meant to be measurable, so there the fallback is rc=2. The
# floor below is the one case_19 fails on, so the fixture is only green while the
# comparison is absent.
d=$work/case_30; mkrepo "$d" 5.0.0
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.1...<6.0 REQUIRED CONFIG)'
run  "case_30 no project() under --min is rc=2, not a pass" 2 "$d" --min 1
says "case_30b ... and names what could not be set up" yes "could not be set up"
# Without --min the note stands and the run is green: a checkout with no CMake
# build publishes no package of its own, and the cross-repository check that
# delegates to this gate from such a repository must not be failing it for
# lacking something it never had.
run  "case_30c the same tree without --min keeps the note" 0 "$d"
says "case_30d ... and the note is the reason it is green" yes "compared by major only"
# The control: the identical floor with a project() line to compare it against.
d=$work/case_30e; mkrepo "$d" 5.0.0
add "$d" CMakeLists.txt 'project(LibreMiddleware VERSION 5.0.0 LANGUAGES CXX)'
add "$d" docs/CONSUMERS.md 'find_package(LibreMiddleware 5.1...<6.0 REQUIRED CONFIG)'
run "case_30e with project() the same floor is judged whole" 1 "$d" --min 1

if [ "$fails" -eq 0 ]; then
    echo "check-version-floors selftest: all cases passed"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-version-floors selftest: $fails case(s) failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1

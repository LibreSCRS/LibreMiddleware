#!/usr/bin/env sh
# check-version-stamp.selftest.sh
#
# Proves check-version-stamp.sh can tell red from green, on fixtures rather than
# on this repository -- a gate measured only against a tree that passes is a gate
# nobody has seen fail.
#
# The fixtures are three-line CMake projects with LANGUAGES NONE, so no compiler
# is detected and each case is a fraction of a second. Each carries a version
# module of a shape that has really been written: the one that lets the tag
# decide unconditionally is the shape that shipped a 4.2.0 stamp under a 5.0.0
# VERSION, and the one that ignores git is the over-correction.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

HERE="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
GATE="$HERE/check-version-stamp.sh"
[ -x "$GATE" ] || { echo "FAIL: $GATE is not executable"; exit 1; }

WORK="$(mktemp -d)" || exit 2
trap 'rm -rf "$WORK"' EXIT INT TERM
fails=0
n=0
red=0

# $1 dir, $2 module flavour: newer-wins | tag-wins | no-git
module() {
    mkdir -p "$1/cmake"
    {
        echo 'if(NOT DEFINED GIT_EXECUTABLE)'
        echo '    find_package(Git QUIET REQUIRED)'
        echo 'endif()'
        echo 'set(SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/..")'
        echo 'set(V "")'
        if [ "$2" != "no-git" ]; then
            echo 'if(GIT_EXECUTABLE)'
            echo '  execute_process(COMMAND ${GIT_EXECUTABLE} describe --tags'
            echo '    WORKING_DIRECTORY ${SRC_DIR} OUTPUT_VARIABLE V RESULT_VARIABLE E'
            echo '    OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)'
            echo '  if(E)'
            echo '    set(V "")'
            echo '  endif()'
            echo 'endif()'
        fi
        echo 'set(F "")'
        echo 'if(EXISTS "${SRC_DIR}/VERSION")'
        echo '  file(STRINGS "${SRC_DIR}/VERSION" F LIMIT_COUNT 1)'
        echo '  string(STRIP "${F}" F)'
        echo 'endif()'
        echo 'if(V STREQUAL "")'
        echo '  set(V "${F}")'
        if [ "$2" = "newer-wins" ]; then
            echo 'elseif(NOT F STREQUAL "")'
            echo '  string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" VT "${V}")'
            echo '  string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" FT "${F}")'
            echo '  if(FT VERSION_GREATER VT)'
            echo '    set(V "${FT}")'
            echo '  endif()'
        fi
        echo 'endif()'
        echo 'if(NOT V)'
        echo '  set(V 0.0.1)'
        echo 'endif()'
        echo 'string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)" M "${V}")'
        echo 'set(GIT_VERSION_MAJOR ${CMAKE_MATCH_1})'
        echo 'set(GIT_VERSION_MINOR ${CMAKE_MATCH_2})'
        echo 'set(GIT_VERSION_PATCH ${CMAKE_MATCH_3})'
    } > "$1/cmake/GitVersion.cmake"
}

project_file() {
    {
        echo 'cmake_minimum_required(VERSION 3.24)'
        echo 'include(cmake/GitVersion.cmake)'
        echo 'project(StampFixture VERSION ${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}.${GIT_VERSION_PATCH} LANGUAGES NONE)'
    } > "$1/CMakeLists.txt"
}

# $1 label, $2 expected rc, $3 dir
expect() {
    n=$((n + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$2" != 0 ]; then red=$((red + 1)); fi
    out="$( (cd "$3" && sh "$GATE") 2>&1 )"
    rc=$?
    if [ "$rc" != "$2" ]; then
        echo "FAIL: $1 -- expected rc=$2, got rc=$rc"
        printf '%s\n' "$out" | sed 's/^/       /'
        fails=$((fails + 1))
    fi
}

# case_1 -- the shape the project ships: the file version wins when the tag is
# behind, the tag wins when it is ahead.
d="$WORK/c1"; mkdir -p "$d"; module "$d" newer-wins; project_file "$d"; echo 5.0.0 > "$d/VERSION"
expect case_1_newer_wins 0 "$d"

# case_2 -- the defect: describe decides unconditionally, so a tag a major
# behind stamps the old major over a bumped VERSION. This is the case that was
# live in a shipped tree with every other gate green.
d="$WORK/c2"; mkdir -p "$d"; module "$d" tag-wins; project_file "$d"; echo 5.0.0 > "$d/VERSION"
expect case_2_stale_tag_wins 1 "$d"

# case_3 -- the over-correction: git ignored altogether, so a tag AHEAD of
# VERSION (a release commit, a hotfix branch) is stamped as the old version.
# A one-sided gate would call this clean.
d="$WORK/c3"; mkdir -p "$d"; module "$d" no-git; project_file "$d"; echo 5.0.0 > "$d/VERSION"
expect case_3_tag_ahead_ignored 1 "$d"

# case_4 -- no VERSION file: there is no expected major, so there is no verdict.
d="$WORK/c4"; mkdir -p "$d"; module "$d" newer-wins; project_file "$d"
expect case_4_no_version_file 2 "$d"

# case_5 -- VERSION carries no numeric major.
d="$WORK/c5"; mkdir -p "$d"; module "$d" newer-wins; project_file "$d"; echo "unreleased" > "$d/VERSION"
expect case_5_unparsable_version 2 "$d"

# case_6 -- nothing to configure.
d="$WORK/c6"; mkdir -p "$d"; echo 5.0.0 > "$d/VERSION"
expect case_6_no_cmakelists 2 "$d"

# case_7 -- the configure dies before project(), so the probe never records a
# stamp. "Could not measure" must not be spelled the same as "measured, clean".
d="$WORK/c7"; mkdir -p "$d"; module "$d" newer-wins; echo 5.0.0 > "$d/VERSION"
{
    echo 'cmake_minimum_required(VERSION 3.24)'
    echo 'message(FATAL_ERROR "fixture: dies before project()")'
} > "$d/CMakeLists.txt"
expect case_7_probe_never_reached 2 "$d"

if [ "$fails" = 0 ]; then
    echo "check-version-stamp selftest: all $n cases passed"
    printf 'selftest: %s cases, %s red-proved\n' "$n" "$red"
    exit 0
fi
echo "check-version-stamp selftest: $fails of $n cases FAILED"
printf 'selftest: %s cases, %s red-proved\n' "$n" "$red"
exit 1

#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-version-stamp.sh [--verbose]
#
# The version this tree STAMPS -- what `project()` ends up with, and with it the
# Config package, the SONAME, the packaging metadata and every banner -- must
# name the same major as the VERSION file, even while the newest reachable
# release tag is still a major behind.
#
# Why this is not covered by anything else: check-version-floors.sh reads
# VERSION and the sources, so it is green whatever the version derivation does;
# configuring with an EMPTY GIT_EXECUTABLE measures the tarball path, which is
# the one input under which a tag cannot win at all; and a test that asserts
# the stamp is self-consistent (triple is a prefix of the full string, not the
# 0.0.1 fallback) is satisfied by the wrong major exactly as by the right one.
# The defect this measures shipped in a release-shaped tree with
# all three of those green: VERSION, the changelog and the package metadata said
# 5.0.0 while project(), the About window and the bundle keys said 4.2.0.
#
# How it is measured, and why a stub rather than the checkout's own tags: the
# real top-level CMakeLists is configured with GIT_EXECUTABLE pointed at a
# script that answers `describe` with a tag chosen by this gate, and with
# CMAKE_PROJECT_INCLUDE pointed at a probe that records PROJECT_VERSION and
# stops the configure before the first find_package(). So the answer does not
# depend on which tags the CI checkout happened to fetch -- a shallow clone with
# no tags would otherwise make the interesting case unreachable and the gate
# vacuously green -- and no tag is ever created anywhere.
#
# Two cases, because one of them alone is passed by a module that is simply
# wrong in the other direction:
#   behind  tag one major BELOW VERSION  -> the stamp must be VERSION's major
#   ahead   tag one major ABOVE VERSION  -> the stamp must be the TAG's major
# A module that ignored git would pass the first and fail the second; one that
# lets the tag decide unconditionally does the reverse.
#
# Exit: 0 both cases stamp the expected major · 1 one of them does not
#       2 the stamp could not be measured -- NOT a pass.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

VERBOSE=0
[ "${1:-}" = "--verbose" ] && VERBOSE=1

VERSION_FILE=${VERSION_FILE:-VERSION}
FILE_VER="$(head -n1 "$VERSION_FILE" 2>/dev/null | tr -d '[:space:]')"
FILE_VER=${FILE_VER#v}
WANT="$(printf '%s' "$FILE_VER" | sed -n 's/^\([0-9][0-9]*\).*$/\1/p')"
if [ -z "$WANT" ]; then
    echo "::error::no major version in $VERSION_FILE -- the stamped version was NOT measured" >&2
    exit 2
fi

[ -f CMakeLists.txt ] || {
    echo "::error::no CMakeLists.txt here -- the stamped version was NOT measured" >&2; exit 2; }
command -v cmake >/dev/null 2>&1 || {
    echo "::error::cmake not found -- the stamped version was NOT measured" >&2; exit 2; }
REAL_GIT="$(command -v git 2>/dev/null)"
[ -n "$REAL_GIT" ] || {
    echo "::error::git not found -- the stamped version was NOT measured" >&2; exit 2; }

SRC="$(pwd)"
TMP="$(mktemp -d)" || { echo "::error::mktemp failed -- the stamped version was NOT measured" >&2; exit 2; }
trap 'rm -rf "$TMP"' EXIT INT TERM

cat > "$TMP/probe.cmake" <<'PROBE'
file(WRITE "$ENV{LIBRESCRS_STAMP_OUT}" "${PROJECT_VERSION}")
message(FATAL_ERROR "version-stamp probe: stopping before the first find_package()")
PROBE

# The stub answers only `describe`; everything else the module asks (which
# repository is this, where is the git dir) must keep telling the truth, or the
# module under test takes a path no real build ever takes.
stub() {
    cat > "$TMP/git" <<STUB
#!/usr/bin/env sh
if [ "\${1:-}" = "describe" ]; then printf '%s\n' '$1'; exit 0; fi
exec "$REAL_GIT" "\$@"
STUB
    chmod 755 "$TMP/git"
}

rc=0
run_case() {
    _label=$1; _tag=$2; _expect=$3
    stub "$_tag"
    rm -rf "$TMP/b" "$TMP/stamp"
    LIBRESCRS_STAMP_OUT="$TMP/stamp" cmake -S "$SRC" -B "$TMP/b" \
        -DGIT_EXECUTABLE="$TMP/git" -DCMAKE_PROJECT_INCLUDE="$TMP/probe.cmake" \
        > "$TMP/log" 2>&1
    _got="$(cat "$TMP/stamp" 2>/dev/null)"
    if [ -z "$_got" ]; then
        echo "::error::configure never reached project() with the probe attached -- the stamped version was NOT measured" >&2
        tail -n 15 "$TMP/log" >&2
        exit 2
    fi
    _maj="$(printf '%s' "$_got" | sed -n 's/^\([0-9][0-9]*\).*$/\1/p')"
    if [ "$VERBOSE" = 1 ]; then
        printf '  %-7s tag %-10s -> stamped %-12s (expected major %s)\n' "$_label" "$_tag" "$_got" "$_expect"
    fi
    if [ "$_maj" != "$_expect" ]; then
        printf '::error::%s: with the nearest release tag at %s and %s at %s, the tree stamps %s\n' \
               "$_label" "$_tag" "$VERSION_FILE" "$FILE_VER" "$_got" >&2
        printf '          project() must carry major %s here, not %s\n' "$_expect" "${_maj:-<none>}" >&2
        rc=1
    fi
}

BEHIND=$((WANT - 1))
AHEAD=$((WANT + 1))
if [ "$BEHIND" -lt 0 ]; then
    echo "::error::$VERSION_FILE names major $WANT -- no major below it to measure against" >&2
    exit 2
fi

run_case behind "${BEHIND}.0.0" "$WANT"
run_case ahead  "${AHEAD}.0.0"  "$AHEAD"

if [ "$rc" = 0 ]; then
    echo "  -> the tree stamps major $WANT with a stale tag, and the tag's major when the tag is ahead"
fi
exit "$rc"

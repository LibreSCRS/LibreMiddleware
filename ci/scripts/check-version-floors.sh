#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-version-floors.sh [--list] [--min <n>]
#
# Every first-party `find_package(...)` / `find_dependency(...)` version floor
# in this repository must name the SAME MAJOR as the VERSION file.
#
# Why a property and not a token: the 4.x floors were swept for with
# `git grep 4.2`, and the one that mattered read `4.0`, so it survived the
# sweep and the only executable consumer in the project kept a floor no shipped
# package can satisfy. Counting hits cannot answer "is any floor wrong";
# comparing every floor against VERSION can.
#
# Why VERSION and not `git describe`: `describe` answers with the PREVIOUS
# release for the whole development cycle, so a gate reading it would call the
# tree green while the package the tree ships is a major ahead. VERSION is
# bumped at code freeze and is the only version present in a source tarball.
#
# Equality, not ">=": the Config packages declare COMPATIBILITY
# SameMajorVersion, under which a floor ABOVE the installed major is exactly as
# unsatisfiable as one below it. Measured in both directions.
#
# The major is not the whole floor. A generated SameMajorVersion file rejects a
# request whose lower bound is above the installed version before it ever looks
# at the major, so `5.1...<6.0` against an installed 5.0.0 is refused while its
# major agrees; and it rejects one whose upper bound excludes the installed
# version for the mirror-image reason, so `5.0...<5.1` goes unsatisfiable the
# day VERSION reaches 5.1 without any digit in it changing. On top of that the
# upper bound carries a major rule of its own: an INCLUSIVE top must sit inside
# the installed major, an EXCLUSIVE top may reach the next major exactly and no
# further. Measured against a real install of 5.0.0, not derived from the
# generated file: `5.0...6.0` and `5.0...<7.0` are both refused with "no
# configuration file compatible with requested version range", while
# `5.0...<6.0` and `5.0...5.9` configure. A floor on the package THIS
# repository publishes is therefore compared whole -- BOTH ends of a range, by
# value and by major -- against the whole VERSION. There, and only there, is
# the shipped version known exactly. Floors on every other package keep the
# major-only comparison, because this checkout cannot know another component's
# minor.
#
# The whole-floor comparison needs the package name, and the name is read from
# `project()` in the top-level CMakeLists.txt. When it cannot be read the check
# falls back to the major-only one it was written to replace, which is a
# comparison disappearing quietly -- the shape this gate exists to remove. So
# `--min`, which is the caller stating that this repository is meant to be
# measurable, makes an unreadable name rc=2 instead of a green run with a note.
# Without `--min` the note alone stands, because a checkout with no CMake build
# publishes no package of its own and has nothing to compare whole; that is the
# call a cross-repository check makes on such a repository, and it must not be
# turned into a failure for lacking something it never had.
#
# What that comparison rests on is VERSION being the truth about what this
# repository ships, so it stands down exactly when something says it is not.
# An expectation naming a DIFFERENT major than VERSION says precisely that, and
# for the package it covers the comparison drops back to majors -- announced on
# stderr, because a check that disappears quietly is not a check. An
# expectation naming the SAME major as VERSION contradicts nothing and stands
# nothing down: an override that changes no expectation must not silently
# remove a comparison.
#
# The expected major is this repository's own VERSION, which is the right answer
# only while every component shares a major. That premise is STATED here, not
# proved here: the in-repo release-lockstep check compares this repository's
# CHANGELOG against this repository's VERSION and has no view of any other
# checkout, and no check in this repository can have one.
#
# The premise stops holding on purpose, not by accident: a major bump reaches
# the components one at a time, and for that whole window a floor naming the NEW
# major is correct while this repository's VERSION still names the old one. So
# the expectation is keyed per PACKAGE and not only per repository --
# LIBRESCRS_FLOOR_MAJOR takes a bare major for everything, or `Package=major`
# pairs, or both:
#
#   LIBRESCRS_FLOOR_MAJOR=6                       every first-party floor is 6
#   LIBRESCRS_FLOOR_MAJOR="LibreMiddleware=6"     that package is 6, the rest
#                                                 keep the major in VERSION
#   LIBRESCRS_FLOOR_MAJOR="LibreMiddleware=6 4"   ... and 4 for the rest
#
# Both spellings are expectations in the sense above: whichever one ends up
# covering this repository's own package decides whether that package's floors
# are still comparable against the whole VERSION.
#
# Without that the only way through the window is to stop running the gate,
# which is not a transfer of the check to anybody.
#
# Exemptions, each for a reason and no others:
#   CHANGELOG.md   a release note naming the floor a past release carried is a
#                  correct historical record, not a live floor.
#   thirdparty/    vendored code, not ours to version.
#   this script + its selftest, which carry wrong floors on purpose as fixtures.
#
# Exit: 0 all floors agree · 1 a floor disagrees (or fewer than --min found)
#       2 the scan could not run, or `--min` was given and the whole-floor
#         comparison could not be set up -- NOT a pass.
# `--list` prints every floor with the verdict the check would reach, so the
# inspection mode and the check mode cannot tell a reader different things.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

MODE=check
MIN=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --list) MODE=list ;;
        --min)  shift; MIN=${1:-0} ;;
        *) echo "usage: check-version-floors.sh [--list] [--min <n>]" >&2; exit 2 ;;
    esac
    shift
done

VERSION_FILE=${VERSION_FILE:-VERSION}
WANT=""
MAP=""
for tok in $(printf '%s' "${LIBRESCRS_FLOOR_MAJOR:-}" | tr ',' ' '); do
    case "$tok" in
        *=*)
            pkg=${tok%%=*}; maj=${tok#*=}
            case "$pkg" in ''|*[!A-Za-z0-9_]*) maj="" ;; esac
            case "$maj" in ''|*[!0-9]*)
                echo "::error::LIBRESCRS_FLOOR_MAJOR: \"$tok\" is not <Package>=<major>" >&2
                exit 2 ;;
            esac
            MAP="$MAP $pkg=$maj" ;;
        *[!0-9]*)
            echo "::error::LIBRESCRS_FLOOR_MAJOR: \"$tok\" is neither a major nor <Package>=<major>" >&2
            exit 2 ;;
        *) WANT=$tok ;;
    esac
done
FILE_VER="$(head -n1 "$VERSION_FILE" 2>/dev/null | tr -d '[:space:]')"
FILE_VER=${FILE_VER#v}
FILE_MAJ="$(printf '%s' "$FILE_VER" | sed -n 's/^\([0-9][0-9]*\).*$/\1/p')"
ENV_WANT=0
if [ -n "$WANT" ]; then
    ENV_WANT=1
else
    WANT=$FILE_MAJ
fi
if [ -z "$WANT" ]; then
    echo "::error::no major version in $VERSION_FILE -- floors NOT measured" >&2
    exit 2
fi

# The whole-floor comparison needs a package name AND a version it can trust.
SELF_PKG="$(sed -n 's/^[[:space:]]*project([[:space:]]*\([A-Za-z][A-Za-z0-9_]*\).*$/\1/p' \
            CMakeLists.txt 2>/dev/null | head -n1)"
SELF_VER=""
SELF_UNREADABLE=0
if [ -z "$SELF_PKG" ]; then
    echo "note: no project() name in CMakeLists.txt -- floors are compared by major only" >&2
    SELF_UNREADABLE=1
elif [ -z "$FILE_MAJ" ]; then
    echo "note: no version in $VERSION_FILE -- floors are compared by major only" >&2
    SELF_UNREADABLE=1
else
    OWN_WANT=$WANT
    for pair in $MAP; do
        case "$pair" in "$SELF_PKG"=*) OWN_WANT=${pair#*=} ;; esac
    done
    if [ "$OWN_WANT" = "$FILE_MAJ" ]; then
        SELF_VER=$FILE_VER
    else
        echo "note: floors on $SELF_PKG are expected at major $OWN_WANT, not the $FILE_MAJ in" \
             "$VERSION_FILE -- they are compared by major only" >&2
    fi
fi
case "$MIN" in ''|*[!0-9]*|0) MIN_POS=0 ;; *) MIN_POS=1 ;; esac
if [ "$SELF_UNREADABLE" -eq 1 ] && [ "$MIN_POS" -eq 1 ]; then
    echo "::error::--min was given, so this repository is meant to be measurable, but the" >&2
    echo "         whole-floor comparison could not be set up -- floors only PARTLY measured" >&2
    exit 2
fi

HITS="$(git grep -nIE 'find_(package|dependency)\([ 	]*Libre[A-Za-z]+[ 	]+[0-9]' -- . \
        ':!thirdparty' ':!CHANGELOG.md' \
        ':!ci/scripts/check-version-floors.sh' ':!ci/scripts/check-version-floors.selftest.sh' 2>/dev/null)"
g=$?
if [ "$g" -ge 2 ]; then
    echo "::error::git grep exited $g -- version floors NOT measured (is this a git checkout?)" >&2
    exit 2
fi

printf '%s\n' "$HITS" | awk -v want="$WANT" -v map="$MAP" -v mode="$MODE" -v min="$MIN" -v vf="$VERSION_FILE" \
                              -v self_pkg="$SELF_PKG" -v self_ver="$SELF_VER" \
                              -v envwant="$ENV_WANT" '
function above(a, b,   x, y, i, n, m) {   # 1 when version a sorts above version b
  n = split(a, x, "."); m = split(b, y, ".")
  if (n > m) m = n
  for (i = 1; i <= m; i++) {
    if ((x[i] + 0) > (y[i] + 0)) return 1
    if ((x[i] + 0) < (y[i] + 0)) return 0
  }
  return 0
}
BEGIN {
  n = split(map, pairs, /[ \t]+/)
  for (i = 1; i <= n; i++) {
    if (pairs[i] == "") continue
    eq = index(pairs[i], "=")
    want_of[substr(pairs[i], 1, eq - 1)] = substr(pairs[i], eq + 1)
    keyed++
  }
  if (self_ver != "") { split(self_ver, sv, "."); self_maj = sv[1] + 0; self_next = self_maj + 1 }
}
$0 == "" { next }
{
  s = $0
  while (match(s, /find_(package|dependency)\([ \t]*Libre[A-Za-z]+[ \t]+[0-9][^ \t)]*/)) {
    tok = substr(s, RSTART, RLENGTH); s = substr(s, RSTART + RLENGTH)
    pkg = tok; sub(/^find_(package|dependency)\([ \t]*/, "", pkg); sub(/[ \t].*$/, "", pkg)
    ver = tok; sub(/^.*[ \t]/, "", ver)
    maj = ver; sub(/[^0-9].*$/, "", maj)
    low = ver; sub(/\.\.\..*$/, "", low)   # a range floors at its lower bound
    hi = ""; hi_excl = 0                   # ... and, when it is a range, ceilings at the other
    if (ver ~ /\.\.\./) {
      hi = ver; sub(/^.*\.\.\./, "", hi)
      if (substr(hi, 1, 1) == "<") { hi_excl = 1; hi = substr(hi, 2) }
    }
    hi_maj = hi; sub(/[^0-9].*$/, "", hi_maj)
    seen++
    xmaj = (pkg in want_of) ? want_of[pkg] : want
    src = ((pkg in want_of) || envwant + 0) ? "LIBRESCRS_FLOOR_MAJOR" : vf
    mine = (self_ver != "" && pkg == self_pkg)
    low_bad = (mine && above(low, self_ver))
    # Two independent ways for the top of a range to exclude what we ship: by
    # value (it sits at or below the installed version) and by major (it reaches
    # past the installed major line, which SameMajorVersion refuses whatever the
    # digits say).
    hi_val_bad = (mine && hi != "" && \
                  ((hi_excl && !above(hi, self_ver)) || (!hi_excl && above(self_ver, hi))))
    hi_maj_bad = (mine && hi != "" && \
                  ((hi_excl && above(hi, self_next "")) || (!hi_excl && (hi_maj + 0) != self_maj)))
    if (mode == "list") {
      mark = (maj != xmaj) ? "MAJOR-MISMATCH" : \
             ((low_bad || hi_val_bad || hi_maj_bad) ? "UNSATISFIABLE" : "")
      printf "  %-16s floor %-13s major %-3s expected %-3s %-14s %s\n", pkg, ver, maj, xmaj, mark, $0
    }
    else if (maj != xmaj) {
      printf "::error::%s\n", $0
      printf "          floor on %s is major %s; %s says major %s\n", pkg, maj, src, xmaj
      bad++
    }
    else if (low_bad) {
      printf "::error::%s\n", $0
      printf "          floor on %s starts at %s; this repository ships %s, so the package\n", pkg, low, self_ver
      printf "          it installs cannot satisfy it\n"
      bad++
    }
    else if (hi_val_bad) {
      printf "::error::%s\n", $0
      printf "          range on %s ends at %s%s, which excludes the %s this repository\n", pkg, (hi_excl ? "<" : ""), hi, self_ver
      printf "          ships, so the package it installs cannot satisfy it\n"
      bad++
    }
    else if (hi_maj_bad) {
      printf "::error::%s\n", $0
      printf "          range on %s ends at %s%s, outside the major %s line this repository\n", pkg, (hi_excl ? "<" : ""), hi, self_maj
      printf "          ships; an inclusive top has to stay inside that major and an exclusive\n"
      printf "          one may reach %s exactly, no further\n", self_next
      bad++
    }
  }
}
END {
  if (mode == "list") {
    printf "  %d floor(s) examined\n", seen+0
    if (self_ver != "")
      printf "  own package %s ships %s -- both ends of its floors are compared by value and\n", self_pkg, self_ver
      printf "  by major; every other package by major only\n"

    exit 0
  }
  if (seen+0 < min+0) {
    printf "::error::only %d first-party floor(s) found, --min %d -- the scan matched nothing it was meant to measure\n", seen+0, min+0
    exit 1
  }
  if (bad+0) { printf "%d floor(s) disagree with the expected version\n", bad; exit 1 }
  if (keyed+0) { printf "  -> %d first-party version floor(s), each naming its expected major (default %s)\n", seen+0, want; exit 0 }
  printf "  -> %d first-party version floor(s), all major %s\n", seen+0, want
  exit 0
}'

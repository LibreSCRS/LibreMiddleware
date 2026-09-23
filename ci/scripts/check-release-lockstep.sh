#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-release-lockstep.sh <version>
#
# The CHANGELOG and the VERSION file must agree on the version passed in.
#
# Two callers, one body. The cheap lint job passes the version this tree is
# heading for (the first line of VERSION), so the check runs on every push;
# the release job passes the tag's version, so it runs again on the tag. Until
# this existed the extraction awk lived in five copies across the components,
# and one of them had drifted: without escaping the dots, tag 5.0.0 also
# matched a [500.0] heading.
#
# Excluding pre-release tags is a property of the TAG, not of this check, so it
# stays in the workflow that knows what a tag is.
set -u

usage() {
    echo "usage: check-release-lockstep.sh [--section] <version>   (e.g. 5.0.0)" >&2
    echo "  default    assert the CHANGELOG section and the VERSION file agree" >&2
    echo "  --section  print that CHANGELOG section on stdout instead" >&2
    exit 2
}

MODE=assert
if [ "${1:-}" = "--section" ]; then
    MODE=section
    shift
fi
[ "$#" -eq 1 ] || usage
VER=${1#v}
[ -n "$VER" ] || usage

CHANGELOG=${CHANGELOG_FILE:-CHANGELOG.md}
VERSION_FILE=${VERSION_FILE:-VERSION}

FAIL=0

# Extract with the SAME awk the release-notes step uses, then require the
# section to hold a non-whitespace character. Testing only for the header let a
# header with nothing under it pass, and the release then shipped precisely the
# generic auto-notes the error text warns about. Matching with a second,
# near-miss pattern also made the two steps disagree: `^## .*(\[|[[:space:]])`
# spends the space in its own `## ` prefix, so a bracket-less `## 5.0.0` header
# was called missing here while the extractor read it correctly.
#
# A missing CHANGELOG is the no-section case, said out loud: an awk over an
# absent file would otherwise die before this branch could report anything.
extract() {  # extract <version>: that version's CHANGELOG section, or nothing
    [ -f "$CHANGELOG" ] || return 0
    awk -v ver="$1" \
        'BEGIN { gsub(/\./, "\\.", ver) }
         /^## / { if ($0 ~ ("(\\[|[[:space:]])" ver "(\\]|[[:space:]]|$)")) {f=1; next} else if (f) exit } f' \
        "$CHANGELOG"
}
SECTION="$(extract "$VER")"
# --section is the release job's notes extractor. It is the SAME awk above,
# reached through the same file, because five hand-copied extractors are what
# let one of them drift: without the dot escaping, tag 5.0.0 also matched a
# [500.0] heading. A section that exists but holds only whitespace is a miss —
# `gh release create --notes-file` accepts a blank file and publishes a release
# with no body at all — so the caller can branch on the exit code.
# A pre-release tag (5.0.0-rc1) falls back to the section of its base version
# when it has none of its own, so a rehearsal publishes exactly the notes the
# final tag will. Only here, and only when the exact version has no non-empty
# section: a repository that keeps a pre-release section still gets that one,
# and the agreement check below is untouched.
if [ "$MODE" = section ] && ! printf '%s' "$SECTION" | grep -q '[^[:space:]]' \
        && [ "${VER%%-*}" != "$VER" ]; then
    SECTION="$(extract "${VER%%-*}")"
fi
if [ "$MODE" = section ]; then
    printf '%s\n' "$SECTION"
    printf '%s' "$SECTION" | grep -q '[^[:space:]]'
    exit $?
fi

if ! printf '%s' "$SECTION" | grep -q '[^[:space:]]'; then
    echo "::error::CHANGELOG.md has no section for $VER, or the section is empty — the release would ship generic auto-notes. Rename the [Unreleased] header before tagging."
    FAIL=1
fi

FILE_VER="$(head -n1 "$VERSION_FILE" 2>/dev/null | tr -d '[:space:]')"
FILE_VER=${FILE_VER#v}
if [ "$FILE_VER" != "$VER" ]; then
    echo "::error::VERSION file holds '$FILE_VER' but the tag is '$VER' — no-git source drops would stamp the wrong version. Bump VERSION with the tag."
    FAIL=1
fi

[ "$FAIL" -eq 0 ] && echo "  -> changelog and VERSION agree on $VER"
exit "$FAIL"

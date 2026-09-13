#!/usr/bin/env bash
# Selftest for check-package-matrix.sh. Three cases: agreement, a single
# changed digest, and a missing matrix -- the last one because a check that
# reports success for having found nothing to compare is the vacuous kind.
#
# The subject reads two fixed paths relative to the current directory, so each
# case builds a throwaway .github/workflows/ and runs the subject inside it.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-package-matrix.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0

matrix() {  # matrix <third-digest>
    cat <<Y
jobs:
  package:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - slug: debian13
            image: debian@sha256:aaaa
          - slug: ubuntu2604
            image: ubuntu@sha256:bbbb
          - slug: fedora43
            image: fedora@sha256:$1
Y
}

run() {  # run <name> <expected-rc> <dir>
    local name=$1 want=$2 dir=$3
    ( cd "$dir" && bash "$subject" ) > "$work/out" 2>&1
    local got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-50s rc=%s  %s\n' "$name" "$got" "$(head -n1 "$work/out")"
    else
        printf '  FAIL  %-50s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_1 -- the two copies agree.
d=$work/case_1/.github/workflows; mkdir -p "$d"
matrix cccc > "$d/ci.yml"
matrix cccc > "$d/release.yml"
run "case_1 the two copies agree" 0 "$work/case_1"

# case_2 -- one digest bumped in one file only. This is the whole point: the
# release would build on an image no push was ever tested against.
d=$work/case_2/.github/workflows; mkdir -p "$d"
matrix cccc > "$d/ci.yml"
matrix dddd > "$d/release.yml"
run "case_2 one digest bumped in one file only" 1 "$work/case_2"

# case_3 -- release.yml has no matrix at all. Nothing to compare is not
# agreement.
d=$work/case_3/.github/workflows; mkdir -p "$d"
matrix cccc > "$d/ci.yml"
printf 'jobs:\n  release:\n    runs-on: ubuntu-latest\n' > "$d/release.yml"
run "case_3 no matrix to compare is not a pass" 2 "$work/case_3"

if [ "$fails" -eq 0 ]; then
    echo "check-package-matrix selftest: all cases passed"
    exit 0
fi
echo "check-package-matrix selftest: $fails case(s) failed"
exit 1

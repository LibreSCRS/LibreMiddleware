#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-package-matrix.sh
#
# The package matrix is written twice -- once in ci.yml, once in release.yml --
# because a job that calls a reusable workflow cannot carry timeout-minutes and
# ci/scripts/check-job-timeouts.sh requires one on every job. Two copies of a
# pinned digest drift, and a release built on a stale image is invisible: the
# packages are produced, the gate is green, and nothing says they were built
# against a different base than every push was tested against.
#
# This asserts the two copies are the same SET of slug/image pairs. Order does
# not matter; membership and the exact digest do.
#
# Threat model. This reads workflow TEXT at a fixed indentation, so it guards
# against the honest regression: someone bumps an image in one file and forgets
# the other, writing the matrix in the shape this repository writes it. It does
# not resist a matrix written to evade it, and these doors are open knowingly:
# a matrix at a different indentation, or expressed as anything other than a
# literal `- slug:`/`image:` pair -- an expression, an env indirection, a
# `include` assembled elsewhere -- is simply not seen, and if BOTH files stop
# being seen the exit is 2, not 0. Code review, not this gate, is what catches
# a matrix deliberately hidden from it.
#
# The scan is per FILE, not per job: every `- slug:`/`image:` pair at this
# indentation anywhere in ci.yml joins one set and every such pair in
# release.yml joins the other. Each file holds exactly one such matrix today.
# A second, unrelated matrix written in the same shape in only one of the two
# files would therefore be compared as though it belonged to this one and
# reported as drift -- a visible failure with a misleading name, never a silent
# pass.
#
# Exit: 0 the two copies agree - 1 they have drifted - 2 one of them could not
#       be read at all, which is not a pass.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

pairs() {  # pairs <file>
    awk '
        /^          - slug:[[:space:]]/ { s = $3; next }
        /^            image:[[:space:]]/ && s != "" { print s, $2; s = "" }
    ' "$1" | sort
}

a=$(pairs .github/workflows/ci.yml)
b=$(pairs .github/workflows/release.yml)

if [ -z "$a" ] || [ -z "$b" ]; then
    echo "no package matrix found in one of the two workflows -- that is not a pass" >&2
    exit 2
fi

if [ "$a" = "$b" ]; then
    printf 'package-matrix: %d image(s), ci.yml and release.yml agree\n' "$(printf '%s\n' "$a" | wc -l)"
    exit 0
fi

echo "::error::the package matrix in ci.yml and release.yml has drifted"
diff <(printf '%s\n' "$a") <(printf '%s\n' "$b") || true
exit 1

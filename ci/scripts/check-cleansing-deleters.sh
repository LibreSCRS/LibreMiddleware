#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# check-cleansing-deleters.sh — the BIGNUM deleter must cleanse, and must say why.
#
# PACE holds three secrets that exist ONLY as a BIGNUM: the ephemeral private
# keys skMap and skAgree, the x-coordinate of the ECDH shared secret K, and the
# decrypted nonce s. CleanseGuard reaches none of them -- it wipes std::vector,
# and the ephemeral private key has no vector copy at all. Plain BN_free hands
# the limb buffer back with the secret still in it.
#
# That was fixed once already, in 4.1.0, and lost again when a deduplication
# pass merged two deleters that differed only in the body: a cleansing one in
# pace.cpp and a plain one in the shared header. The merge matched on the name,
# kept the plain body, and deleted the comment explaining why the other
# existed. So this gate checks the call AND the reason, as two separate
# failures, because last time one of them going was what hid the other.
#
# Clauses 3 and 4 are the general form: no BIGNUM anywhere in tracked sources
# is released through a deleter that calls plain BN_free. They are split
# because a deleter has three shapes and a search for one of them sees neither
# of the others -- a struct with operator()(BIGNUM*), a function pointer
# (unique_ptr<BIGNUM, decltype(&BN_free)>), and a lambda. Both remaining shapes
# were live in this tree while clause 3 alone reported OK.
#
# Both clauses are scoped to deleters on purpose -- a bare BN_free on a public
# ECDSA r/s in an error path is not this bug, and a gate that flagged it would
# be argued away within a release.
#
# Usage:  ci/scripts/check-cleansing-deleters.sh
# Exit:   0 clean · 1 violation · 2 refusing to judge (never read as a pass)
set -uo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2

git rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || { echo "FATAL: not a git work tree — this gate reads git ls-files, nothing else" >&2; exit 2; }

HEADER="lib/LibreSCRS/include/LibreSCRS_internal/Crypto/OpenSslPtr.h"
EXCEPTIONS="ci/cleansing-deleter-exceptions.txt"
[[ -f "$HEADER" ]] || { echo "FATAL: $HEADER not found; nothing was measured" >&2; exit 2; }

fail=0

# --- 1. the canonical deleter cleanses ------------------------------------
decl="$(grep -n '^struct BnDeleter$' "$HEADER" | head -n1 | cut -d: -f1)"
[[ -n "$decl" ]] || { echo "FATAL: no 'struct BnDeleter' in $HEADER; nothing was measured" >&2; exit 2; }

body="$(awk '/^struct BnDeleter$/,/^};$/' "$HEADER")"
if ! printf '%s\n' "$body" | grep -q 'BN_clear_free'; then
    echo "ERROR: $HEADER:$decl BnDeleter does not call BN_clear_free." >&2
    echo "       PACE ephemeral private keys, the ECDH x-coordinate and the" >&2
    echo "       decrypted nonce are freed through it and nothing else wipes them." >&2
    fail=1
fi

# --- 2. the reason is written down where the call is ----------------------
# The reason is looked for in the 25 comment lines directly above the
# declaration: that is the whole doc comment with room to spare. A comment that
# outgrows the window fails closed here, and the fix is to widen this number,
# not to move the reason away from the call.
start=$(( decl > 25 ? decl - 25 : 1 ))
if ! sed -n "${start},$((decl - 1))p" "$HEADER" | grep -E '^[[:space:]]*//' | grep -q 'PACE'; then
    echo "ERROR: $HEADER:$decl the comment above BnDeleter does not mention PACE." >&2
    echo "       The call and its reason are deleted separately on purpose: a" >&2
    echo "       cleansing call with no recorded reason is what regressed before." >&2
    fail=1
fi

SCRATCH="$(mktemp -d /var/tmp/check-cleansing-deleters.XXXXXX)" || exit 2
trap 'rm -rf "$SCRATCH"' EXIT
git ls-files -z -- '*.c' '*.cc' '*.cpp' '*.cxx' '*.h' '*.hh' '*.hpp' '*.m' '*.mm' > "$SCRATCH/files.z" || exit 2
if [[ ! -s "$SCRATCH/files.z" ]]; then
    echo "FATAL: git ls-files listed no sources at all; nothing was measured" >&2
    exit 2
fi

# --- 3. no BIGNUM deleter written as a member calls plain BN_free ---------
# Six lines after the signature is the whole body of a deleter written in this
# repository's style; anything longer is not the shape this gate is about.
# The space before the star is tolerated because the formatter, not this gate,
# is what settles it: a security gate that only sees the shape another gate
# happens to enforce is one .clang-format edit away from measuring nothing.
# -H so a batch xargs hands grep a single file still carries the path.
hits="$(xargs -0 -r grep -H -n -A6 'operator()(BIGNUM[[:space:]]*\*' < "$SCRATCH/files.z" \
        | grep -E '(^|[^_[:alnum:]])BN_free[[:space:]]*\(' || true)"
if [[ -n "$hits" ]]; then
    echo "ERROR: a BIGNUM deleter calls plain BN_free. One policy in this tree:" >&2
    echo "       a BIGNUM released through a deleter is cleansed first." >&2
    printf '%s\n' "$hits" >&2
    fail=1
fi

# --- 4. nor one written as a function pointer or a lambda -----------------
# The two shapes clause 3 cannot see. Both were shipped here while it said OK:
# a certificate serial number released through unique_ptr<BIGNUM,
# decltype(&BN_free)>, and the control leg of the behavioural probe.
#
# The control leg is the one deliberate exception, and it is not written into
# this script: exceptions live in ci/cleansing-deleter-exceptions.txt, one
# path:line and its reason per line. The line is half the entry -- an amnesty
# granted to a file covers every deleter written there afterwards, including
# the ones nobody has justified. An excused entry whose file is untracked, or
# whose line no longer releases a BIGNUM this way, is itself a failure: an
# amnesty that outlives its site is how a gate quietly stops measuring.
raw="$( { xargs -0 -r grep -H -n -A2 -E 'unique_ptr[[:space:]]*<[[:space:]]*BIGNUM' < "$SCRATCH/files.z" \
            | grep -E '(decltype[[:space:]]*\([[:space:]]*&[[:space:]]*BN_free[[:space:]]*\)|&[[:space:]]*BN_free|,[[:space:]]*BN_free[[:space:]]*[)}])'
          xargs -0 -r grep -H -n -A6 -E '\[[^]]*\][[:space:]]*\([[:space:]]*BIGNUM[[:space:]]*\*' < "$SCRATCH/files.z" \
            | grep -E '(^|[^_[:alnum:]])BN_free[[:space:]]*\('
        } | sort -u)"

excused=()
if [[ -f "$EXCEPTIONS" ]]; then
    while IFS= read -r line; do
        [[ "$line" =~ ^[[:space:]]*(#.*)?$ ]] && continue
        excused+=("${line%%[[:space:]]*}")
    done < "$EXCEPTIONS"
fi

for entry in ${excused[@]+"${excused[@]}"}; do
    if [[ ! "$entry" =~ ^(.+):([0-9]+)$ ]]; then
        echo "ERROR: $EXCEPTIONS excuses '$entry', which names no line." >&2
        echo "       Write it as path:line. A bare path excuses every deleter in" >&2
        echo "       that file, the ones not written yet included." >&2
        fail=1
        continue
    fi
    path="${BASH_REMATCH[1]}"
    at="${BASH_REMATCH[2]}"
    if ! git ls-files --error-unmatch -- "$path" >/dev/null 2>&1; then
        echo "ERROR: $EXCEPTIONS excuses $entry, whose path is not a tracked file." >&2
        echo "       An exception nothing can match hides the next one that matters." >&2
        fail=1
        continue
    fi
    if ! printf '%s\n' "$raw" | awk -v m="$path:$at:" -v c="$path-$at-" \
        'index($0, m) == 1 || index($0, c) == 1 { found = 1 } END { exit !found }'; then
        echo "ERROR: $EXCEPTIONS excuses $entry, which no longer releases a BIGNUM" >&2
        echo "       through plain BN_free. Move the line number if the site moved," >&2
        echo "       drop the entry if the site is gone: a stale amnesty widens" >&2
        echo "       silently, and the next call site there inherits it." >&2
        fail=1
    fi
done

hits2="$raw"
for entry in ${excused[@]+"${excused[@]}"}; do
    [[ "$entry" =~ ^(.+):([0-9]+)$ ]] || continue
    hits2="$(printf '%s\n' "$hits2" \
        | awk -v m="${BASH_REMATCH[1]}:${BASH_REMATCH[2]}:" -v c="${BASH_REMATCH[1]}-${BASH_REMATCH[2]}-" \
              'index($0, m) == 1 || index($0, c) == 1 { next } { print }')"
done
if [[ -n "$hits2" ]]; then
    echo "ERROR: a BIGNUM is released through a plain BN_free deleter. One policy" >&2
    echo "       in this tree: a BIGNUM released through a deleter is cleansed" >&2
    echo "       first, whether the deleter is a struct, a function pointer or a" >&2
    echo "       lambda." >&2
    printf '%s\n' "$hits2" >&2
    fail=1
fi

[[ "$fail" -eq 0 ]] || exit 1
echo "check-cleansing-deleters: OK (BnDeleter cleanses, records why, and no deleter — struct, function pointer or lambda — releases a BIGNUM through plain BN_free)"

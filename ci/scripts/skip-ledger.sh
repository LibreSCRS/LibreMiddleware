#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# skip-ledger.sh — every test that did not run is accounted for, by leg.
#
# A suite that skips silently costs nothing to add and nothing to notice. This
# repository runs well over a hundred skipped cases on one leg; without a
# written account, one more is invisible and one that starts running again is
# equally invisible.
#
# Both directions fail:
#   - a skipped test with no line in the ledger, and
#   - a line in the ledger that matched nothing that was skipped.
# The second is not pedantry. A ledger entry that has rotted against the test
# it names ("pa.sod_signature" against a test since renamed "pa_sod_signature")
# reads as coverage while covering nothing.
#
# DISABLED_ tests are in the same book even though ctest never lists them as
# skipped: their source is a scan of the tracked sources. A budget that cannot
# see them is a budget with a hole.
#
# The ledger is per LEG, not per repository. One desktop repository here skips
# twelve cases on Linux and twenty-two on macOS; a per-repository total is
# satisfied on day one and the ten that only one platform skips stay invisible.
#
# Format — three columns: category, glob, expected count.
#
#   # <repo> — <leg>. Regenerate: ci/scripts/skip-ledger.sh --update <log> <leg>
#   CARD      AllBackends/SigningE2ETest.*      62
#   NETWORK   TrustStoreServiceTest.LiveFetch    1
#
# The category vocabulary is closed: CARD, NETWORK, SERVICE, PLATFORM, DESIGN,
# TAUTOLOGY, TOMBSTONE. Closed because this text is printed by every public CI
# run, and one earlier leak in this project was exactly a skip message. These
# are technical facts and carry no trace of internal tracking.
#
# Usage:
#   ci/scripts/skip-ledger.sh --check  <ctest.log> <leg>
#   ci/scripts/skip-ledger.sh --update <ctest.log> <leg>
#
# Exit codes:
#   0  every skip is accounted for and every entry still matches something
#   1  an unrecorded skip, a stale entry, or a count that moved
#   2  refusing to judge: no ledger, an unreadable log, an unknown category, or
#      an --update from an environment that is missing what ci/skip-ledger-env.txt
#      names. Recording a ledger from a run whose test token was never
#      provisioned writes tens of skips that do not exist on a provisioned
#      runner, and every one of them then reads as a stale entry there.
set -uo pipefail
export LC_ALL=C

VOCAB="CARD NETWORK SERVICE PLATFORM DESIGN TAUTOLOGY TOMBSTONE"

usage() {
    echo "FATAL: usage: skip-ledger.sh --check|--update <ctest.log> <leg>" >&2
    exit 2
}

[ $# -eq 3 ] || usage
case "$1" in --check|--update) ACTION="${1#--}" ;; *) usage ;; esac
LOG="$2"
LEG="$3"
case "$LEG" in ""|*/*) echo "FATAL: leg name '$LEG' is not a single path segment" >&2; exit 2 ;; esac

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO_ROOT" || exit 2
BOOK="ci/skipped-tests.${LEG}.txt"
ENVFILE="ci/skip-ledger-env.txt"

[ -f "$LOG" ] || { echo "FATAL: no ctest log at $LOG" >&2; exit 2; }

SCRATCH="$(mktemp -d /var/tmp/skip-ledger.XXXXXX)"
trap 'rm -rf "$SCRATCH"' EXIT

# --- what did not run ------------------------------------------------------
# ctest prints, after the summary:
#     The following tests did not run:
#             123 - Some.Test (Skipped)
awk '
    /^The following tests did not run:/ { on = 1; next }
    on && /^[ \t]*[0-9]+ - / {
        line = $0
        sub(/^[ \t]*[0-9]+ - /, "", line)
        sub(/ \([A-Za-z]+\)[ \t]*$/, "", line)
        print line
        next
    }
    on && !/^[ \t]*[0-9]+ - / { on = 0 }
' "$LOG" | sort -u > "$SCRATCH/skipped.txt"

# --- what is disabled at the source ----------------------------------------
# ctest never reports a DISABLED_ case as skipped, so it is read from the
# tracked sources instead of from the log.
git grep -hoE 'TEST[_A-Z]*\([ \t]*[A-Za-z0-9_]+[ \t]*,[ \t]*DISABLED_[A-Za-z0-9_]+' \
    -- '*.cpp' '*.cc' '*.mm' 2>/dev/null \
  | sed -E 's/^TEST[_A-Z]*\([ \t]*//; s/[ \t]*,[ \t]*/./' \
  | sort -u > "$SCRATCH/disabled.txt"

cat "$SCRATCH/skipped.txt" "$SCRATCH/disabled.txt" | sort -u > "$SCRATCH/accountable.txt"

n_skipped=$(wc -l < "$SCRATCH/skipped.txt")
n_disabled=$(wc -l < "$SCRATCH/disabled.txt")

if [ "$ACTION" = "update" ]; then
    if [ -f "$ENVFILE" ]; then
        missing=""
        while read -r v; do
            case "$v" in ''|\#*) continue ;; esac
            eval "val=\${$v:-}"
            [ -n "$val" ] || missing="$missing $v"
        done < "$ENVFILE"
        if [ -n "$missing" ]; then
            echo "FATAL: --update refused:$missing not set, and $ENVFILE says this leg needs them." >&2
            echo "       A ledger recorded without them books skips that do not exist on a" >&2
            echo "       provisioned runner, and every one of those reads as a stale entry there." >&2
            exit 2
        fi
    fi
    {
        echo "# $(basename "$REPO_ROOT") — leg '$LEG'. Regenerate: ci/scripts/skip-ledger.sh --update <ctest.log> $LEG"
        echo "# Columns: category, glob, expected count. Categories: $VOCAB"
        echo "# TODO rows are a draft: --check refuses an unknown category, on purpose."
        echo "# Counted here: $n_skipped skipped by ctest, $n_disabled DISABLED_ in the sources."
        sed -E 's/\.[^.]*$//' "$SCRATCH/accountable.txt" | sort | uniq -c | sort -k2 \
          | awk '{ printf "TODO      %-58s %d\n", $2 ".*", $1 }'
    } > "$BOOK"
    echo "$BOOK: drafted $(grep -cv '^#' "$BOOK") row(s) for $(wc -l < "$SCRATCH/accountable.txt") accountable test(s)"
    exit 0
fi

[ -f "$BOOK" ] || { echo "FATAL: no skip ledger at $BOOK" >&2; exit 2; }

rc=0
: > "$SCRATCH/matched.txt"
while read -r cat pat expected rest; do
    case "$cat" in ''|\#*) continue ;; esac
    ok=0
    for v in $VOCAB; do [ "$cat" = "$v" ] && ok=1; done
    if [ "$ok" = 0 ]; then
        echo "FATAL: unknown category '$cat' in $BOOK — the vocabulary is closed: $VOCAB" >&2
        exit 2
    fi
    case "$expected" in ''|*[!0-9]*) echo "FATAL: '$expected' is not a count in $BOOK" >&2; exit 2 ;; esac
    hits=0
    while read -r name; do
        # shellcheck disable=SC2053
        if [[ $name == $pat ]]; then
            hits=$((hits + 1))
            echo "$name" >> "$SCRATCH/matched.txt"
        fi
    done < "$SCRATCH/accountable.txt"
    if [ "$hits" = 0 ]; then
        echo "stale entry: $pat matched nothing that was skipped"
        rc=1
    elif [ "$hits" != "$expected" ]; then
        echo "count moved: $pat expected $expected, saw $hits"
        rc=1
    fi
done < "$BOOK"

sort -u "$SCRATCH/matched.txt" -o "$SCRATCH/matched.txt"
comm -23 "$SCRATCH/accountable.txt" "$SCRATCH/matched.txt" > "$SCRATCH/unrecorded.txt"
n_unrec=$(wc -l < "$SCRATCH/unrecorded.txt")
if [ "$n_unrec" != 0 ]; then
    sed -n '1,20p' "$SCRATCH/unrecorded.txt"
    echo "$n_unrec unrecorded skips"
    rc=1
fi

if [ "$rc" = 0 ]; then
    echo "$n_skipped skipped + $n_disabled disabled, all accounted for in $BOOK"
fi
exit $rc

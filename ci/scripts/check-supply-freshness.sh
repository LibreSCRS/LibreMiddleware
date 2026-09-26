#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-supply-freshness.sh [--json <out>] [--offline]
#
# Report when a bundled dependency has fallen behind its own release series.
#
# The bundled crypto entered this tree in February and was three security
# releases behind seven months later. Nothing said so: the version is in a
# directory name, the packaging tables copy it, and none of that knows what
# upstream has published since. This compares every pin in the tree against the
# newest release of the SAME series, which is where security patches land.
#
# Never against the newest release overall. Measured: the OpenSSL project's
# `releases/latest` is a 4.x tag while this tree pins 3.5.x, so a check built on
# it would report "two majors behind" for ever and be ignored within a week. A
# newer minor or major is reported and does not fail: moving one is a decision
# with a cost, and this check does not get to make it.
#
# What each verdict means:
#   current             newest in its series, and not older than the threshold
#   newer-other-series  a newer minor or major exists  -- REPORTED, not a failure
#   behind              a newer release in the pin's own series          -> fail
#   stale               the pin's upstream release is older than
#                       MAX_AGE_MONTHS (default 6)                       -> fail
#   eol                 the pinned series is past its published end of life -> fail
#   cannot-measure      no pin, an unparseable pin, an empty answer from
#                       upstream, or no network                -> exit 2, never 0
#   elsewhere           the pin is carried in another repository, or is a plain
#                       file with no upstream release to compare against. Named
#                       in the report and counted, but NOT in the exit code: it
#                       is not a finding about this tree, and folding it in left
#                       no state of this repository able to exit 0.
#   allowed             a `behind`-free finding covered by a dated, owned and
#                       reasoned entry in ci/supply-freshness-allowances.txt.
#                       An entry whose owner is PENDING is NOT permission: the
#                       finding stands and the check is red.
#
# The date a pin is judged by is the UPSTREAM publication date of the release or
# commit it names, read from the API. Not the file's mtime, which checkout
# rewrites; not the `built on:` string inside a vendored archive, which says
# when somebody compiled it; not the date of our own commit, which a squash
# moves. Each of those measures something else.
#
# rc=2 is never a pass. A check that cannot reach upstream, or cannot turn a pin
# into a version, has not found the tree to be current -- it has found out
# nothing, and saying so is the whole point of a third exit code.
#
# Exit: 0 every pin current or reported - 1 a pin is behind, stale or past EOL
#       2 cannot measure
#
# Environment:
#   GH_TOKEN                 required unless --offline. Unauthenticated the API
#                            allows 60 requests an hour against 5000, so this
#                            would drop into rc=2 on most runs -- and rc=2 is
#                            not a failure, so nobody would notice it had
#                            stopped measuring.
#   MAX_AGE_MONTHS           default 6
#   SUPPLY_FRESHNESS_REPO    tree to read pins from (default: this repository)
#   SUPPLY_FRESHNESS_FIXTURE canned upstream answers instead of the API.
#                            For the selftest only; CI never sets it.
set -uo pipefail
export LC_ALL=C

repo_default="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO="${SUPPLY_FRESHNESS_REPO:-$repo_default}"
FIXTURE="${SUPPLY_FRESHNESS_FIXTURE:-}"
ALLOWANCES="${SUPPLY_FRESHNESS_ALLOWANCES:-$REPO/ci/supply-freshness-allowances.txt}"
MAX_AGE_MONTHS="${MAX_AGE_MONTHS:-6}"
OFFLINE=0
JSON_OUT=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --offline) OFFLINE=1; shift ;;
        --json) JSON_OUT="${2:-}"; shift 2 || { echo "FATAL: --json needs a path" >&2; exit 2; } ;;
        -h|--help) sed -n '2,60p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) echo "FATAL: unknown argument '$1'" >&2; exit 2 ;;
    esac
done

[ -d "$REPO" ] || { echo "FATAL: '$REPO' is not a directory -- cannot measure" >&2; exit 2; }

now_epoch="$(date -u +%s)"
max_age_days=$(( MAX_AGE_MONTHS * 30 ))

fails=0
unknowns=0
rows=()

# Every component this check can judge or list. An allowance naming anything
# else is a stale entry, not a silent no-op.
KNOWN_COMPONENTS="openssl
openssl-eol
curl
miniz
nlohmann
opensc
qcbor
jasper
oid-database
liberation-sans"

# --- upstream, through one seam -------------------------------------------
#
# refs <component> <repo> <tag-prefix>
#   every version in the pin's series, one per line, prereleases dropped.
refs() {
    local comp="$1" ghrepo="$2" prefix="$3"
    if [ -n "$FIXTURE" ]; then
        cat "$FIXTURE/$comp.refs" 2>/dev/null
        return 0
    fi
    gh api "repos/$ghrepo/git/matching-refs/tags/$prefix" --jq '.[].ref' 2>/dev/null \
        | sed "s#^refs/tags/##" | normalise_version
}

# normalise_version: strip whatever a project puts in front of the digits and
# turn its separator into a dot. curl tags releases `curl-8_22_0`, OpenSSL
# `openssl-3.5.8`, nlohmann `v3.11.3` and miniz `3.1.2`; without this the
# underscore form fails the numeric filter and the whole series listing comes
# back empty, which reads as "upstream renamed its tags" rather than as a bug
# here. The curl case is exactly that, and it is why this is a function.
normalise_version() {
    sed -e 's#^[^0-9]*##' -e 's#_#.#g'
}

# published <component> <repo> <tag-or-sha> <kind>
published() {
    local comp="$1" ghrepo="$2" ref="$3" kind="$4"
    if [ -n "$FIXTURE" ]; then
        cat "$FIXTURE/$comp.published" 2>/dev/null
        return 0
    fi
    if [ "$kind" = sha ]; then
        gh api "repos/$ghrepo/commits/$ref" --jq .commit.committer.date 2>/dev/null
    else
        gh api "repos/$ghrepo/releases/tags/$ref" --jq .published_at 2>/dev/null
    fi
}

# newest_overall <component> <repo>
newest_overall() {
    local comp="$1" ghrepo="$2"
    if [ -n "$FIXTURE" ]; then
        cat "$FIXTURE/$comp.newest-overall" 2>/dev/null
        return 0
    fi
    gh api "repos/$ghrepo/releases/latest" --jq .tag_name 2>/dev/null
}

# --- helpers ---------------------------------------------------------------

# Numeric, component-wise. A lexical maximum calls 3.5.9 newer than 3.5.10, and
# that bug arrives with 3.5.10 rather than being visible today.
newest_version() {
    grep -E '^[0-9]+(\.[0-9]+)*$' | sort -t. -k1,1n -k2,2n -k3,3n -k4,4n | tail -1
}

age_days() {
    local iso="$1" then
    then="$(date -u -d "$iso" +%s 2>/dev/null)" || return 1
    [ -n "$then" ] || return 1
    echo $(( (now_epoch - then) / 86400 ))
}

json_escape() { printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

add_row() { # add_row <component> <pin> <verdict> <detail>
    rows+=("$(printf '{"component":"%s","pin":"%s","verdict":"%s","detail":"%s"}' \
        "$(json_escape "$1")" "$(json_escape "$2")" "$(json_escape "$3")" "$(json_escape "$4")")")
}

note()    { printf 'note: %s\n' "$*"; }
report()  { printf 'REPORT: %s\n' "$*"; }
failing() { printf 'FAIL: %s\n' "$*" >&2; fails=$((fails + 1)); }
cannot()  { printf 'CANNOT MEASURE: %s\n' "$*" >&2; unknowns=$((unknowns + 1)); }

# An allowance covers a `stale` or `newer-other-series` finding only. A newer
# release in the pin's own series is where security patches land, and nothing in
# this file can silence one -- otherwise the cheapest way to make this check
# green is the thing it exists to prevent.
#
# Every entry also names WHO decided. Not keeping a pin current is a decision
# about what ships, and it is not this check's to make or an implementer's to
# assume: `owner:PENDING` means nobody has taken it yet, and the check treats
# that as a finding rather than as permission. An entry in that state makes the
# check red on purpose, which is the honest reading of "a pin is old and nobody
# has said that is acceptable".
allowance_for() {
    local comp="$1"
    [ -f "$ALLOWANCES" ] || return 1
    local line c until owner reason
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue;; esac
        c="${line%%[[:space:]]*}"
        [ "$c" = "$comp" ] || continue
        line="${line#"$c"}"; line="${line#"${line%%[![:space:]]*}"}"
        until="${line%%[[:space:]]*}"
        line="${line#"$until"}"; line="${line#"${line%%[![:space:]]*}"}"
        owner="${line%%[[:space:]]*}"
        reason="${line#"$owner"}"; reason="${reason#"${reason%%[![:space:]]*}"}"
        # Shape, date and owner were all judged by validate_allowances, which
        # runs whatever any pin's verdict turns out to be. This only decides
        # whether the entry APPLIES, and an unowned one never does.
        case "$owner" in
            owner:?*) ;;
            *) return 1 ;;
        esac
        if [ "$owner" = "owner:PENDING" ]; then
            # Said out loud. Returning quietly left the reader of a red run with
            # only "this pin is old" and no way to learn that a line in the
            # exceptions file is waiting for THEIR signature.
            printf 'NOTE: %s: an exception for it exists but its owner is PENDING, so it grants nothing; record a decision in %s or bump the pin\n' \
                "$comp" "$(basename "$ALLOWANCES")" >&2
            return 1
        fi
        [ -n "$reason" ] || return 1
        local u
        u="$(date -u -d "$until" +%s 2>/dev/null)" || return 1
        [ "$u" -lt "$now_epoch" ] && return 1
        printf '%s (decided by %s, until %s)' "$reason" "${owner#owner:}" "$until"
        return 0
    done < "$ALLOWANCES"
    return 1
}

# Validate the whole allowances file, once, before any component is judged.
#
# Read only on demand it would be invisible: an entry is consulted only when the
# pin it names is already a finding, so a malformed, expired or orphaned entry for
# a component that happens to be current is never looked at. A stale entry fails
# for exactly this reason -- amnesty that cannot go stale is amnesty nobody
# rereads.
validate_allowances() {
    [ -f "$ALLOWANCES" ] || return 0
    local line c until owner reason u
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in ''|'#'*) continue;; esac
        c="${line%%[[:space:]]*}"
        line="${line#"$c"}"; line="${line#"${line%%[![:space:]]*}"}"
        until="${line%%[[:space:]]*}"
        line="${line#"$until"}"; line="${line#"${line%%[![:space:]]*}"}"
        owner="${line%%[[:space:]]*}"
        reason="${line#"$owner"}"; reason="${reason#"${reason%%[![:space:]]*}"}"

        if ! printf '%s\n' "$KNOWN_COMPONENTS" | grep -qxF "$c"; then
            failing "$(basename "$ALLOWANCES"): '$c' is not a component this check knows about (stale entry)"
            continue
        fi
        case "$owner" in
            owner:?*) ;;
            *) failing "$(basename "$ALLOWANCES"): the entry for $c names no owner (expected owner:<who> after the date)"
               continue ;;
        esac
        [ -n "$reason" ] || failing "$(basename "$ALLOWANCES"): the entry for $c carries no reason"
        if ! u="$(date -u -d "$until" +%s 2>/dev/null)" || [ -z "$u" ]; then
            failing "$(basename "$ALLOWANCES"): '$until' in the entry for $c is not a date"
        elif [ "$u" -lt "$now_epoch" ]; then
            failing "$c: its exception expired on $until"
        fi
    done < "$ALLOWANCES"
}

# judge <component> <pin-version> <gh-repo> <series-prefix> <pinned-tag> <eol|->
judge() {
    local comp="$1" pin="$2" ghrepo="$3" prefix="$4" tag="$5" eol="$6"

    local series
    series="$(refs "$comp" "$ghrepo" "$prefix" | newest_version)"
    if [ -z "$series" ]; then
        cannot "$comp: the series query returned nothing -- upstream may have renamed its tags, and silence is not currency"
        add_row "$comp" "$pin" cannot-measure "empty series listing for prefix $prefix"
        return
    fi

    local when age
    when="$(published "$comp" "$ghrepo" "$tag" release)"
    if [ -z "$when" ] || ! age="$(age_days "$when")"; then
        cannot "$comp: upstream did not say when $tag was published"
        add_row "$comp" "$pin" cannot-measure "no publication date for $tag"
        return
    fi

    if [ "$eol" != - ]; then
        local eol_epoch
        eol_epoch="$(date -u -d "$eol" +%s 2>/dev/null)"
        if [ -n "$eol_epoch" ] && [ "$eol_epoch" -lt "$now_epoch" ]; then
            failing "$comp: the $prefix series reached end of life on $eol"
            add_row "$comp" "$pin" eol "series end of life $eol"
            return
        fi
    fi

    if [ "$series" != "$pin" ]; then
        failing "$comp: pinned $pin is behind $series in the same series -- security releases land here"
        add_row "$comp" "$pin" behind "newest in series $series"
        return
    fi

    local overall detail=""
    overall="$(newest_overall "$comp" "$ghrepo" | normalise_version)"
    if [ -n "$overall" ] && [ "$overall" != "$pin" ]; then
        detail="newest overall $overall"
    fi

    if [ "$age" -gt "$max_age_days" ]; then
        local allowed
        if allowed="$(allowance_for "$comp")"; then
            report "$comp: pinned $pin, published $when, ${age} days old -- allowed: $allowed"
            add_row "$comp" "$pin" allowed "${age} days old, $allowed"
        else
            failing "$comp: pinned $pin is older than ${MAX_AGE_MONTHS} months (published $when, ${age} days ago)"
            add_row "$comp" "$pin" stale "${age} days old${detail:+, $detail}"
        fi
        return
    fi

    if [ -n "$detail" ]; then
        report "$comp: pinned $pin is newest in its series; $detail is a decision, not a patch"
        add_row "$comp" "$pin" newer-other-series "$detail"
    else
        note "$comp: $pin is current (published $when, ${age} days ago)"
        add_row "$comp" "$pin" current "${age} days old"
    fi
}

# judge_sha <component> <sha> <gh-repo>
# A commit pin has no series, so age is the only signal there is.
judge_sha() {
    local comp="$1" sha="$2" ghrepo="$3"
    local when age
    when="$(published "$comp" "$ghrepo" "$sha" sha)"
    if [ -z "$when" ] || ! age="$(age_days "$when")"; then
        cannot "$comp: upstream did not say when ${sha:0:9} was committed"
        add_row "$comp" "${sha:0:9}" cannot-measure "no commit date"
        return
    fi
    if [ "$age" -gt "$max_age_days" ]; then
        local allowed
        if allowed="$(allowance_for "$comp")"; then
            report "$comp: ${sha:0:9} is ${age} days old -- allowed: $allowed"
            add_row "$comp" "${sha:0:9}" allowed "${age} days old, $allowed"
        else
            failing "$comp: the pinned commit ${sha:0:9} is older than ${MAX_AGE_MONTHS} months (committed $when)"
            add_row "$comp" "${sha:0:9}" stale "${age} days old"
        fi
        return
    fi
    note "$comp: ${sha:0:9} is ${age} days old (committed $when)"
    add_row "$comp" "${sha:0:9}" current "${age} days old"
}

# --- no network, no verdict ------------------------------------------------
if [ "$OFFLINE" = 1 ]; then
    cannot "--offline: nothing was compared against upstream"
    add_row all - cannot-measure "--offline"
elif [ -z "$FIXTURE" ]; then
    if ! command -v gh >/dev/null 2>&1; then
        cannot "gh is not on PATH"
        add_row all - cannot-measure "no gh"
    elif [ -z "${GH_TOKEN:-}" ] && [ -z "${GITHUB_TOKEN:-}" ]; then
        cannot "no GH_TOKEN: unauthenticated the API allows sixty requests an hour, and a check that quietly stops measuring is worse than one that fails"
        add_row all - cannot-measure "no token"
    elif ! gh api rate_limit --jq .resources.core.remaining >/dev/null 2>&1; then
        cannot "the API is not reachable"
        add_row all - cannot-measure "API unreachable"
    fi
fi

validate_allowances

# --- the pins in this tree, each read rather than typed --------------------
if [ "$unknowns" = 0 ]; then
    # OpenSSL: the directory name is the version, which is also what
    # thirdparty/CMakeLists.txt builds OPENSSL_ROOT out of.
    # Counted, not first-of-a-glob: in the middle of a version move a tree holds
    # two of these directories, and taking the lexicographically first one means
    # certifying the OLD tree as fresh -- exactly the state this branch is in.
    # make-sbom.sh closed the same branch; a fix that reaches one surface and not
    # its sibling is half a fix.
    ossl_dir=""
    ossl_count=0
    for d in "$REPO"/thirdparty/openssl-*; do
        [ -d "$d" ] || continue
        ossl_count=$((ossl_count + 1))
        ossl_dir="$d"
    done
    if [ "$ossl_count" -gt 1 ]; then
        cannot "openssl: $ossl_count thirdparty/openssl-* directories -- which one is the pin is not this check's guess to make"
        add_row openssl - cannot-measure "$ossl_count pin directories"
        ossl_dir=""
    fi
    if [ -z "$ossl_dir" ]; then
        [ "$ossl_count" = 0 ] && {
            cannot "openssl: no thirdparty/openssl-* directory in $REPO"
            add_row openssl - cannot-measure "no pin directory"
        }
    else
        ossl_ver="$(basename "$ossl_dir" | sed 's/^openssl-//')"
        if ! printf '%s' "$ossl_ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
            cannot "openssl: cannot read a version out of $(basename "$ossl_dir")"
            add_row openssl "$ossl_ver" cannot-measure "unparseable pin"
        else
            ossl_series="${ossl_ver%.*}"
            # End-of-life dates are not in the API, so they are written down
            # with where they came from -- and a series with no recorded date is
            # "cannot measure", never a silent pass. A bare `-` here meant the
            # next OpenSSL minor would turn the only end-of-life check in this
            # file into a no-op without saying anything.
            case "$ossl_series" in
                3.5) ossl_eol=2030-04-08 ;;  # openssl-library.org release strategy, LTS
                *)   ossl_eol=-
                     cannot "openssl: no recorded end-of-life date for the $ossl_series series -- add one from the project's release strategy page before trusting this check on it"
                     add_row openssl-eol "$ossl_series" cannot-measure "no recorded end-of-life date" ;;
            esac
            judge openssl "$ossl_ver" openssl/openssl "openssl-$ossl_series." \
                  "openssl-$ossl_ver" "$ossl_eol"
        fi
    fi

    # curl: the submodule's own header, the same place the bill of materials
    # reads it from.
    curlver="$REPO/thirdparty/curl-source/include/curl/curlver.h"
    if [ ! -f "$curlver" ]; then
        cannot "curl: $curlver is missing -- an unpopulated submodule measures nothing"
        add_row curl - cannot-measure "no curlver.h"
    else
        c_maj="$(awk '/^#define LIBCURL_VERSION_MAJOR /{print $3; exit}' "$curlver")"
        c_min="$(awk '/^#define LIBCURL_VERSION_MINOR /{print $3; exit}' "$curlver")"
        c_pat="$(awk '/^#define LIBCURL_VERSION_PATCH /{print $3; exit}' "$curlver")"
        if [ -z "$c_maj" ] || [ -z "$c_min" ] || [ -z "$c_pat" ]; then
            cannot "curl: curlver.h does not carry the three version macros"
            add_row curl - cannot-measure "unparseable curlver.h"
        else
            # curl keeps one line, so its series is the minor: a patch release
            # is 8.22.x and 8.23.0 is a decision.
            judge curl "$c_maj.$c_min.$c_pat" curl/curl "curl-${c_maj}_${c_min}_" \
                  "curl-${c_maj}_${c_min}_${c_pat}" -
        fi
    fi

    # miniz: the release is in a pin file, because MZ_VERSION is the zlib
    # version being emulated (2.1.0 says "10.1.0", 3.1.2 says "11.3.2") and
    # there is no formula between the two. Guessing would compare 11.3.2
    # against a 3.x tag list.
    miniz_pin="$REPO/thirdparty/miniz/VERSION.txt"
    if [ ! -f "$miniz_pin" ]; then
        cannot "miniz: no thirdparty/miniz/VERSION.txt -- MZ_VERSION is the emulated zlib version and cannot stand in for it"
        add_row miniz - cannot-measure "no pin file"
    else
        miniz_ver="$(tr -d '[:space:]' < "$miniz_pin")"
        if ! printf '%s' "$miniz_ver" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$'; then
            cannot "miniz: cannot read a version out of thirdparty/miniz/VERSION.txt ('$miniz_ver')"
            add_row miniz "$miniz_ver" cannot-measure "unparseable pin"
        else
            judge miniz "$miniz_ver" richgel999/miniz "${miniz_ver%.*}." "$miniz_ver" -
        fi
    fi

    # nlohmann/json: its own version macros.
    nj="$REPO/thirdparty/nlohmann/json.hpp"
    if [ ! -f "$nj" ]; then
        cannot "nlohmann: $nj is missing"
        add_row nlohmann - cannot-measure "no json.hpp"
    else
        n_maj="$(awk '/^#define NLOHMANN_JSON_VERSION_MAJOR /{print $3; exit}' "$nj")"
        n_min="$(awk '/^#define NLOHMANN_JSON_VERSION_MINOR /{print $3; exit}' "$nj")"
        n_pat="$(awk '/^#define NLOHMANN_JSON_VERSION_PATCH /{print $3; exit}' "$nj")"
        if [ -z "$n_maj" ] || [ -z "$n_min" ] || [ -z "$n_pat" ]; then
            cannot "nlohmann: json.hpp does not carry the three version macros"
            add_row nlohmann - cannot-measure "unparseable json.hpp"
        else
            judge nlohmann "$n_maj.$n_min.$n_pat" nlohmann/json "v$n_maj.$n_min." \
                  "v$n_maj.$n_min.$n_pat" -
        fi
    fi

    # OpenSC: a commit pin, so age is the only signal. The submodule is read
    # from git when it is checked out, and from the recorded SHA otherwise --
    # a source tarball has the tree but not the gitlink.
    opensc_sha=""
    if [ -e "$REPO/thirdparty/opensc-source/.git" ]; then
        opensc_sha="$(git -C "$REPO/thirdparty/opensc-source" rev-parse HEAD 2>/dev/null)"
    fi
    if [ -z "$opensc_sha" ] && [ -f "$REPO/thirdparty/opensc-source/.pinned-sha" ]; then
        opensc_sha="$(tr -d '[:space:]' < "$REPO/thirdparty/opensc-source/.pinned-sha")"
    fi
    if [ -z "$opensc_sha" ] && [ -f "$REPO/packaging/arch/PKGBUILD" ]; then
        opensc_sha="$(grep -oE 'OpenSC/archive/[0-9a-f]{40}' "$REPO/packaging/arch/PKGBUILD" \
                      | head -1 | grep -oE '[0-9a-f]{40}')"
    fi
    if [ -z "$opensc_sha" ]; then
        cannot "opensc: no commit pin found in the submodule or the packaging recipe"
        add_row opensc - cannot-measure "no commit pin"
    else
        judge_sha opensc "$opensc_sha" OpenSC/OpenSC
    fi
fi

# --- pins this repository does not hold -----------------------------------
#
# Listed rather than measured, so that "not in the report" never means "fine".
# QCBOR is pinned in the agent repository (cmake/FetchQCBOR.cmake) and the
# JPEG 2000 pins live in the desktop client; this check runs here and does not
# clone either, so a twin belongs beside them. Neither contributes to the exit
# code, because an unmeasured component is not a finding about this tree.
# Reported with a verdict of their own, and counted separately from the exit
# code. A pin carried in another repository is not a finding about THIS tree and
# not a clean bill either -- but folding it into "cannot measure" made no state
# of this repository able to exit 0, so the weekly run was permanently red for
# something unfixable here. That is the thing the header of the workflow argues
# against: a red build nobody can act on is a red build people learn to ignore.
# The count is surfaced instead, so "how many twins are still missing" is a
# number somebody can read rather than a colour.
elsewhere=0
note_elsewhere() { printf 'ELSEWHERE: %s\n' "$*"; elsewhere=$((elsewhere + 1)); }

note_elsewhere "qcbor: pinned in the agent repository (cmake/FetchQCBOR.cmake) -- needs a twin check there"
add_row qcbor - elsewhere "pinned in the agent repository"
note_elsewhere "jasper and qtimageformats: pinned in the desktop client repository -- needs a twin check there"
add_row jasper - elsewhere "pinned in the desktop client repository"

# Two vendored things with no upstream release to compare against, which is a
# different answer from "current" and from "elsewhere".
#
# The OID database is a file lifted out of one OpenSSL version while the library
# beside it is another: thirdparty/oid-database/README.md names the tag it came
# from. Comparing it to the pinned library version is the comparison that matters
# and this check has no way to make it -- objects.txt is not a release.
oid_readme="$REPO/thirdparty/oid-database/README.md"
if [ -f "$oid_readme" ]; then
    oid_from="$(grep -oE 'openssl-[0-9]+\.[0-9]+\.[0-9]+' "$oid_readme" | head -1 | sed 's/^openssl-//')"
    if [ -n "$oid_from" ]; then
        note_elsewhere "oid-database: lifted from objects.txt at openssl-$oid_from while the bundled library is ${ossl_ver:-unknown} -- two OpenSSL versions in one tree, and a plain file has no release to compare against"
        add_row oid-database "openssl-$oid_from" elsewhere "no upstream release for a single file; library is ${ossl_ver:-unknown}"
    fi
fi
if [ -d "$REPO/thirdparty/liberation-sans" ]; then
    note_elsewhere "liberation-sans: vendored as font files with no version recorded anywhere and no upstream release feed this check can read"
    add_row liberation-sans - elsewhere "no recorded version, no release feed"
fi

# --- output ---------------------------------------------------------------
if [ -n "$JSON_OUT" ]; then
    {
        printf '{\n  "generated": "%s",\n  "max_age_months": %s,\n  "components": [\n' \
            "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$MAX_AGE_MONTHS"
        first=1
        for r in "${rows[@]}"; do
            [ $first -eq 1 ] || printf ',\n'
            first=0
            printf '    %s' "$r"
        done
        printf '\n  ]\n}\n'
    } > "$JSON_OUT"
    command -v python3 >/dev/null 2>&1 && python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$JSON_OUT" \
        || { [ -s "$JSON_OUT" ] || { echo "FATAL: wrote no report to $JSON_OUT" >&2; exit 2; }; }
fi

[ "$elsewhere" -gt 0 ] && printf 'check-supply-freshness: %d pin(s) are carried elsewhere and need a twin check there\n' "$elsewhere"
if [ "$fails" -gt 0 ]; then
    printf 'check-supply-freshness: %d pin(s) need attention\n' "$fails" >&2
    exit 1
fi
if [ "$unknowns" -gt 0 ]; then
    printf 'check-supply-freshness: could not measure %d component(s) -- this is not a pass\n' "$unknowns" >&2
    exit 2
fi
printf 'check-supply-freshness: every pin measured here is current\n'
exit 0

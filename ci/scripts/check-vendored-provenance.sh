#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-vendored-provenance.sh -- the archives say how they were built; the
# written record has to agree with them.
#
# Some of what this repository ships is a committed binary, not a source tree:
# thirdparty/openssl-*/{linux,macosx}/lib/lib{crypto,ssl}.a are four archives
# produced somewhere else, by somebody, at some time. A diff of a version bump
# shows megabytes of opaque bytes and nothing about where they came from.
#
# Property, not proxy: OpenSSL compiles its own build configuration into
# libcrypto (crypto/cversion.c), so each archive carries its version, its
# target, the compiler line it was built with and the date it was built. This
# check reads those back out with strings(1) and compares them against
# PROVENANCE.txt. The obvious alternative -- record a sha256 of each archive
# and compare it -- is a tautology: the same hand writes the archive and its
# hash, so it agrees by construction after every bump and only ever fails on
# tampering, which is not the risk here. What IS the risk is a bump that
# updates half the archives, or updates them and forgets the record. Both of
# those go red here without anyone touching anything.
#
# The version is compared twice: against the record, and against the directory
# name (the directory name is the version -- thirdparty/CMakeLists.txt builds
# OPENSSL_ROOT out of it). The output always says which of the two failed,
# because "version mismatch" with two possible sides is not a diagnosis.
#
# macOS must carry both slices. That is asserted against the archive, not only
# against the record: a `lipo -thin` archive with the record trimmed to match
# would otherwise pass, and the platform that loses a slice is the one whose
# users silently keep whatever the old slice had.
#
# The configure: field used to be recorded and never compared, which made the
# check loud about a forgotten record and silent about a wrong build: deleting
# `no-asm` from the macOS line, replacing the line with nonsense, or removing it
# altogether all passed. The line itself is not in any archive -- but its
# CONSEQUENCE is committed, in include/openssl/configuration.h, so each
# `no-<feature>` token is compared against the OPENSSL_NO_<FEATURE> macro it must
# produce, in both directions. A build that quietly turned assembly back on is
# what the README says no test can see; this is that test.
#
# Only tokens in the map below are compared. Some configure options emit no macro
# at all (`no-shared`), so requiring a macro for every token would fail on a
# correct record; the map is what is checkable, and the rest stays recorded.
#
# Note on parsing: in the universal macOS archive the arm64 slice's compiler
# line is preceded by a Mach-O string-table length byte, so it does not begin
# its line. Every pattern here is unanchored for that reason; anchoring on '^'
# drops one slice of two and reports success.
#
# Exit: 0 record and archives agree - 1 they do not - 2 cannot measure
#       (rc=2 is never a pass: no record means no judgement, not a good one).
#
# PROV_ROOT overrides the directory scanned (default: thirdparty/), so the
# selftest and a perturbation can run against a copy.
set -uo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
ROOT="${PROV_ROOT:-$repo/thirdparty}"

[ -d "$ROOT" ] || { echo "FATAL: $ROOT is not a directory -- cannot measure" >&2; exit 2; }
command -v strings >/dev/null 2>&1 \
    || { echo "FATAL: strings(1) is not on PATH -- cannot measure" >&2; exit 2; }

TMP="$(mktemp -d "${TMPDIR:-/var/tmp}/prov-check.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

rc=0
cannot=0
fail() { echo "FAIL: $*" >&2; rc=1; }

# Every property this check compares, pulled out of one archive.
# archive_props <file> <kind>   kind in: version platform compiler built
archive_props() {
    case "$2" in
        version)  strings -n 8 "$1" 2>/dev/null | grep -oE 'OpenSSL [0-9]+\.[0-9]+\.[0-9]+' \
                      | sed 's/^OpenSSL //' | sort -u ;;
        platform) strings -n 8 "$1" 2>/dev/null | grep -oE 'platform: [A-Za-z0-9_.+-]+' \
                      | sed 's/^platform: //' | sort -u ;;
        compiler) strings -n 8 "$1" 2>/dev/null | grep -oE 'compiler: .*' \
                      | sed 's/^compiler: //' | sort -u ;;
        built)    strings -n 8 "$1" 2>/dev/null | grep -oE 'built on: .*' \
                      | sed 's/^built on: //' | sort -u ;;
    esac
}

# A record is judged where it lies: thirdparty/<component>-<version>/PROVENANCE.txt
# normally, or directly under the root when a copy of one component is scanned.
# A read loop rather than mapfile, which bash 3.2 (macOS /bin/bash) lacks.
records=()
while IFS= read -r record; do
    records+=("$record")
done < <(find "$ROOT" -maxdepth 2 -name PROVENANCE.txt -type f 2>/dev/null | sort)
if [ "${#records[@]}" -eq 0 ]; then
    echo "FATAL: no PROVENANCE.txt under $ROOT -- nothing to judge against" >&2
    exit 2
fi

for record in "${records[@]}"; do
    comp="$(dirname "$record")"
    rel="${comp#"$ROOT"/}"; [ "$rel" = "$comp" ] && rel="$(basename "$comp")"

    rm -f "$TMP"/sec.* "$TMP"/sections
    : > "$TMP/sections"
    rec_version=""
    section=""
    while IFS= read -r line || [ -n "$line" ]; do
        line="${line%$'\r'}"
        case "$line" in ''|'#'*) continue;; esac
        case "$line" in
            '['*']')
                section="${line#[}"; section="${section%]}"
                printf '%s\n' "$section" >> "$TMP/sections"
                : > "$TMP/sec.$section.platform"
                : > "$TMP/sec.$section.compiler"
                : > "$TMP/sec.$section.built"
                : > "$TMP/sec.$section.configure"
                continue ;;
        esac
        key="${line%%:*}"
        val="${line#*:}"; val="${val# }"
        [ "$key" = "$line" ] && continue          # not a key: value line
        if [ -z "$section" ]; then
            [ "$key" = version ] && rec_version="$val"
            continue
        fi
        case "$key" in
            platform)   printf '%s\n' "$val" >> "$TMP/sec.$section.platform" ;;
            compiler)   printf '%s\n' "$val" >> "$TMP/sec.$section.compiler" ;;
            'built on') printf '%s\n' "$val" >> "$TMP/sec.$section.built" ;;
            configure)  printf '%s\n' "$val" >> "$TMP/sec.$section.configure" ;;
        esac
    done < "$record"

    if [ -z "$rec_version" ]; then
        echo "FATAL: $rel/PROVENANCE.txt carries no 'version:' line -- cannot judge" >&2
        cannot=1
        continue
    fi
    if [ ! -s "$TMP/sections" ]; then
        echo "FATAL: $rel/PROVENANCE.txt declares no [platform] section -- cannot judge" >&2
        cannot=1
        continue
    fi

    # (1) record version vs directory name. The directory name IS the version
    #     wherever the build system spells it, so a rename that forgets the
    #     record (or the reverse) has to be caught here.
    base="$(basename "$comp")"
    if [[ "$base" =~ ^[A-Za-z][A-Za-z0-9_+]*-([0-9]+(\.[0-9]+)*)$ ]]; then
        dir_version="${BASH_REMATCH[1]}"
        [ "$dir_version" = "$rec_version" ] \
            || fail "$rel: record says version $rec_version, directory name says $dir_version"
    else
        echo "note: $rel is not named <component>-<version>; the directory-name comparison is skipped" >&2
    fi

    # (2) every platform directory on disk must be declared, and vice versa.
    while IFS= read -r d; do
        p="$(basename "$d")"
        grep -qxF "$p" "$TMP/sections" \
            || fail "$rel/$p carries lib/libcrypto.a but PROVENANCE.txt has no [$p] section"
    done < <(find "$comp" -mindepth 1 -maxdepth 1 -type d 2>/dev/null \
                 | while IFS= read -r d; do [ -f "$d/lib/libcrypto.a" ] && printf '%s\n' "$d"; done)

    while IFS= read -r section; do
        archive="$comp/$section/lib/libcrypto.a"
        if [ ! -f "$archive" ]; then
            fail "$rel: PROVENANCE.txt declares [$section] but $rel/$section/lib/libcrypto.a is missing"
            continue
        fi
        if [ ! -f "$comp/$section/lib/libssl.a" ]; then
            fail "$rel/$section: lib/libssl.a is missing beside lib/libcrypto.a"
        fi

        # (3) version, read out of the archive.
        archive_props "$archive" version > "$TMP/got.version"
        if [ ! -s "$TMP/got.version" ]; then
            echo "FATAL: $rel/$section/lib/libcrypto.a carries no OpenSSL version string -- cannot judge" >&2
            cannot=1
            continue
        fi
        while IFS= read -r v; do
            [ "$v" = "$rec_version" ] \
                || fail "$rel/$section/lib/libcrypto.a says version $v, record says version $rec_version"
        done < "$TMP/got.version"

        # (4) platform, compiler and build date: whole sets, not first lines.
        for kind in platform compiler built; do
            archive_props "$archive" "$kind" > "$TMP/got.$kind"
            sort -u "$TMP/sec.$section.$kind" > "$TMP/want.$kind"
            while IFS= read -r v; do
                [ -n "$v" ] || continue
                grep -qxF "$v" "$TMP/want.$kind" \
                    || fail "$rel/$section/lib/libcrypto.a says $kind '$v', which the record does not list"
            done < "$TMP/got.$kind"
            while IFS= read -r v; do
                [ -n "$v" ] || continue
                grep -qxF "$v" "$TMP/got.$kind" \
                    || fail "$rel/$section: record lists $kind '$v', which the archive does not carry"
            done < "$TMP/want.$kind"
        done

        # (4b) the configure line against the headers it produced.
        cfgdir="$comp/$section/include/openssl/configuration.h"
        if [ ! -f "$cfgdir" ]; then
            echo "FATAL: $rel/$section has no include/openssl/configuration.h -- cannot judge the configure line" >&2
            cannot=1
        else
            grep -oE 'OPENSSL_NO_[A-Z0-9_]+' "$cfgdir" | sort -u > "$TMP/hdr.macros"
            tr ' ' '\n' < "$TMP/sec.$section.configure" \
                | grep -oE '^no-[a-z0-9-]+$' | sed 's/^no-//' | tr 'a-z-' 'A-Z_' | sort -u > "$TMP/cfg.tokens"
            # One token, one macro, both directions. AFALGENG, CAPIENG and
            # PADLOCKENG are deliberately NOT here: they are engine
            # implementations that no-engine turns off as a consequence, so they
            # have no token of their own and requiring one fails a correct
            # record. Their presence is checked below as a consequence instead.
            for feature in ASM ENGINE ASYNC APPS DOCS TESTS; do
                want=no; have=no
                grep -qxF "$feature" "$TMP/cfg.tokens" && want=yes
                grep -qxF "OPENSSL_NO_$feature" "$TMP/hdr.macros" && have=yes
                if [ "$want" != "$have" ]; then
                    if [ "$want" = yes ]; then
                        fail "$rel/$section: the record configures no-$(printf '%s' "$feature" | tr 'A-Z_' 'a-z-'), but configuration.h does not define OPENSSL_NO_$feature -- the build did not honour the recorded line"
                    else
                        fail "$rel/$section: configuration.h defines OPENSSL_NO_$feature, which no recorded configure line asked for -- the record does not describe this build"
                    fi
                fi
            done
            # no-engine turns the three engine implementations off with it. If
            # the record asks for no-engine and any of them survives, the build
            # is not the one the record describes.
            if grep -qxF ENGINE "$TMP/cfg.tokens"; then
                for implied in AFALGENG CAPIENG PADLOCKENG; do
                    grep -qxF "OPENSSL_NO_$implied" "$TMP/hdr.macros" \
                        || fail "$rel/$section: the record configures no-engine, but configuration.h does not define OPENSSL_NO_$implied, which follows from it"
                done
            fi
        fi

        # (5) a macOS archive has to be universal. Asserted against the
        #     archive so that trimming the record to match cannot buy a pass.
        if grep -q '^macos-' "$TMP/got.platform" || grep -q '^macos-' "$TMP/want.platform"; then
            for slice in macos-x86_64 macos-arm64; do
                grep -qxF "$slice" "$TMP/got.platform" \
                    || fail "$rel/$section/lib/libcrypto.a is not universal: no $slice slice in it"
            done
        fi
    done < "$TMP/sections"
done

if [ "$cannot" = 1 ] && [ "$rc" = 0 ]; then
    exit 2
fi
if [ "$rc" = 0 ]; then
    echo "check-vendored-provenance: ${#records[@]} record(s) agree with the archives beside them"
fi
exit "$rc"

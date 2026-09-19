#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-vendored-provenance.selftest.sh -- prove the provenance check can fail,
# and prove it fails for the right reason.
#
# The eleven cases below perturb the RECORD or the ARCHIVE. Only the three
# archive cases can tell a working check from one whose archive-reading
# branch is dead: the version is also compared against the
# directory name, so a check that never opens an archive still passes every
# record-side case. That is the difference between measuring a property and
# measuring a proxy for it.
#
# Each fixture is asserted GREEN before it is perturbed. A perturbation of an
# already-red tree proves nothing, and the two archive cases below are exactly
# where that mistake is cheap to make.
#
# The synthetic version numbers are deliberately not the vendored ones: a
# fixture that spelled the real version would go stale at every bump and would
# also defeat the "no stale version literal anywhere" sweep a bump runs.
#
# The synthetic archives are text files. The check's only input is what
# strings(1) prints out of them, so text is a faithful stand-in -- and it lets
# the fixtures reproduce a real quirk of the shipped macOS archive: in the
# universal archive the arm64 slice's compiler line is preceded by a Mach-O
# string-table length byte, so it does not start the line. A check anchored
# with '^compiler:' silently loses one of the two slices; case
# macos_not_universal is what holds that.
#
# Cases (ten must go non-zero; one must stay zero):
#   version_mismatch        record says another version      -> 1, names which comparison
#   missing_macos_platform  one platform line cut from record-> 1, names macosx
#   no_record               PROVENANCE.txt removed           -> 2 (never 0)
#   archive_swapped         macOS archive put where Linux's  -> 1, names the archive
#   half_bump               macOS archive left a release back-> 1, names macosx
#   macos_not_universal     macOS archive with one slice     -> 1, names macosx
#   configure_token_dropped a no- token cut from the record  -> 1, names the macro
#   configure_line_removed  no configure: line at all        -> 1
#   configure_token_added   a no- token the build never had  -> 1
#   configure_two_lines_same_tokens   two lines, one flag set  -> unchanged
#   configure_two_lines_extra_token   second line adds a flag  -> 1
set -uo pipefail

CHECK="$(cd "$(dirname "$0")" && pwd)/check-vendored-provenance.sh"
WORK="$(mktemp -d /var/tmp/prov-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fail=0
baseline_green=0
baseline_broken=0
FIXTURE_ROOT=""

# --- fixture builders ------------------------------------------------------
#
# linux_archive <file> <version> <built-on>
linux_archive() {
    {
        printf 'OpenSSL %s 27 Jan 2026\n' "$2"
        printf 'platform: linux-x86_64\n'
        printf 'compiler: gcc -fPIC -pthread -m64 -Wall -O3 -DOPENSSL_BUILDING_OPENSSL -DNDEBUG\n'
        printf 'built on: %s\n' "$3"
        printf 'ENGINESDIR: "/usr/local/lib64/engines-3"\n'
    } > "$1"
}

# macos_archive <file> <version> <built-on-x86_64> [<built-on-arm64>]
# With three arguments only the x86_64 slice is written -- a `lipo -thin`
# archive. The arm64 compiler line carries the leading length byte the real
# universal archive has.
macos_archive() {
    {
        printf 'OpenSSL %s 27 Jan 2026\n' "$2"
        printf 'platform: macos-x86_64\n'
        printf 'compiler: cc -fPIC -arch x86_64 -isysroot /SDKs/MacOSX15.2.sdk -O3 -Wall -DNDEBUG\n'
        printf 'built on: %s\n' "$3"
        if [ "$#" -ge 4 ]; then
            printf 'OpenSSL %s 27 Jan 2026\n' "$2"
            printf 'platform: macos-arm64\n'
            printf '$compiler: cc -fPIC -arch arm64 -isysroot /SDKs/MacOSX15.2.sdk -O3 -Wall -DNDEBUG\n'
            printf 'built on: %s\n' "$4"
        fi
    } > "$1"
}

# record <file> <version> <linux-built-on> <macos-built-on-x86_64> <macos-built-on-arm64>
record() {
    {
        printf 'component: openssl\n'
        printf 'version: %s\n' "$2"
        printf 'source-sha256: deadbeef\n'
        printf '\n[linux]\n'
        printf 'configure: ./Configure linux-x86_64 no-shared no-tests no-apps no-docs\n'
        printf 'platform: linux-x86_64\n'
        printf 'compiler: gcc -fPIC -pthread -m64 -Wall -O3 -DOPENSSL_BUILDING_OPENSSL -DNDEBUG\n'
        printf 'built on: %s\n' "$3"
        printf '\n[macosx]\n'
        printf 'configure: ./Configure darwin64-x86_64-cc no-shared no-tests no-apps no-docs no-asm no-async\n'
        printf 'platform: macos-x86_64\n'
        printf 'platform: macos-arm64\n'
        printf 'compiler: cc -fPIC -arch x86_64 -isysroot /SDKs/MacOSX15.2.sdk -O3 -Wall -DNDEBUG\n'
        printf 'compiler: cc -fPIC -arch arm64 -isysroot /SDKs/MacOSX15.2.sdk -O3 -Wall -DNDEBUG\n'
        printf 'built on: %s\n' "$4"
        printf 'built on: %s\n' "$5"
    } > "$1"
}

# fixture <name> [<version>] -> sets FIXTURE_ROOT (a thirdparty-shaped directory).
# It sets a global rather than printing one, so that the "is the fixture green"
# assert below runs in THIS shell and its failure count survives.
fixture() {
    local name="$1" ver="${2:-9.9.9}"
    local root="$WORK/$name" comp
    comp="$root/openssl-$ver"
    mkdir -p "$comp/linux/lib" "$comp/macosx/lib" \
             "$comp/linux/include/openssl" "$comp/macosx/include/openssl"
    # The consequence of the configure line, committed beside the archives. The
    # macros a default build always carries are included so the check is
    # comparing a set and not an empty file.
    {
        printf '#ifndef OPENSSL_NO_ASAN\n# define OPENSSL_NO_ASAN\n#endif\n'
        printf '#ifndef OPENSSL_NO_APPS\n# define OPENSSL_NO_APPS\n#endif\n'
        printf '#ifndef OPENSSL_NO_DOCS\n# define OPENSSL_NO_DOCS\n#endif\n'
        printf '#ifndef OPENSSL_NO_TESTS\n# define OPENSSL_NO_TESTS\n#endif\n'
    } > "$comp/linux/include/openssl/configuration.h"
    {
        cat "$comp/linux/include/openssl/configuration.h"
        printf '#ifndef OPENSSL_NO_ASM\n# define OPENSSL_NO_ASM\n#endif\n'
        printf '#ifndef OPENSSL_NO_ASYNC\n# define OPENSSL_NO_ASYNC\n#endif\n'
    } > "$comp/macosx/include/openssl/configuration.h"
    linux_archive "$comp/linux/lib/libcrypto.a" "$ver" 'Sun Feb 22 22:25:00 2026 UTC'
    macos_archive "$comp/macosx/lib/libcrypto.a" "$ver" \
        'Wed Feb 18 12:44:24 2026 UTC' 'Wed Feb 18 12:49:43 2026 UTC'
    : > "$comp/linux/lib/libssl.a"
    : > "$comp/macosx/lib/libssl.a"
    record "$comp/PROVENANCE.txt" "$ver" 'Sun Feb 22 22:25:00 2026 UTC' \
        'Wed Feb 18 12:44:24 2026 UTC' 'Wed Feb 18 12:49:43 2026 UTC'
    # A perturbation of an already-red tree proves nothing.
    local out grc
    out="$(PROV_ROOT="$root" bash "$CHECK" 2>&1)"; grc=$?
    if [ "$grc" != 0 ]; then
        echo "case $name: FATAL -- fixture is not green before perturbation (rc=$grc)"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1))
        baseline_broken=$((baseline_broken + 1))
    else
        baseline_green=$((baseline_green + 1))
    fi
    FIXTURE_ROOT="$root"
}

# expect <name> <expected-rc> <root> [<substring>...]
expect() {
    local name="$1" want="$2" root="$3"; shift 3
    local out grc
    cases=$((cases + 1))
    out="$(PROV_ROOT="$root" bash "$CHECK" 2>&1)"; grc=$?
    if [ "$grc" = "$want" ]; then
        echo "case $name: OK   -- exit $grc"
        [ "$want" != 0 ] && red=$((red + 1))
    else
        echo "case $name: FAIL -- expected exit $want, got $grc"
        echo "$out" | sed 's/^/    /'
        fail=$((fail + 1))
        return
    fi
    local want_s
    for want_s in "$@"; do
        case "$out" in
            *"$want_s"*) ;;
            *) echo "  case $name: FAIL -- the output does not name '$want_s'"
               echo "$out" | sed 's/^/    /'
               fail=$((fail + 1)) ;;
        esac
    done
}

# --- record-side perturbations --------------------------------------------

# 1. The bump that forgot the record: the archives moved, the record did not.
#    Both comparisons have to fire, and the output has to say which is which.
fixture version_mismatch; r="$FIXTURE_ROOT"
perl -pi -e 's/^version: 9\.9\.9$/version: 1.2.3/' "$r/openssl-9.9.9/PROVENANCE.txt"
expect version_mismatch 1 "$r" \
    'record says version 1.2.3' \
    'directory name says 9.9.9' \
    'linux/lib/libcrypto.a says version 9.9.9'

# 2. One recorded slice removed: the universal archive still has two.
fixture missing_macos_platform; r="$FIXTURE_ROOT"
perl -ni -e 'print unless /^platform: macos-x86_64$/' "$r/openssl-9.9.9/PROVENANCE.txt"
expect missing_macos_platform 1 "$r" 'macosx' 'macos-x86_64'

# 3. No record at all is not a pass. It is "cannot judge".
fixture no_record; r="$FIXTURE_ROOT"
rm -f "$r/openssl-9.9.9/PROVENANCE.txt"
expect no_record 2 "$r"

# --- archive-side perturbations -------------------------------------------

# 4. The record and the directory name are untouched; only the bytes moved.
#    A check that never opens an archive passes this one.
fixture archive_swapped; r="$FIXTURE_ROOT"
command cp -f "$r/openssl-9.9.9/macosx/lib/libcrypto.a" \
              "$r/openssl-9.9.9/linux/lib/libcrypto.a"
expect archive_swapped 1 "$r" 'linux/lib/libcrypto.a' 'macos-x86_64' 'linux-x86_64'

# 5. Half a bump: everything says 3.5.8 except the macOS archive, which is the
#    platform whose users would keep the vulnerability. The output must name it.
fixture half_bump 9.9.10; r="$FIXTURE_ROOT"
macos_archive "$r/openssl-9.9.10/macosx/lib/libcrypto.a" 9.9.9 \
    'Wed Feb 18 12:44:24 2026 UTC' 'Wed Feb 18 12:49:43 2026 UTC'
expect half_bump 1 "$r" 'macosx' 'says version 9.9.9' 'record says version 9.9.10'

# 6. A macOS archive with one slice. "macOS must carry both" was, until this
#    case, only ever checked against the record.
fixture macos_not_universal; r="$FIXTURE_ROOT"
macos_archive "$r/openssl-9.9.9/macosx/lib/libcrypto.a" 9.9.9 \
    'Wed Feb 18 12:44:24 2026 UTC'
expect macos_not_universal 1 "$r" 'macosx' 'macos-arm64'

# 7. The configure line used to be recorded and never compared, so a wrong BUILD
#    was silent while a forgotten RECORD was loud. The line is not in any archive,
#    but its consequence is committed in configuration.h.
fixture configure_token_dropped; r="$FIXTURE_ROOT"
perl -pi -e 's/ no-asm no-async$/ no-async/' "$r/openssl-9.9.9/PROVENANCE.txt"
expect configure_token_dropped 1 "$r" 'macosx' 'OPENSSL_NO_ASM' 'does not describe this build'

# 8. Removing the line entirely is the same finding, not an exemption.
fixture configure_line_removed; r="$FIXTURE_ROOT"
perl -ni -e 'print unless /^configure:/' "$r/openssl-9.9.9/PROVENANCE.txt"
expect configure_line_removed 1 "$r" 'macosx' 'OPENSSL_NO_ASM'

# 9. And the other direction: a token in the record that the build never had.
fixture configure_token_added; r="$FIXTURE_ROOT"
perl -pi -e 's#^configure: ./Configure linux-x86_64 no-shared#configure: ./Configure linux-x86_64 no-shared no-asm#' \
    "$r/openssl-9.9.9/PROVENANCE.txt"
expect configure_token_added 1 "$r" 'linux' 'did not honour the recorded line'

# 10. Two configure lines in one section -- which is what the macOS record has,
#     one per architecture slice. The tokens are unioned and compared against the
#     single committed header, so two lines carrying the SAME flag set must read
#     exactly like one line. Nothing covered that until now: every other case is
#     a single-line perturbation.
fixture configure_two_lines_same_tokens; r="$FIXTURE_ROOT"
perl -pi -e 's|^configure: ./Configure darwin64-x86_64-cc (.*)$|configure: ./Configure darwin64-x86_64-cc $1\nconfigure: ./Configure darwin64-arm64-cc $1|' \
    "$r/openssl-9.9.9/PROVENANCE.txt"
expect configure_two_lines_same_tokens 0 "$r"

# 11. And a second line that adds a flag the build never had is caught, so the
#     union is a union and not "whichever line came last".
fixture configure_two_lines_extra_token; r="$FIXTURE_ROOT"
perl -pi -e 's|^configure: ./Configure darwin64-x86_64-cc (.*)$|configure: ./Configure darwin64-x86_64-cc $1\nconfigure: ./Configure darwin64-arm64-cc $1 no-engine|' \
    "$r/openssl-9.9.9/PROVENANCE.txt"
expect configure_two_lines_extra_token 1 "$r" 'macosx' 'OPENSSL_NO_ENGINE'

# `red` is not expected to equal `cases`: one case asserts a PASS on purpose
# -- two configure lines carrying the same flag set. What must hold is that nothing failed, that something
# was proved red, and that every fixture was green before it was perturbed.
echo "selftest: baselines green $baseline_green, broken $baseline_broken"
echo "selftest: $cases cases, $red red-proved"
[ "$fail" = 0 ] && [ "$red" -gt 0 ] && [ "$baseline_broken" = 0 ]

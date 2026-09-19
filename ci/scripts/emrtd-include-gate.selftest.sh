#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# emrtd-include-gate.selftest.sh -- proves the configure-time check at the end
# of the top-level CMakeLists.txt can fail. A gate that has never failed is a
# claim.
#
# The gate is not a script. It is the block at the end of CMakeLists.txt that
# compares EMRTDCrypto's INCLUDE_DIRECTORIES with the list in
# cmake/EmrtdCryptoPrivateIncludes.cmake and fails the configure if the target
# carries a directory the module does not name. It runs in every configure,
# LIBRESCRS_BUILD_FUZZ on or off, which is the point: the three eMRTD fuzz
# harnesses read the same module, and the day the two lists were hand copies
# one directory went to the library only and the harnesses stopped compiling
# with nothing in an ordinary build to say so.
#
# This drives the REAL tree -- the real library file, module and check -- on a
# throw-away copy of the tracked files under ${TMPDIR:-/var/tmp}. Nothing in
# the checkout is touched. Seven cases; each asserts rc AND the message, because
# a gate that fails for the wrong reason is not a gate:
#   1 control       the untouched copy configures                       rc=0
#   2 PERTURBATION  target_include_directories(EMRTDCrypto PRIVATE ...)
#                   appended to lib/emrtd-crypto/CMakeLists.txt          rc!=0
#   3 PERTURBATION  the same line in the top-level file, right after the
#                   library is added -- the check must sit below it      rc!=0
#   4 control       a comment appended to the library's CMakeLists.txt   rc=0
#   5 control       a consumer project that calls include_directories()
#                   above add_subdirectory() of the copy: that directory
#                   reaches every target here, harnesses included, so it
#                   is no drift and must not trip the check              rc=0
#   6 PERTURBATION  the same consumer with case 2's line in the library:
#                   the consumer's directory is set aside, the target's
#                   own is still caught and named                        rc!=0
#   7 PERTURBATION  include_directories() written inside lib/emrtd-crypto:
#                   directory-wide too, but the library's own, so what is
#                   set aside is the root's list and nothing below it     rc!=0
# Cases 2, 3, 6 and 7 must name the directory and carry the check's own message.
# The log is grepped with whitespace runs squeezed to one space: CMake wraps
# FATAL_ERROR text at a column and indents the continuation, so a fixed phrase
# can straddle a line break.
#
# Extra arguments are passed to every cmake configure (a prefix path, say).
#
# Exit: 0 all cases hold - 1 a case failed - 2 cannot measure.
set -uo pipefail
repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
git -C "$repo" rev-parse --show-toplevel >/dev/null 2>&1 \
    || { echo "FATAL: $repo is not a git checkout -- cannot measure" >&2; exit 2; }
for tool in cmake tar sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || { echo "FATAL: $tool not found -- cannot measure" >&2; exit 2; }
done

T="$(mktemp -d "${TMPDIR:-/var/tmp}/emrtd-inc-selftest.XXXXXX")"
trap 'rm -rf "$T"' EXIT
SRC="$T/src"
mkdir -p "$SRC"
if ! git -C "$repo" ls-files --recurse-submodules -z \
        | tar -C "$repo" --null -T - -cf - | tar -C "$SRC" -xf -; then
    echo "FATAL: could not copy the tracked tree -- cannot measure" >&2; exit 2
fi
LIB="$SRC/lib/emrtd-crypto/CMakeLists.txt"
TOP="$SRC/CMakeLists.txt"
[ -f "$LIB" ] && [ -f "$TOP" ] || { echo "FATAL: copy lacks the CMake files -- cannot measure" >&2; exit 2; }
cp -p "$LIB" "$T/lib.orig"; cp -p "$TOP" "$T/top.orig"
sum() { sha256sum "$1" | cut -d' ' -f1; }
LIB0="$(sum "$LIB")"; TOP0="$(sum "$TOP")"
restore() {  # restore -- both files back, proved by hash, or we cannot judge the next case
    cp -p "$T/lib.orig" "$LIB"; cp -p "$T/top.orig" "$TOP"
    [ "$(sum "$LIB")" = "$LIB0" ] && [ "$(sum "$TOP")" = "$TOP0" ] \
        || { echo "FATAL: restore did not reproduce the original files -- cannot measure" >&2; exit 2; }
}

# A downstream project of the shape FetchContent/add_subdirectory produce, with
# a directory-wide include set before the copy is added.
WRAP="$T/consumer"
mkdir -p "$WRAP"
cat > "$WRAP/CMakeLists.txt" <<CMAKE
cmake_minimum_required(VERSION 3.24)
project(consumer C CXX)
include_directories(/nonexistent/consumer-dir)
add_subdirectory("$SRC" lm)
CMAKE

fails=0
cases=0
red=0
# say <status> <label> <gate-rc>: <gate-rc> is what the gate was expected to
# return for this case, and a non-zero one is a case that proved the gate red.
say() {
  cases=$((cases + 1))
  if [ "${3:-0}" != 0 ]; then red=$((red + 1)); fi
  if [ "$1" = 0 ]; then printf 'PASS  %s\n' "$2"; else printf 'FAIL  %s\n' "$2"; fails=1; fi
}
EXTRA=("$@")
configure() {  # configure <n> [source dir] -> rc; log in $T/log<n>
    cmake -S "${2:-$SRC}" -B "$T/b$1" -DBUILD_TESTING=OFF -DLIBRESCRS_VENDOR_OPENSC=OFF \
        ${EXTRA[@]+"${EXTRA[@]}"} > "$T/log$1" 2>&1; echo $?
}
says_check() {  # says_check <log> -> 0 when the check's own message is in the log
    tr -s '[:space:]' ' ' < "$1" | grep -q 'EMRTDCrypto include directory not declared'
}
names_probe() {  # names_probe <log> -> 0 when the check's message and the probe directory are both there
    says_check "$1" && grep -q '/nonexistent/probe' "$1"
}
PROBE='target_include_directories(EMRTDCrypto PRIVATE /nonexistent/probe)'
DIR_PROBE='include_directories(/nonexistent/probe-dir)'

# 1. control: the untouched copy configures.
rc=$(configure 1)
[ "$rc" = 0 ] && ! says_check "$T/log1"; say $? "1 control: untouched tree configures (rc=$rc)" 0
[ "$rc" = 0 ] || { echo "  (control failed -- log tail follows)"; tail -n 20 "$T/log1" | sed 's/^/  | /'; }

# 2. PERTURBATION: a directory added to the target directly, in the library's file.
printf '\n%s\n' "$PROBE" >> "$LIB"
[ "$(sum "$LIB")" != "$LIB0" ] || { echo "FATAL: perturbation changed nothing" >&2; exit 2; }
rc=$(configure 2)
[ "$rc" != 0 ] && names_probe "$T/log2"; say $? "2 PERTURBATION: directory added in lib/emrtd-crypto fails the configure and is named (rc=$rc)" 1
restore

# 3. PERTURBATION: the same line in the top-level file, after the library exists.
sed -i "/^add_subdirectory(lib\/emrtd-crypto)$/a $PROBE" "$TOP"
[ "$(sum "$TOP")" != "$TOP0" ] || { echo "FATAL: perturbation changed nothing (anchor line missing?)" >&2; exit 2; }
rc=$(configure 3)
[ "$rc" != 0 ] && names_probe "$T/log3"; say $? "3 PERTURBATION: directory added in the top-level file fails the configure and is named (rc=$rc)" 1
restore

# 4. control: an edit that adds no directory must not trip the check.
printf '\n# probe comment\n' >> "$LIB"
[ "$(sum "$LIB")" != "$LIB0" ] || { echo "FATAL: perturbation changed nothing" >&2; exit 2; }
rc=$(configure 4)
[ "$rc" = 0 ] && ! says_check "$T/log4"; say $? "4 control: a comment in the library's file still configures (rc=$rc)" 0
restore

# 5. control: a consumer's directory-wide include is inherited by every target,
#    the harnesses included, and must not read as drift.
rc=$(configure 5 "$WRAP")
[ "$rc" = 0 ] && ! says_check "$T/log5"; say $? "5 control: a consumer's include_directories() above add_subdirectory() still configures (rc=$rc)" 0
[ "$rc" = 0 ] || { echo "  (control failed -- log tail follows)"; tail -n 20 "$T/log5" | sed 's/^/  | /'; }

# 6. PERTURBATION: setting the consumer's directory aside must not set aside the
#    target's own -- case 2 under the consumer is still caught.
printf '\n%s\n' "$PROBE" >> "$LIB"
[ "$(sum "$LIB")" != "$LIB0" ] || { echo "FATAL: perturbation changed nothing" >&2; exit 2; }
rc=$(configure 6 "$WRAP")
[ "$rc" != 0 ] && names_probe "$T/log6"; say $? "6 PERTURBATION: under that consumer, a directory added in lib/emrtd-crypto still fails the configure and is named (rc=$rc)" 1
restore

# 7. PERTURBATION: a directory-wide include in the library's own file lands on
#    the target and is not the root's, so it must still be caught.
printf '\n%s\n' "$DIR_PROBE" >> "$LIB"
[ "$(sum "$LIB")" != "$LIB0" ] || { echo "FATAL: perturbation changed nothing" >&2; exit 2; }
rc=$(configure 7)
[ "$rc" != 0 ] && says_check "$T/log7" && grep -q '/nonexistent/probe-dir' "$T/log7"; say $? "7 PERTURBATION: include_directories() inside lib/emrtd-crypto fails the configure and is named (rc=$rc)" 1
restore

[ "$fails" -eq 0 ] && echo "selftest: 7/7 OK" || echo "selftest: FAILED"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit "$fails"

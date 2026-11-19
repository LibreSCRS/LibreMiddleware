#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-snapshot.selftest.sh — prove the ABI snapshot can fail, and can refuse.
#
# The gate this proves is the last thing standing between a silently changed
# public ABI and a release tag, and until this file existed nobody had watched
# it go red. Worse, it could be disarmed for good without a single red run:
# `--update` over a tree that exports nothing used to write a baseline of
# comments only, and every later `--check` against the same empty tree then
# passed. That is the case this file exists for, so it is measured in both
# directions: the baseline losing a symbol, and the tree losing one.
#
# Every case builds a throwaway repository under /var/tmp (never /tmp, a RAM
# filesystem on the development host) holding a copy of this gate, its
# public-surface helper, an installed-header tree (include/LibreSCRS) and a stub
# shared object named the way CMake names the real ones. The stub is the point:
# a case that leans on the repository's own build tree would measure whatever
# was last built there.
#
# selftest-platforms: linux -- the fixtures are ELF shared objects read with
# `nm -D`; the gate itself runs only on the Linux leg that records the baseline.
#
# Cases:
#   1  control: --update over the stub tree, then --check          -> 0
#   2  one symbol removed from the baseline                        -> 1
#   3  one exported symbol removed from the shared object          -> 1
#   4  an empty build tree, --check                                -> 2
#   5  an empty build tree, --update: refused, baseline untouched   -> 2
#   6  control: the same run under a PATH shim that HAS c++filt    -> 0
#   7  c++filt taken off PATH                                      -> 2
#   8  an exported data symbol                                     -> 2
#   9  an exported Internal:: function is a leak; allowlisted (and
#      imported by a plugin) it is not recorded; renamed, it is a leak,
#      the plugin's import is a hidden symbol and the entry is stale -> 1/0/1
#  10  a public function taking an Internal:: type                 -> 1
#  11  one function exported by two libraries, --check / --update  -> 1
#
# The public-entity rule (every export of every binding class names an entity
# the installed headers declare, nothing Internal/detail):
#  12  control: an exported public class with a vtable             -> 0
#  13  a class outside Internal, declared only in a header that is
#      not installed, re-exported (the PlainChannel shape)         -> 1
#  14  a new Internal:: export, and the typeinfo of an Internal::
#      class (V binding)                                           -> 1
#  15  a public function taking a type no installed header declares -> 1
#  16  a function declared only under LIBRESCRS_INTERNAL_BUILD      -> 1
#  17  a function declared only as a friend                        -> 1
#  18  a function declared only in an installed tree's detail/
#      directory, which install() excludes                         -> 1
#  19  the allowlist: an entry no shipped image imports, an entry
#      whose export is gone, an entry without a reason, a "thrown:"
#      reason on a function                                        -> 1/1/2/2
#  20  CXX is not clang                                            -> 2
#
# The import and inline-body rules, and the shrink-only rule:
#  21  a plugin imports a symbol no core library exports (hidden)   -> 1
#  22  an inline function in an installed header calls a function
#      no core library exports                                     -> 1
#  23  the same inline body calling an Internal:: export the
#      allowlist does not name                                     -> 1
#  24  control: an inline body calling an exported public function  -> 0
#  25  an entry added against --allowlist-base, and its control     -> 1/0
set -uo pipefail

HERE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SUBJECT="${SUBJECT:-$HERE/abi-snapshot.sh}"
[ -f "$SUBJECT" ] || { echo "FATAL: $SUBJECT is missing" >&2; exit 2; }

# A compiler is the only way to get a shared object whose exported set this
# file controls. Without one the answer is "I could not measure", never a pass.
# The gate reads the installed headers with clang. CI hands the self-tests a
# CXX naming the clang it pins (the runner's default one crashes on <type_traits>
# under -std=c++23); a CXX naming gcc is replaced, because it would turn every
# case into "cannot measure".
if ! "${CXX:-clang++}" --version 2>/dev/null | grep -q clang; then
    CXX=clang++
fi
CXX="${CXX:-clang++}"
export CXX

for tool in g++ nm c++filt python3 "$CXX"; do
    command -v "$tool" >/dev/null 2>&1 \
        || { echo "FATAL: $tool not found on PATH -- cannot build the fixture" >&2; exit 2; }
done

HELPER="$HERE/abi-public-surface.py"
[ -f "$HELPER" ] || { echo "FATAL: $HELPER is missing" >&2; exit 2; }
WORK="$(mktemp -d /var/tmp/abi-snapshot-selftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

cases=0
red=0
fails=0

check() {  # check <label> <want-rc> <got-rc>
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero over a
    # perturbed input.
    if [ "$2" != 0 ]; then red=$((red + 1)); fi
    if [ "$2" = "$3" ]; then
        printf 'ok    %-52s rc=%s\n' "$1" "$3"
    else
        printf 'FAIL  %-52s rc=%s want=%s\n' "$1" "$3" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

says() {  # says <label> <text>
    if grep -qF -- "$2" "$WORK/out"; then
        printf 'ok    %-52s says %s\n' "$1" "$2"
    else
        printf 'FAIL  %-52s does not say %s\n' "$1" "$2"
        sed 's/^/        /' "$WORK/out"
        fails=$((fails + 1))
    fi
}

# fixture <root>: the gate, its helper, an empty allowlist, the header of the
# three stub functions, which every stub below exports, and a card plugin that
# imports nothing from LibreSCRS (the gate refuses to judge imports without
# one).
fixture() {
    local root="$1"
    mkdir -p "$root/ci/scripts" "$root/ci/abi" "$root/build/lib/LibreSCRS" "$root/build/plugins" \
        "$root/include/LibreSCRS"
    cp "$SUBJECT" "$root/ci/scripts/abi-snapshot.sh"
    cp "$HELPER" "$root/ci/scripts/abi-public-surface.py"
    chmod 0755 "$root/ci/scripts/abi-snapshot.sh"
    printf '# fixture allowlist\n' > "$root/ci/abi/5.x-internal-exports.txt"
    printf 'namespace LibreSCRS {\nint selftestAlpha(int x);\nint selftestBeta(int x);\nint selftestGamma(int x);\n}\n' \
        > "$root/include/LibreSCRS/Stub.h"
    plugin "$root" 'extern "C" int fixture_plugin_entry() { return 0; }'
}

# plugin <root> <source text>: the fixture's one card plugin, compiled from
# <source text>. Its undefined symbols are what a shipped image imports.
plugin() {
    printf '%s\n' "$2" > "$1/plugin.cpp"
    g++ -shared -fPIC -o "$1/build/plugins/libfixture-plugin.so" "$1/plugin.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the fixture plugin" >&2; sed 's/^/        /' "$WORK/gcc.err" >&2; exit 2; }
}

# stub <name> [--without-beta] -> prints the fixture root
stub() {
    # One `local` per name: bash 5.3 does not let the second assignment in a
    # single `local` see the first, and under `set -u` that is an unbound
    # variable rather than an empty one.
    local name="$1"
    local omit="${2:-}"
    local root="$WORK/$name"
    fixture "$root"
    {
        printf 'namespace LibreSCRS {\n'
        printf 'int selftestAlpha(int x) { return x + 1; }\n'
        [ -n "$omit" ] || printf 'int selftestBeta(int x) { return x + 2; }\n'
        printf 'int selftestGamma(int x) { return x + 3; }\n'
        printf '}\n'
    } > "$root/stub.cpp"
    # The filename shape the gate looks for: libLibreSCRS_*.so.<X>.<Y>.<Z>.
    g++ -shared -fPIC -o "$root/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
        "$root/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the stub shared object" >&2; sed 's/^/        /' "$WORK/gcc.err" >&2; exit 2; }
    printf '%s' "$root"
}

run() {  # run <root> <args...> -> rc; output in $WORK/out
    local root="$1"; shift
    if ( cd "$root" && ./ci/scripts/abi-snapshot.sh "$@" ) > "$WORK/out" 2>&1; then
        echo 0
    else
        echo $?
    fi
}

# --- case 1: the control. Without it every refusal below could be an error path.
root="$(stub control)"
rc=$(run "$root" --update build)
check "control: --update over the stub tree" 0 "$rc"
if ! grep -q 'selftestBeta' "$root/ci/abi/5.x-baseline.txt"; then
    echo "FATAL: the fixture's own baseline does not carry the stub symbols" >&2
    exit 2
fi
rc=$(run "$root" --check build)
check "control: --check against what --update wrote" 0 "$rc"
command cp -f "$root/ci/abi/5.x-baseline.txt" "$WORK/baseline.good"

# --- case 2: the baseline loses a symbol -- drift from the recorded side.
root2="$(stub baseline-short)"
run "$root2" --update build >/dev/null
grep -v 'selftestBeta' "$WORK/baseline.good" > "$root2/ci/abi/5.x-baseline.txt"
if cmp -s "$WORK/baseline.good" "$root2/ci/abi/5.x-baseline.txt"; then
    echo "FATAL: the perturbation changed nothing -- it would pass for the wrong reason" >&2
    exit 2
fi
rc=$(run "$root2" --check build)
check "a symbol missing from the baseline is drift" 1 "$rc"
says "a symbol missing from the baseline is drift" "selftestBeta"

# --- case 3: the tree loses a symbol -- drift from the measured side.
root3="$(stub tree-short --without-beta)"
command cp -f "$WORK/baseline.good" "$root3/ci/abi/5.x-baseline.txt"
rc=$(run "$root3" --check build)
check "a symbol missing from the library is drift" 1 "$rc"
says "a symbol missing from the library is drift" "selftestBeta"

# --- case 4/5: a tree that exports nothing. This is the one that could disarm
#     the gate for every later run, so --update must refuse and leave the
#     baseline byte-for-byte as it was.
root4="$(stub empty-tree)"
run "$root4" --update build >/dev/null
command cp -f "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"
rm -f "$root4/build/lib/LibreSCRS/"*.so.*
rc=$(run "$root4" --check build)
check "an empty tree cannot be judged" 2 "$rc"
rc=$(run "$root4" --update build)
check "an empty tree is refused by --update" 2 "$rc"
if cmp -s "$WORK/baseline.good" "$root4/ci/abi/5.x-baseline.txt"; then
    printf 'ok    %-52s baseline untouched\n' "the refused --update wrote nothing"
else
    printf 'FAIL  %-52s the refused --update overwrote the baseline\n' "the refused --update wrote nothing"
    fails=$((fails + 1))
fi

# --- case 6/7: the tool that was silenced. The shim is proved to work with
#     c++filt present before c++filt is taken out of it, or a broken shim
#     would read as the finding.
SHIM="$WORK/shim"
mkdir -p "$SHIM"
for t in bash sh nm c++filt awk sort find wc basename dirname mktemp diff cat sed grep cp mkdir rm head tr env printf ls uname python3 "$CXX"; do
    p="$(command -v "$t" 2>/dev/null)" && ln -sf "$p" "$SHIM/$t"
done
root5="$(stub shim-tree)"
run "$root5" --update build >/dev/null
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "control: the PATH shim with c++filt still judges" 0 "$rc"
rm -f "$SHIM/c++filt"
rc=$( if ( cd "$root5" && PATH="$SHIM" ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "c++filt off PATH is 'cannot measure'" 2 "$rc"
says "c++filt off PATH is 'cannot measure'" "c++filt not found on PATH"

# --- case 8: a binding class the snapshot has no rule for -------------------
# The snapshot records T and declares which classes it deliberately does not,
# because the policy says vague-linkage entries are not the public API: they are
# how the object model emits a vtable or an inline member, and the compiler
# decides which exist. Recording them would put inlining decisions into the ABI.
#
# What that must NOT do is drop something that IS the ABI. An exported DATA
# symbol is part of a C++ contract, and the old T-only clause threw it away
# without a word. This case is that symbol.
root6="$(stub data-symbol)"
run "$root6" --update build >/dev/null
{
    printf 'namespace LibreSCRS {\n'
    printf 'int selftestAlpha(int x) { return x + 1; }\n'
    printf 'int selftestBeta(int x) { return x + 2; }\n'
    printf 'int selftestGamma(int x) { return x + 3; }\n'
    printf 'int selftestExportedGlobal = 7;\n'
    printf '}\n'
} > "$root6/stub.cpp"
g++ -shared -fPIC -o "$root6/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
    "$root6/stub.cpp" 2>"$WORK/gcc.err" \
    || { echo "FATAL: could not rebuild the stub with a data symbol" >&2; exit 2; }
# The fixture really does export one, or the case would pass for the wrong reason.
if ! nm -D -U "$root6/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
        | awk '$2 == "D" || $2 == "B" { found = 1 } END { exit !found }'; then
    echo "FATAL: the fixture exports no data symbol -- nothing to detect" >&2
    exit 2
fi
rc=$(run "$root6" --check build)
check "an exported data symbol is not dropped in silence" 2 "$rc"
says "an exported data symbol is not dropped in silence" "no
       rule for"

# --- case 9: an exported Internal:: or detail:: symbol is a leak ------------
#     It used to be dropped by its spelling, which is how 82 internal exports
#     went unrecorded. Now it is a leak unless the allowlist names it exactly;
#     allowlisted, it is not recorded; renamed, the new name is a leak and the
#     entry naming the old one is stale.
root9="$WORK/internal"
fixture "$root9"
build_internal() {  # build_internal <internal-function-name>
    {
        printf 'namespace LibreSCRS {\n'
        printf 'int selftestAlpha(int x) { return x + 1; }\n'
        printf 'int selftestBeta(int x) { return x + 2; }\n'
        printf 'int selftestGamma(int x) { return x + 3; }\n'
        printf 'namespace Internal { int %s(int x) { return x + 4; } }\n' "$1"
        printf '}\n'
    } > "$root9/stub.cpp"
    g++ -shared -fPIC -o "$root9/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
        "$root9/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the internal-symbol stub" >&2; exit 2; }
}
build_internal selftestInternal
rc=$(run "$root9" --update build)
check "an Internal:: export, not allowlisted: --update" 1 "$rc"
says "an Internal:: export, not allowlisted: --update" "LibreSCRS::Internal::selftestInternal(int)"
printf 'libLibreSCRS_Stub.so\tLibreSCRS::Internal::selftestInternal(int)\timported: libfixture-plugin\n' \
    >> "$root9/ci/abi/5.x-internal-exports.txt"
plugin "$root9" 'namespace LibreSCRS { namespace Internal { int selftestInternal(int x); } }
int fixture_use() { return LibreSCRS::Internal::selftestInternal(1); }'
rc=$(run "$root9" --update build)
check "the same export, allowlisted: --update" 0 "$rc"
if grep -q 'selftestInternal' "$root9/ci/abi/5.x-baseline.txt"; then
    printf 'FAIL  %-52s recorded\n' "an allowlisted internal export is not recorded"
    fails=$((fails + 1))
else
    printf 'ok    %-52s not recorded\n' "an allowlisted internal export is not recorded"
fi
build_internal selftestInternalRenamed
rc=$(run "$root9" --check build)
check "a renamed Internal:: export" 1 "$rc"
says "a renamed Internal:: export" "LibreSCRS::Internal::selftestInternalRenamed(int)"
says "a renamed Internal:: export" "STALE ALLOWLIST"
says "a renamed Internal:: export" "IMPORT OF A HIDDEN SYMBOL"

# --- case 10: a public function that takes an Internal:: type ---------------
#     Declared in an installed header, but a consumer can only call it with a
#     type in an internal scope: not public API either.
root10="$WORK/internal-param"
fixture "$root10"
{
    printf 'namespace LibreSCRS {\n'
    printf 'namespace Internal { struct SelftestCommand { int x; }; }\n'
    printf 'int selftestAlpha(int x);\nint selftestBeta(int x);\nint selftestGamma(int x);\n'
    printf 'int selftestTakesInternal(const Internal::SelftestCommand& a);\n'
    printf '}\n'
} > "$root10/include/LibreSCRS/Stub.h"
{
    printf '#include <LibreSCRS/Stub.h>\n'
    printf 'namespace LibreSCRS {\n'
    printf 'int selftestAlpha(int x) { return x + 1; }\n'
    printf 'int selftestBeta(int x) { return x + 2; }\n'
    printf 'int selftestGamma(int x) { return x + 3; }\n'
    printf 'int selftestTakesInternal(const Internal::SelftestCommand& a) { return a.x; }\n'
    printf '}\n'
} > "$root10/stub.cpp"
g++ -shared -fPIC -I"$root10/include" -o "$root10/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" \
    "$root10/stub.cpp" 2>"$WORK/gcc.err" \
    || { echo "FATAL: could not build the internal-parameter stub" >&2; exit 2; }
rc=$(run "$root10" --update build)
check "a public function taking an Internal:: type" 1 "$rc"
says "a public function taking an Internal:: type" "selftestTakesInternal(LibreSCRS::Internal::SelftestCommand const&)"

# --- case 11: one function exported by two libraries ------------------------
#     A library that absorbs another one's implementation exports its
#     functions a second time, and the snapshot would record both copies as
#     two promises. The control is two libraries with disjoint exports, so the
#     refusal below is about the shared function and not about a second file.
root11="$WORK/two-owners"
fixture "$root11"
printf 'namespace LibreSCRS {\nint selftestOwned(int x);\nint selftestOther(int x);\n}\n' \
    > "$root11/include/LibreSCRS/Stub.h"
build_lib11() {  # build_lib11 <Module> <function-name...>
    local module="$1"; shift
    local fn
    {
        printf 'namespace LibreSCRS {\n'
        for fn in "$@"; do printf 'int %s(int x) { return x + 1; }\n' "$fn"; done
        printf '}\n'
    } > "$root11/$module.cpp"
    g++ -shared -fPIC -o "$root11/build/lib/LibreSCRS/libLibreSCRS_$module.so.5.0.0" \
        "$root11/$module.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build the $module stub" >&2; exit 2; }
}
build_lib11 Owner selftestOwned
build_lib11 Other selftestOther
rc=$(run "$root11" --update build)
check "control: two libraries, disjoint exports" 0 "$rc"
command cp -f "$root11/ci/abi/5.x-baseline.txt" "$WORK/baseline.two"
build_lib11 Other selftestOther selftestOwned
rc=$(run "$root11" --check build)
check "a function exported by two libraries" 1 "$rc"
says "a function exported by two libraries" "exported by more than one library"
says "a function exported by two libraries" "selftestOwned"
rc=$(run "$root11" --update build)
check "the duplicate is refused by --update" 1 "$rc"
if cmp -s "$WORK/baseline.two" "$root11/ci/abi/5.x-baseline.txt"; then
    printf 'ok    %-52s baseline untouched\n' "the refused duplicate wrote nothing"
else
    printf 'FAIL  %-52s the refused --update overwrote the baseline\n' "the refused duplicate wrote nothing"
    fails=$((fails + 1))
fi

# --- cases 12 to 20: only public entities are exported ---------------------
# custom <name> <installed header text> <source text> [<path> <text>]...: a
# fixture whose one library is compiled from <source text>, with <installed
# header text> as include/LibreSCRS/Stub.h and each further <path> (relative to
# the fixture root) holding <text>. The source sees the internal build's view
# (it defines LIBRESCRS_INTERNAL_BUILD and has src/ on its include path); the
# gate sees what a consumer sees. Sets $root; called without a subshell, so a
# failed compile stops the whole self-test.
custom() {
    root="$WORK/$1"
    fixture "$root"
    mkdir -p "$root/src"
    printf '%s\n' "$2" > "$root/include/LibreSCRS/Stub.h"
    printf '%s\n' "$3" > "$root/stub.cpp"
    shift 3
    while [ "$#" -ge 2 ]; do
        mkdir -p "$(dirname "$root/$1")"
        printf '%s\n' "$2" > "$root/$1"
        shift 2
    done
    # The visibility flags of the shipped libraries: an inline member (an
    # implicit constructor among them) is never exported, so the export table
    # holds what the real one holds.
    g++ -shared -fPIC -fvisibility=hidden -fvisibility-inlines-hidden -DLIBRESCRS_INTERNAL_BUILD \
        -I"$root/include" -I"$root/src" \
        -o "$root/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" "$root/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not build fixture $root" >&2; sed 's/^/        /' "$WORK/gcc.err" >&2; exit 2; }
}
EXPORT='__attribute__((visibility("default")))'
PUBLIC_FNS='int selftestAlpha(int x);'
PUBLIC_DEFS="$EXPORT int selftestAlpha(int x) { return x + 1; }"

# 12: the control of 13 and 14. A public class with two polymorphic bases,
#     defined in an installed header and exported: its members, the thunk of
#     the override from its second base, its vtable and its typeinfo are all
#     attributed to the installed declaration.
custom public-class \
    "namespace LibreSCRS { $PUBLIC_FNS
struct $EXPORT SelftestA { virtual ~SelftestA(); virtual int a(); };
struct $EXPORT SelftestB { virtual ~SelftestB(); virtual int b(); };
class $EXPORT SelftestWidget : public SelftestA, public SelftestB { public: SelftestWidget(); ~SelftestWidget() override; int b() override; }; }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS
SelftestA::~SelftestA() = default; int SelftestA::a() { return 1; }
SelftestB::~SelftestB() = default; int SelftestB::b() { return 2; }
SelftestWidget::SelftestWidget() = default; SelftestWidget::~SelftestWidget() = default;
int SelftestWidget::b() { return 3; } }"
root12="$root"
if ! nm -D -U "$root12/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" | c++filt \
        | grep -q 'non-virtual thunk to LibreSCRS::SelftestWidget::b()'; then
    echo "FATAL: the control exports no thunk -- it would prove nothing" >&2
    exit 2
fi
rc=$(run "$root12" --update build)
check "control: an exported public class" 0 "$rc"

# 13: the shape a name rule never saw. PlainChannel lives in a public namespace
#     (not Internal), its header is not installed, and LIBRESCRS_PUBLIC_API on
#     the class re-exports its members, vtable and typeinfo. The installed
#     header forward-declares it, as installed headers do for a friend: a
#     declaration is not a definition, so it publishes no vtable.
custom reexported-plain \
    "namespace LibreSCRS { $PUBLIC_FNS namespace SecureChannel { class PlainChannel; } }" \
    "#include <LibreSCRS/Stub.h>
#include \"PlainChannel.h\"
namespace LibreSCRS { $PUBLIC_DEFS
namespace SecureChannel { PlainChannel::PlainChannel(int a) : aid(a) {} int PlainChannel::state() const { return aid; } int PlainChannel::applet() const { return aid; } } }" \
    src/PlainChannel.h "namespace LibreSCRS::SecureChannel {
struct ISecureChannel { virtual ~ISecureChannel() = default; virtual int state() const = 0; };
struct IApplet { virtual ~IApplet() = default; virtual int applet() const = 0; };
class $EXPORT PlainChannel final : public ISecureChannel, public IApplet { public: explicit PlainChannel(int a); int state() const override; int applet() const override; private: int aid; }; }"
root13="$root"
rc=$(run "$root13" --update build)
check "a re-exported PlainChannel" 1 "$rc"
says "a re-exported PlainChannel" "LibreSCRS::SecureChannel::PlainChannel::PlainChannel(int)"
says "a re-exported PlainChannel" "vtable for LibreSCRS::SecureChannel::PlainChannel"
says "a re-exported PlainChannel" "non-virtual thunk to LibreSCRS::SecureChannel::PlainChannel::applet() const"

# 14: a new Internal:: export, declared in the installed header (a forward
#     declaration for a friend is the usual reason), plus the typeinfo of an
#     Internal:: class -- a V-binding row the old T-only filter never read.
custom new-internal \
    "namespace LibreSCRS { $PUBLIC_FNS namespace Internal { int selftestHelper(int x); } }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS
namespace Internal { $EXPORT int selftestHelper(int x) { return x; }
struct $EXPORT SelftestProvider { virtual ~SelftestProvider(); virtual int get() = 0; };
SelftestProvider::~SelftestProvider() = default; } }"
root14="$root"
rc=$(run "$root14" --update build)
check "a new Internal:: export and its typeinfo" 1 "$rc"
says "a new Internal:: export and its typeinfo" "LibreSCRS::Internal::selftestHelper(int)"
says "a new Internal:: export and its typeinfo" "V  typeinfo for LibreSCRS::Internal::SelftestProvider"

# 15: a public function whose parameter type no installed header declares (the
#     SessionKeys shape): no installed declaration of the function can exist.
custom undeclared-param \
    "namespace LibreSCRS { $PUBLIC_FNS }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS
namespace SecureChannel { struct SessionKeys { int enc; }; $EXPORT int selftestRekey(SessionKeys k) { return k.enc; } } }"
root15="$root"
rc=$(run "$root15" --update build)
check "a function taking an uninstalled type" 1 "$rc"
says "a function taking an uninstalled type" "LibreSCRS::SecureChannel::selftestRekey(LibreSCRS::SecureChannel::SessionKeys)"

# 16: the two-faced header. The declaration exists only for the internal build,
#     so the consumer's view of the same header has no such function.
custom internal-build-only \
    "namespace LibreSCRS { $PUBLIC_FNS
#ifdef LIBRESCRS_INTERNAL_BUILD
int selftestTransmitInternal(int x);
#endif
}" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS $EXPORT int selftestTransmitInternal(int x) { return x; } }"
root16="$root"
rc=$(run "$root16" --update build)
check "a function only the internal build declares" 1 "$rc"
says "a function only the internal build declares" "LibreSCRS::selftestTransmitInternal(int)"

# 17: a friend declaration names a function; it does not declare it for the
#     consumer.
custom friend-only \
    "namespace LibreSCRS { $PUBLIC_FNS
class SelftestSession { friend int selftestSessionGeneration(const SelftestSession&); int gen = 0; }; }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS $EXPORT int selftestSessionGeneration(const SelftestSession& s) { return s.gen; } }"
root17="$root"
rc=$(run "$root17" --update build)
check "a function declared only as a friend" 1 "$rc"
says "a function declared only as a friend" "LibreSCRS::selftestSessionGeneration(LibreSCRS::SelftestSession const&)"

# 18: a header under include/LibreSCRS/**/detail/ is in the source tree but not
#     in the package: install() excludes every detail directory.
custom detail-dir \
    "namespace LibreSCRS { $PUBLIC_FNS }" \
    "#include <LibreSCRS/Stub.h>
#include <LibreSCRS/detail/Bridge.h>
namespace LibreSCRS { $PUBLIC_DEFS int selftestUnwrap(int x) { return x; } }" \
    include/LibreSCRS/detail/Bridge.h "namespace LibreSCRS { $EXPORT int selftestUnwrap(int x); }"
root18="$root"
rc=$(run "$root18" --update build)
check "a function declared only under detail/" 1 "$rc"
says "a function declared only under detail/" "LibreSCRS::selftestUnwrap(int)"

# 19: every entry earns its place. Starting from the green, allowlisted case 9
#     fixture with its first function restored:
build_internal selftestInternal
rc=$(run "$root9" --check build)
check "control: one imported, listed internal export" 0 "$rc"
command cp -f "$root9/ci/abi/5.x-internal-exports.txt" "$WORK/allow9.good"
#   (a) the plugin stops importing it: still exported, but nothing ships that
#       needs it, so the entry is stale and the symbol must be hidden
plugin "$root9" 'extern "C" int fixture_plugin_entry() { return 0; }'
rc=$(run "$root9" --check build)
check "an entry no shipped image imports" 1 "$rc"
says "an entry no shipped image imports" "no shipped image imports it"
#   (b) the export is hidden, the entry kept
plugin "$root9" 'namespace LibreSCRS { namespace Internal { int selftestInternal(int x); } }
int fixture_use() { return LibreSCRS::Internal::selftestInternal(1); }'
build_internal_free() {
    printf 'namespace LibreSCRS {\nint selftestAlpha(int x) { return x + 1; }\nint selftestBeta(int x) { return x + 2; }\nint selftestGamma(int x) { return x + 3; }\n}\n' > "$root9/stub.cpp"
    g++ -shared -fPIC -o "$root9/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" "$root9/stub.cpp" 2>"$WORK/gcc.err" \
        || { echo "FATAL: could not rebuild the case 9 stub" >&2; exit 2; }
}
build_internal_free
rc=$(run "$root9" --check build)
check "an entry whose export is gone" 1 "$rc"
says "an entry whose export is gone" "no longer an internal export"
build_internal selftestInternal
#   (c) an entry without a reason
printf 'libLibreSCRS_Stub.so\tLibreSCRS::Internal::selftestInternal(int)\n' > "$root9/ci/abi/5.x-internal-exports.txt"
rc=$(run "$root9" --check build)
check "an entry without a reason" 2 "$rc"
#   (d) "thrown:" is a reason only for an exception type's typeinfo
printf 'libLibreSCRS_Stub.so\tLibreSCRS::Internal::selftestInternal(int)\tthrown: not a typeinfo\n' \
    > "$root9/ci/abi/5.x-internal-exports.txt"
rc=$(run "$root9" --check build)
check "a thrown: reason on a function" 2 "$rc"
command cp -f "$WORK/allow9.good" "$root9/ci/abi/5.x-internal-exports.txt"

# 20: the public surface is read from clang's AST; gcc cannot produce it.
rc=$( if ( cd "$root12" && CXX=g++ ./ci/scripts/abi-snapshot.sh --check build ) > "$WORK/out" 2>&1; then echo 0; else echo $?; fi )
check "CXX is not clang" 2 "$rc"
says "CXX is not clang" "is not clang"

# --- 21: a shipped image imports a symbol no core library exports ----------
#     The load fails at dlopen. The plugin calls the public function's hidden
#     sibling: declared, defined in the library, but not exported.
custom hidden-import \
    "namespace LibreSCRS { $PUBLIC_FNS }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS int selftestHiddenHelper(int x) { return x; } }"
root21="$root"
plugin "$root21" 'namespace LibreSCRS { int selftestHiddenHelper(int x); }
int fixture_use() { return LibreSCRS::selftestHiddenHelper(1); }'
rc=$(run "$root21" --update build)
check "a plugin importing a hidden symbol" 1 "$rc"
says "a plugin importing a hidden symbol" "libfixture-plugin.so  LibreSCRS::selftestHiddenHelper(int)"

# --- 22 to 24: an inline body in an installed header ------------------------
#     A consumer that calls the inline function links whatever it calls. The
#     makeSessionKey shape: a public inline function calling a detail:: one.
#     22: the callee is not exported at all.
custom inline-hidden \
    "namespace LibreSCRS { $PUBLIC_FNS int selftestGeneration(int x);
inline int selftestKey(int x) { return selftestGeneration(x) + 1; } }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS int selftestGeneration(int x) { return x; } }"
root22="$root"
rc=$(run "$root22" --update build)
check "an inline body calling an unexported function" 1 "$rc"
says "an inline body calling an unexported function" "LibreSCRS::selftestKey calls LibreSCRS::selftestGeneration(int), which no core library exports"
#     23: the callee is an exported detail:: function the allowlist does not name.
custom inline-detail \
    "namespace LibreSCRS { $PUBLIC_FNS namespace detail { int selftestGeneration(int x); }
inline int selftestKey(int x) { return detail::selftestGeneration(x) + 1; } }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS namespace detail { $EXPORT int selftestGeneration(int x) { return x; } } }"
root23="$root"
rc=$(run "$root23" --update build)
check "an inline body calling an internal export" 1 "$rc"
says "an inline body calling an internal export" "LibreSCRS::selftestKey calls LibreSCRS::detail::selftestGeneration(int), an internal export the allowlist does not name"
#     24: the control -- the callee is exported and public.
custom inline-public \
    "namespace LibreSCRS { $PUBLIC_FNS
inline int selftestKey(int x) { return selftestAlpha(x) + 1; } }" \
    "#include <LibreSCRS/Stub.h>
namespace LibreSCRS { $PUBLIC_DEFS }"
root24="$root"
rc=$(run "$root24" --update build)
check "control: an inline body calling public API" 0 "$rc"

# --- 25: the list only shrinks ----------------------------------------------
#     The case 9 fixture as a git repository whose base commit holds the list
#     with one entry. A second entry -- a real, imported internal export -- is
#     green without a base and red against it.
git_fixture() { git -C "$root9" -c user.name=selftest -c user.email=selftest@invalid \
    -c commit.gpgsign=false -c core.hooksPath=/dev/null "$@"; }
build_internal selftestInternal
command cp -f "$WORK/allow9.good" "$root9/ci/abi/5.x-internal-exports.txt"
git_fixture init -q
git_fixture add ci/abi/5.x-internal-exports.txt
git_fixture commit -q -m base
{
    printf 'namespace LibreSCRS {\n'
    printf 'int selftestAlpha(int x) { return x + 1; }\n'
    printf 'int selftestBeta(int x) { return x + 2; }\n'
    printf 'int selftestGamma(int x) { return x + 3; }\n'
    printf 'namespace Internal { int selftestInternal(int x) { return x + 4; } int selftestExtra(int x) { return x; } }\n'
    printf '}\n'
} > "$root9/stub.cpp"
g++ -shared -fPIC -o "$root9/build/lib/LibreSCRS/libLibreSCRS_Stub.so.5.0.0" "$root9/stub.cpp" 2>"$WORK/gcc.err" \
    || { echo "FATAL: could not rebuild the case 9 stub" >&2; exit 2; }
plugin "$root9" 'namespace LibreSCRS { namespace Internal { int selftestInternal(int x); int selftestExtra(int x); } }
int fixture_use() { return LibreSCRS::Internal::selftestInternal(1) + LibreSCRS::Internal::selftestExtra(2); }'
printf 'libLibreSCRS_Stub.so\tLibreSCRS::Internal::selftestExtra(int)\timported: libfixture-plugin\n' \
    >> "$root9/ci/abi/5.x-internal-exports.txt"
rc=$(run "$root9" --check build)
check "control: the added entry, judged without a base" 0 "$rc"
rc=$(run "$root9" --check --allowlist-base HEAD build)
check "an entry added against the base" 1 "$rc"
says "an entry added against the base" "ALLOWLIST GREW"
says "an entry added against the base" "LibreSCRS::Internal::selftestExtra(int)"

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$fails" = 0 ]

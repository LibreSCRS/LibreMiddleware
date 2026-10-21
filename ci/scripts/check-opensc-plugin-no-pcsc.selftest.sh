#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Selftest for check-opensc-plugin-no-pcsc.sh.
#
# Each case is a fixture build tree: a static archive where the plugin's copy of
# OpenSC sits and a shared library where the plugin sits, compiled here from a
# few lines of C so the test needs no OpenSC build. A PC/SC symbol in either
# image must be red, and so must every image the check cannot judge -- an empty
# tree, a symbol table without the CT-API driver, a host without nm.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
subject="$here/check-opensc-plugin-no-pcsc.sh"
[[ -f "$subject" ]] || { echo "missing subject: $subject" >&2; exit 2; }

cc="${CC:-cc}"
command -v "$cc" >/dev/null 2>&1 || { echo "no C compiler ($cc)" >&2; exit 2; }
command -v ar >/dev/null 2>&1 || { echo "no ar" >&2; exit 2; }

work="$(mktemp -d /var/tmp/check-opensc-plugin-no-pcsc-selftest.XXXXXX)"
trap 'rm -rf "$work"' EXIT

if [[ "$(uname -s)" == "Darwin" ]]; then
    shared_flag="-dynamiclib"
    module_name="libopensc-plugin.dylib"
    allow_undefined="-Wl,-undefined,dynamic_lookup"
else
    shared_flag="-shared"
    module_name="libopensc-plugin.so"
    allow_undefined="-Wl,--unresolved-symbols=ignore-all"
fi

fails=0
reds=0
cases=0

# image <dir> <archive-symbols> <module-symbols> -- a fixture build tree whose
# two images define the given functions (space-separated C identifiers).
image() {
    local dir="$1" a_syms="$2" m_syms="$3" s
    mkdir -p "$dir/thirdparty/opensc-plugin-install/lib" "$dir/plugins" "$dir/src"
    # One redirection per file: appending line by line reopens the file 20000
    # times for case_7, which takes minutes on macOS.
    for s in $a_syms; do printf 'int %s(void) { return 0; }\n' "$s"; done > "$dir/src/a.c"
    for s in $m_syms; do printf 'int %s(void) { return 1; }\n' "$s"; done > "$dir/src/m.c"
    "$cc" -c -fPIC -o "$dir/src/a.o" "$dir/src/a.c" \
        && ar rcs "$dir/thirdparty/opensc-plugin-install/lib/libopensc.a" "$dir/src/a.o" \
        && "$cc" $shared_flag -fPIC -o "$dir/plugins/$module_name" "$dir/src/m.c" \
        || { echo "fixture build failed in $dir" >&2; exit 2; }
}

run() { # run <name> <expected-rc> <build-dir> [red] [env...]
    local name="$1" want="$2" dir="$3" red="${4:-}" got
    shift 4 2>/dev/null || shift $#
    cases=$((cases + 1))
    env "$@" bash "$subject" "$dir" > "$work/out" 2>&1
    got=$?
    if [[ "$got" -eq "$want" ]]; then
        printf '  ok    %-60s rc=%s\n' "$name" "$got"
        [[ -n "$red" ]] && reds=$((reds + 1))
    else
        printf '  FAIL  %-60s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_1 -- the plugin's copy and the plugin as they should be.
image "$work/case_1" "ctapi_init sc_context_create" "ctapi_init create_card_plugin"
run "case_1 CT-API only in both images passes" 0 "$work/case_1" ""

# case_2 -- the copy the plugin is given was built with PC/SC.
image "$work/case_2" "ctapi_init SCardConnect" "ctapi_init create_card_plugin"
run "case_2 SCardConnect in the archive is reported" 1 "$work/case_2" red

# case_3 -- the plugin was linked against the PC/SC copy: OpenSC's own reader
# functions are in it and the CT-API driver is not.
image "$work/case_3" "ctapi_init" "pcsc_connect pcsc_detect_readers create_card_plugin"
run "case_3 pcsc_connect in the plugin is reported" 1 "$work/case_3" red

# case_4 -- no symbol of either kind: a stripped image reads like a clean one.
image "$work/case_4" "ctapi_init" "create_card_plugin"
run "case_4 a plugin without ctapi_init cannot be measured" 2 "$work/case_4" red

# case_5 -- a plugin linked straight against the PC/SC library shows the call
# as an undefined symbol, not a definition; the reader functions of the real
# copy are local ones. Both must be read.
mkdir -p "$work/case_5/src"
image "$work/case_5" "ctapi_init" "ctapi_init"
printf '%s\n' 'extern int SCardConnect(void);' \
    'static int pcsc_init(void) { return SCardConnect(); }' \
    'int (*ctapi_init_ref)(void) = pcsc_init;' > "$work/case_5/src/u.c"
"$cc" $shared_flag -fPIC $allow_undefined -o "$work/case_5/plugins/$module_name" "$work/case_5/src/u.c" \
    || { echo "fixture build failed in case_5" >&2; exit 2; }
run "case_5 an undefined SCardConnect and a local pcsc_init are reported" 1 "$work/case_5" red

# case_6 -- a defect in one image is reported as a defect even when the other
# image cannot be judged.
image "$work/case_6" "ctapi_init SCardConnect" "create_card_plugin"
run "case_6 a found defect outranks an unreadable image" 1 "$work/case_6" red

# case_7 -- a real plugin's symbol table runs to thousands of names, with
# ctapi_init early in it; reading it must not depend on how much of it is left
# unread once the answer is known. The fixture is a clean image, only large.
big="ctapi_init $(printf 'f%d ' $(seq 1 20000))"
image "$work/case_7" "$big" "$big"
run "case_7 a large clean symbol table passes" 0 "$work/case_7" ""

# case_8 -- an unbuilt tree.
mkdir -p "$work/case_8"
run "case_8 an empty build tree cannot be measured" 2 "$work/case_8" red

# case_9 -- a host without nm cannot read either image.
mkdir -p "$work/nonm"
ln -s "$(command -v bash)" "$work/nonm/bash"
run "case_9 no nm on PATH cannot be measured" 2 "$work/case_1" red PATH="$work/nonm"

if [[ "$fails" -eq 0 ]]; then
    echo "selftest: $cases cases, $reds red-proved"
    exit 0
fi
echo "check-opensc-plugin-no-pcsc selftest: $fails case(s) failed"
exit 1

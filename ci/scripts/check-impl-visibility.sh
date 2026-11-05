#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-impl-visibility.sh — nm-based guard against pimpl leak regression
#
# Guards against pimpl `struct Impl` symbols escaping the public shared
# libraries as extern-T (they must be hidden) AND against std-library
# template instantiations parameterised on internal `Impl` types leaking as W/V-binding weak symbols (vtable/typeinfo entries
# at DEFAULT visibility — GCC does NOT propagate the `LIBRESCRS_INTERNAL`
# attribute on `::Impl` to std-template instantiations because template-
# instantiation visibility is computed from the instantiation context, not
# the template arguments; `-fvisibility-inlines-hidden` does not override
# this).
#
# Runs after LM build; scans every binary artefact the build produced for:
#   1) T-binding (global text) symbols whose demangled name contains
#      `::Impl::`.
#   2) W/V-binding (weak / vague-linkage) symbols whose demangled name is a
#      `vtable for` / `typeinfo for` / `typeinfo name for` entry containing
#      `::Impl` as a word segment.
#
# Linux coverage: the six libLibreSCRS_*.so core libraries plus
# plugins/*.so.
# macOS coverage: the libLibreSCRS_*.dylib core libraries plus
# plugins/*.dylib.
#
# Fails the build if any leaking symbol is found.
#
# Why this matters now that the core libraries ship as .so:
#   - Two `.so`s each embedding a leaking `Impl` collide on these weak
#     symbols at load time.
#   - Exceptions thrown across the SO boundary carrying any leaking type
#     mis-behave — typeinfo identity depends on symbol interposition.
#   - `dynamic_cast<>` across the SO boundary fails.
#
# Portability: uses `nm -U` which is supported by both GNU binutils and
# BSD (macOS cctools) nm as the defined-only flag. `--defined-only` is
# GNU-only and would break the macOS CI runner.

set -euo pipefail

# Tool guard, before anything is measured. Every symbol pipeline below ends in
# `| grep ... || true`, so a host missing one of these tools produced an empty
# pipeline, satisfied every container-counting guard and printed a clean
# result. "I could not measure" is a third answer and must never be spelled
# the same way as "I measured and found nothing".
for tool in nm c++filt; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "FATAL: $tool not found on PATH — cannot judge Impl visibility" >&2
        exit 2
    fi
done

BUILD_DIR="${1:-build}"
if [[ ! -d "$BUILD_DIR" ]]; then
    echo "ERROR: build dir '$BUILD_DIR' not found" >&2
    exit 2
fi

# ── The PC/SC connection is defined in one image only ─────────────────────
# PCSCConnection holds process-wide PC/SC state, so exactly one shipped image
# may define it: libLibreSCRS_SmartCard, which exports it to everyone else.
# A private copy is invisible to every export check below -- it is a hidden,
# local text symbol -- so this pass reads every definition, whatever its
# visibility. Weak definitions are skipped: an inline accessor's out-of-line
# copy holds no state. A linked image may record such a copy as a local
# symbol all the same, which is why CI runs this on optimised builds, where
# the accessors are inlined.
#
# The same reasoning covers test executables that link
# LibreSCRS_SmartCard_PcscForTests: they define their own PC/SC entry points
# and compile the connection into themselves, so they must never open a real
# session through CardSession::open -- on macOS the library keeps calling its
# own copy of the connection, not theirs. That part reads the sources the
# repository tracks, not the build.
PCSC_CLASS='LibreSCRS::SmartCard::Internal::PCSCConnection::'
PCSC_STUB_TARGET='LibreSCRS_SmartCard_PcscForTests'
PCSC_REPO_ROOT="${LIBRESCRS_REPO_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}"

pcsc_images() {
    if [[ "$(uname -s)" == "Darwin" ]]; then
        find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -name 'libLibreSCRS_*.dylib' 2>/dev/null
        find "$BUILD_DIR/plugins" -maxdepth 2 -name '*.dylib' 2>/dev/null
    else
        find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -name 'libLibreSCRS_*.so' 2>/dev/null
        find "$BUILD_DIR/plugins" -maxdepth 2 -name '*.so' 2>/dev/null
    fi
}

# Demangled strong definitions of the connection's members in one image.
# The symbol table is read first and on its own, so an image nm cannot read
# fails the whole check instead of reading as an image without a copy.
pcsc_definitions() {
    local image="$1" table
    if [[ "$(uname -s)" == "Darwin" ]]; then
        if ! table=$(nm -m "$image" 2>&1); then
            echo "FATAL: nm cannot read $(basename "$image") -- cannot judge where PCSCConnection is defined" >&2
            printf '%s\n' "$table" | sed 's/^/    /' >&2
            return 2
        fi
        printf '%s\n' "$table" \
            | grep -v -e '(undefined)' -e ' weak ' \
            | awk '{ print $NF }' \
            | c++filt \
            | grep -F -- "$PCSC_CLASS" \
            | sort -u || true
    else
        if ! table=$(nm "$image" 2>&1); then
            echo "FATAL: nm cannot read $(basename "$image") -- cannot judge where PCSCConnection is defined" >&2
            printf '%s\n' "$table" | sed 's/^/    /' >&2
            return 2
        fi
        printf '%s\n' "$table" \
            | awk 'NF == 3 && ($2 == "T" || $2 == "t") { print $3 }' \
            | c++filt \
            | grep -F -- "$PCSC_CLASS" \
            | sort -u || true
    fi
}

# Prints "<dir> <target> <source>..." for every add_executable, and
# "LINK <target>" for every target_link_libraries naming the stub target, of
# one CMakeLists.txt. Comments are dropped; a command runs to its first `)`.
pcsc_cmake_commands() {
    awk -v want="$PCSC_STUB_TARGET" '
        { line = $0; sub(/#.*/, "", line); buf = buf " " line }
        END {
            s = buf
            while (match(s, /[A-Za-z_][A-Za-z0-9_]*[ \t]*\(/)) {
                name = tolower(substr(s, RSTART, RLENGTH))
                sub(/[ \t]*\($/, "", name)
                s = substr(s, RSTART + RLENGTH)
                close_at = index(s, ")")
                if (close_at == 0) break
                n = split(substr(s, 1, close_at - 1), raw, /[ \t]+/)
                s = substr(s, close_at + 1)
                k = 0
                for (i = 1; i <= n; i++) {
                    if (raw[i] == "") continue
                    gsub(/"/, "", raw[i])
                    tok[++k] = raw[i]
                }
                if (k == 0) continue
                if (name == "target_link_libraries" && tok[1] != want) {
                    for (i = 2; i <= k; i++) if (tok[i] == want) { print "LINK " tok[1]; break }
                }
                if (name == "add_executable") {
                    out = "EXE " tok[1]
                    for (i = 2; i <= k; i++) out = out " " tok[i]
                    print out
                }
            }
        }' "$1"
}

pcsc_violations=0

while IFS= read -r image; do
    [[ -n "$image" ]] || continue
    case "$(basename "$image")" in
        libLibreSCRS_SmartCard.*) continue ;;
    esac
    # An empty file holds no definition; the passes below report it as a file
    # that yielded no symbols.
    [[ -s "$image" ]] || continue
    defs_rc=0
    defs=$(pcsc_definitions "$image") || defs_rc=$?
    if [[ $defs_rc -ne 0 ]]; then
        exit 2
    fi
    while IFS= read -r symbol; do
        [[ -n "$symbol" ]] || continue
        echo "defines PCSCConnection outside the SmartCard library: $(basename "$image"): $symbol"
        pcsc_violations=$((pcsc_violations + 1))
    done <<< "$defs"
done < <(pcsc_images | while IFS= read -r found; do readlink -f "$found"; done | sort -u)

if ! pcsc_cmake_files=$(git -C "$PCSC_REPO_ROOT" ls-files -- 'CMakeLists.txt' '*/CMakeLists.txt' 2>/dev/null); then
    echo "FATAL: $PCSC_REPO_ROOT is not a git checkout -- cannot read which executables link $PCSC_STUB_TARGET" >&2
    exit 2
fi
pcsc_exes=""
pcsc_links=""
while IFS= read -r cmake_file; do
    [[ -n "$cmake_file" ]] || continue
    cmake_dir="$(dirname "$cmake_file")"
    while IFS= read -r entry; do
        case "$entry" in
            "LINK "*) pcsc_links+="${entry#LINK }"$'\n' ;;
            "EXE "*) pcsc_exes+="$cmake_dir ${entry#EXE }"$'\n' ;;
        esac
    done < <(pcsc_cmake_commands "$PCSC_REPO_ROOT/$cmake_file")
done <<< "$pcsc_cmake_files"

while IFS= read -r target; do
    [[ -n "$target" ]] || continue
    exe_line=$(printf '%s' "$pcsc_exes" | awk -v t="$target" '$2 == t' | head -n 1)
    if [[ -z "$exe_line" ]]; then
        echo "FATAL: $target links $PCSC_STUB_TARGET, but no add_executable($target ...) was found -- cannot judge its sources" >&2
        exit 2
    fi
    exe_dir=$(printf '%s\n' "$exe_line" | awk '{ print $1 }')
    for source in $(printf '%s\n' "$exe_line" | awk '{ for (i = 3; i <= NF; i++) print $i }'); do
        case "$source" in
            WIN32 | MACOSX_BUNDLE | EXCLUDE_FROM_ALL) continue ;;
        esac
        source="${source#\$\{CMAKE_CURRENT_SOURCE_DIR\}/}"
        if [[ "$source" == *'$'* || ! -f "$PCSC_REPO_ROOT/$exe_dir/$source" ]]; then
            echo "FATAL: $target lists '$source', which is not a file under $exe_dir -- cannot judge it" >&2
            exit 2
        fi
        if grep -q 'CardSession::open' "$PCSC_REPO_ROOT/$exe_dir/$source"; then
            echo "links $PCSC_STUB_TARGET and calls CardSession::open: $exe_dir/$source ($target)"
            pcsc_violations=$((pcsc_violations + 1))
        fi
    done
done <<< "$(printf '%s' "$pcsc_links" | sort -u)"

if [[ $pcsc_violations -gt 0 ]]; then
    echo
    echo "ERROR: $pcsc_violations place(s) hold a second PC/SC connection." >&2
    echo "  PCSCConnection is defined only in libLibreSCRS_SmartCard; link" >&2
    echo "  LibreSCRS::SmartCard instead of compiling or archiving it again." >&2
    exit 1
fi

# ── macOS: no shipped image reaches a card through PC/SC ──────────────────
# Apple PCSC.framework corrupts its in-process handle table when
# SCardReleaseContext overlaps any other PC/SC call; on macOS this library
# therefore reaches cards only through CryptoTokenKit. An image that imports
# an SCard function, loads PCSC.framework, or carries OpenSC's PC/SC reader
# driver (reader-pcsc.c: pcsc_init / pcsc_detect_readers, or its
# SCardEstablishContext name string from a dlopen'd PC/SC) brings PC/SC back.
# An image nm or otool cannot read fails the check: "could not measure" is
# not "clean".
if [[ "$(uname -s)" == "Darwin" ]]; then
    if ! command -v otool >/dev/null 2>&1; then
        echo "FATAL: otool not found on PATH -- cannot judge PC/SC on macOS" >&2
        exit 2
    fi
    mac_pcsc_violations=0
    mac_pcsc_images=0
    while IFS= read -r image; do
        [[ -n "$image" ]] || continue
        mac_pcsc_images=$((mac_pcsc_images + 1))
        name="$(basename "$image")"
        if ! table=$(nm -m "$image" 2>&1); then
            echo "FATAL: nm cannot read $name -- cannot judge PC/SC on macOS" >&2
            exit 2
        fi
        if ! loads=$(otool -L "$image" 2>&1); then
            echo "FATAL: otool cannot read $name -- cannot judge PC/SC on macOS" >&2
            exit 2
        fi
        while IFS= read -r sym; do
            [[ -n "$sym" ]] || continue
            echo "imports a PC/SC function on macOS: $name: $sym"
            mac_pcsc_violations=$((mac_pcsc_violations + 1))
        done < <(printf '%s\n' "$table" | grep -F '(undefined)' | grep -oE '_SCard[A-Za-z0-9_]+' | sort -u || true)
        if printf '%s\n' "$loads" | tail -n +2 | grep -q 'PCSC\.framework'; then
            echo "loads PCSC.framework: $name"
            mac_pcsc_violations=$((mac_pcsc_violations + 1))
        fi
        # The name string alone counts only where it is not the import's own
        # symbol name, which the first rule already reports.
        imports_establish=0
        printf '%s\n' "$table" | grep -F '(undefined)' | grep -qE '_SCardEstablishContext([[:space:]]|$)' && imports_establish=1
        if printf '%s\n' "$table" | grep -vF '(undefined)' | grep -qE '[[:space:]]_pcsc_(init|detect_readers)$' \
            || { [[ $imports_establish -eq 0 ]] && grep -aq 'SCardEstablishContext' "$image"; }; then
            echo "carries OpenSC's PC/SC reader driver: $name"
            mac_pcsc_violations=$((mac_pcsc_violations + 1))
        fi
    done < <({
        find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 -type f -name 'libLibreSCRS_*.dylib' 2>/dev/null
        find "$BUILD_DIR/plugins" -maxdepth 2 -type f -name '*.dylib' 2>/dev/null
    } | sort)
    if [[ $mac_pcsc_images -eq 0 ]]; then
        echo "FATAL: no macOS image found under $BUILD_DIR -- cannot judge PC/SC on macOS" >&2
        exit 2
    fi
    if [[ $mac_pcsc_violations -gt 0 ]]; then
        echo
        echo "ERROR: $mac_pcsc_violations PC/SC use(s) in macOS images; cards and readers go through CryptoTokenKit there." >&2
        exit 1
    fi
fi

PLATFORM="$(uname -s)"

if [[ "$PLATFORM" == "Darwin" ]]; then
    # Darwin Impl-visibility check covers the same surface as the Linux
    # branch: plugin dylibs PLUS the six LM core dylibs
    # (libLibreSCRS_*.dylib). The leak pattern is
    # identical — Mach-O `nm -gU` produces the same `T`/`W`/`V` letter
    # codes for global/weak/vague symbols, so the awk + c++filt + grep
    # pipeline transfers byte-for-byte.
    scan_dylib() {
        local dylib="$1"
        local syms t_leaks wv_leaks bad
        # One `nm` read per artefact, so the symbols this pass actually saw can
        # be counted. `2>/dev/null` stays on nm alone: it silences the expected
        # "no symbols" note, and an unreadable artefact is caught by the count.
        syms=$(nm -gU "$dylib" 2>/dev/null || true)
        if [[ -n "$syms" ]]; then
            symbols_seen=$((symbols_seen + $(printf '%s\n' "$syms" | wc -l)))
        fi

        t_leaks=$(printf '%s\n' "$syms" \
            | awk '$2 == "T" { print $3 }' \
            | c++filt \
            | grep -F '::Impl::' \
            | sort -u || true)

        wv_leaks=$(printf '%s\n' "$syms" \
            | awk '$2 == "W" || $2 == "V" { print $3 }' \
            | c++filt \
            | grep -E '^(vtable for|typeinfo (for|name for))\b.*::Impl\b' \
            | sort -u || true)

        bad="$t_leaks"
        if [[ -n "$wv_leaks" ]]; then
            [[ -n "$bad" ]] && bad+=$'\n'
            bad+="$wv_leaks"
        fi

        if [[ -n "$bad" ]]; then
            echo "LEAK in $(basename "$dylib"):"
            echo "$bad" | sed 's/^/  /'
            return 1
        fi
        return 0
    }

    leaks=0
    plugin_count=0
    core_count=0
    symbols_seen=0

    # Plugins.
    while IFS= read -r dylib; do
        plugin_count=$((plugin_count + 1))
        scan_dylib "$dylib" || leaks=$((leaks + 1))
    done < <(find "$BUILD_DIR/plugins" \
                  -maxdepth 2 -name '*.dylib' 2>/dev/null | sort)

    # LM core dylibs.
    while IFS= read -r dylib; do
        core_count=$((core_count + 1))
        scan_dylib "$dylib" || leaks=$((leaks + 1))
    done < <(find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 \
                  -name 'libLibreSCRS_*.dylib' 2>/dev/null | sort)

    if [[ $plugin_count -eq 0 && $core_count -eq 0 ]]; then
        echo "ERROR: no public dylibs found under '$BUILD_DIR/plugins/'" >&2
        echo "       or '$BUILD_DIR/lib/LibreSCRS/'." >&2
        echo "       Build broken or wrong build dir?" >&2
        exit 2
    fi

    # Counting containers is not counting symbols: $((plugin_count + core_count))
    # dylibs that yield no symbol at all mean the pass read nothing, whatever
    # the file names say.
    if [[ $symbols_seen -eq 0 ]]; then
        echo "ERROR: dylib pass read $((plugin_count + core_count)) file(s) and 0 symbols." >&2
        echo "       Nothing was measured; refusing to report a clean result." >&2
        exit 2
    fi

    if [[ $leaks -gt 0 ]]; then
        echo
        echo "ERROR: $leaks dylib(s) leaked pimpl Impl symbols." >&2
        echo "  Apply LIBRESCRS_INTERNAL to leaked Impl structs, or refactor" >&2
        echo "  std-template instantiations that embed internal Impl types." >&2
        exit 1
    fi

    echo "Impl visibility clean — $plugin_count plugin dylib(s) + $core_count LM core dylib(s) scanned, no leaks."
    exit 0
fi

# Linux branch — the plugin .so files and the six LM core .so files
# (Auth, Certificate, Plugin, Signing, SmartCard, Trust).
#
# The expected count is firm: LOUD failure on drift (renamed library, new
# public library added or removed) is preferred over silent green.
EXPECTED_CORE_SOS=6

# Helper: scan a single .so for ::Impl:: T-binding and vtable/typeinfo
# W/V-binding leaks. Prints "LEAK in ..." on stdout when any found.
# Returns 0 if clean, 1 if any leak was found.
#
# `nm -gU` mirrors the macOS branch:
#   -g = external symbols only (the ELF dynamic symbol table on stripped
#        .so; the combined static+dynamic export view otherwise)
#   -U = defined symbols only
# We deliberately do NOT use -D (dynamic-only, GNU-only) because the
# combined -gU view also catches unstripped local-but-default-visible
# symbols that some build configurations leave behind.
#
# No allow-list: on a linked shared object any of these names in the
# export table is a genuine visibility hole.
# `symbols_seen` is the caller's pass counter, added to here so each pass can
# tell "scanned N files, found no leak" apart from "scanned N files and read no
# symbol at all".
# The recorded public surface, one section per library, produced by
# abi-snapshot.sh. It is what the core-library pass compares against instead of
# matching a spelling. Overridable so the self-test can record a surface for its
# own fixture; unset, it is this checkout's.
ABI_BASELINE="${LIBRESCRS_ABI_BASELINE:-$(cd "$(dirname "$0")/.." && pwd)/abi/5.x-baseline.txt}"

# Prints the recorded T-binding symbols of one library, or fails when the
# surface does not record it at all. A library the baseline has never seen is
# "cannot judge": comparing against an empty set would call every symbol a leak,
# and comparing against nothing would call none of them one.
recorded_surface() {
    local name="$1"
    if [[ ! -r "$ABI_BASELINE" ]]; then
        echo "FATAL: no recorded ABI surface at $ABI_BASELINE — cannot judge what is public" >&2
        exit 2
    fi
    awk -v want="== ${name} ==" '
        $0 == want { inside = 1; next }
        /^== .* ==$/ { inside = 0 }
        inside && $0 !~ /^#/ && NF { print }
    ' "$ABI_BASELINE"
}

# The core-library rule, and the reason it is not a spelling any more.
#
# It used to match the demangled segment `::Impl::`, so renaming the pimpl to
# `Impl_` exported exactly the same implementation detail past every rule --
# `_` is a word character, and both `grep -F '::Impl::'` and `::Impl\b` are blind
# to it. `Priv`, `Detail` and every future spelling were free too. The rule is
# now the property: a T-binding symbol in a core library's dynamic export table
# that the recorded surface does not list fails, whatever it is called.
#
# Measured on this tree when the rule was written: the T sets of all seven core
# libraries match the recorded surface exactly, 0 extra and 0 missing.
#
# The W/V half below is still a spelling, and that is a known gap rather than an
# oversight: the recorded surface holds T-binding symbols only, while the seven
# libraries export 168 vague-linkage symbols it has never seen -- among them
# real implementation detail (LibreSCRS::SmartCard::Internal::PCSCScanProvider::*,
# LibreSCRS::Plugin::Internal::*, LibreSCRS::Internal::*). Recording them is an
# ABI-surface change, not a check change, so it is not done here.
# Weak, vague-linkage or unique exports (W, V, u) of an internal entity: a
# function or object under Internal:: or a project *_detail:: namespace, or a
# lambda's operator or guard. Such a symbol is an inline or template
# instantiation the linker exported because nothing hid it; the next library
# that instantiates the same name binds to whichever copy loaded first.
# Excluded: the vtable and typeinfo of a class the library exports on purpose
# (an exception type caught across a library boundary needs its typeinfo
# there). A standard-library entity such as std::__detail is not this rule's
# subject: foreign_weak_exports below refuses every one of them. Read from the
# dynamic table: what a consumer can bind to.
internal_weak_exports() {
    local so="$1"
    nm -D -U "$so" 2>/dev/null \
        | awk '$2 == "W" || $2 == "V" || $2 == "u" { print $3 }' \
        | c++filt \
        | grep -vE '^(vtable for|typeinfo for|typeinfo name for) ' \
        | grep -E '::Internal::|[A-Za-z0-9]_detail::|\{lambda' \
        | sort -u || true
}

# Weak, vague-linkage or unique exports (W, V, u) of an entity that is not a
# LibreSCRS one: a standard-library template instantiated on a LibreSCRS type
# (`std::__detail::_Map_base<..., LibreSCRS::<an enum>>::operator[]`,
# `vtable for std::_Sp_counted_ptr_inplace<LibreSCRS::Trust::TrustStore, ...>`).
# A demangled-name glob over `LibreSCRS::` exports those, because the namespace
# appears in their template arguments; every library and every consumer that
# instantiates the same template then binds to whichever copy loaded first.
# Judged on the MANGLED name: the entity -- after the vtable/typeinfo/VTT/
# construction-vtable, guard-variable, thunk and TLS prefixes, and through a
# local entity's enclosing function -- must be a nested name rooted in
# `9LibreSCRS`. The demangled form cannot say that: a template function's
# return type is printed before its name.
foreign_weak_exports() {
    local so="$1"
    nm -D -U "$so" 2>/dev/null \
        | awk '$2 == "W" || $2 == "V" || $2 == "u" { print $3 }' \
        | sed 's/@.*$//' \
        | grep -vE '^_Z(T[VISTCHW]|GV|Thn?[0-9]+_|Tvn?[0-9]+_n?[0-9]+_)?Z?N[rVKRO]*9LibreSCRS' \
        | c++filt \
        | sort -u || true
}

scan_core_so_against_surface() {
    local so="$1"
    local name syms dyn t_all surface extra wv_leaks bad
    name="$(basename "$so")"

    # Two reads, because the two halves ask different questions. The allowlist
    # compares against a surface abi-snapshot.sh recorded with `nm -D -U`, so it
    # has to read the same table: the DYNAMIC one, which is what a consumer can
    # link against. The combined `-gU` view also lists statically linked
    # internals that never reach the export table -- measured here: it reports
    # symbols in all seven libraries that `nm -D -U` does not, among them
    # vendored libresign internals. Comparing that view against a dynamic-table
    # surface would fail every library on the first run for no reason at all.
    syms=$(nm -gU "$so" 2>/dev/null || true)
    if [[ -n "$syms" ]]; then
        symbols_seen=$((symbols_seen + $(printf '%s\n' "$syms" | wc -l)))
    fi
    dyn=$(nm -D -U "$so" 2>/dev/null || true)

    surface=$(recorded_surface "$name")
    if [[ -z "$surface" ]]; then
        echo "FATAL: the recorded surface has no section for $name — cannot judge it" >&2
        exit 2
    fi

    # Internal:: and detail:: functions are exported for the in-tree plugins
    # and the test-helper archive and are not recorded as surface (see
    # abi-snapshot.sh, whose rule this is: the function's own name before the
    # first '(' decides, not its parameter types); the weak/vague ones among
    # them are judged below.
    t_all=$(printf '%s\n' "$dyn" \
        | awk '$2 == "T" { print $3 }' \
        | c++filt \
        | awk '{ name = $0; paren = index(name, "(")
                 if (paren > 0) name = substr(name, 1, paren - 1)
                 if (name !~ /::(Internal|detail)::/) print }' \
        | sort -u || true)

    extra=$(comm -23 <(printf '%s\n' "$t_all" | sed '/^$/d') \
                     <(printf '%s\n' "$surface" | sort -u) || true)

    wv_leaks=$(printf '%s\n' "$syms" \
        | awk '$2 == "W" || $2 == "V" { print $3 }' \
        | c++filt \
        | grep -E '^(vtable for|typeinfo (for|name for))\b.*::Impl[A-Za-z0-9_]*(::|$)' \
        | sort -u || true)

    bad="$extra"
    if [[ -n "$wv_leaks" ]]; then
        [[ -n "$bad" ]] && bad+=$'\n'
        bad+="$wv_leaks"
    fi
    local weak_internal
    weak_internal=$(internal_weak_exports "$so")
    if [[ -n "$weak_internal" ]]; then
        [[ -n "$bad" ]] && bad+=$'\n'
        bad+="$weak_internal"
    fi
    local weak_foreign
    weak_foreign=$(foreign_weak_exports "$so")
    if [[ -n "$weak_foreign" ]]; then
        [[ -n "$bad" ]] && bad+=$'\n'
        bad+="$weak_foreign"
    fi

    if [[ -n "$bad" ]]; then
        echo "LEAK in $name:"
        echo "$bad" | sed 's/^/  /'
        return 1
    fi
    return 0
}

scan_so_for_impl_leaks() {
    local so="$1"
    local syms t_leaks wv_leaks bad

    syms=$(nm -gU "$so" 2>/dev/null || true)
    if [[ -n "$syms" ]]; then
        symbols_seen=$((symbols_seen + $(printf '%s\n' "$syms" | wc -l)))
    fi

    # `::Impl` plus any identifier tail, not the literal `::Impl::`. `Impl_`,
    # `ImplData`, `Impl2` are the same decision by the author and the same hole
    # in the .so, and this pass judges plugins/*.so. The core pass moved from the spelling to the recorded surface in the same
    # change that left this one reading `::Impl::` literally.
    t_leaks=$(printf '%s\n' "$syms" \
        | awk '$2 == "T" { print $3 }' \
        | c++filt \
        | grep -E '::Impl[A-Za-z0-9_]*::' \
        | sort -u || true)

    wv_leaks=$(printf '%s\n' "$syms" \
        | awk '$2 == "W" || $2 == "V" { print $3 }' \
        | c++filt \
        | grep -E '^(vtable for|typeinfo (for|name for))\b.*::Impl[A-Za-z0-9_]*(::|$)' \
        | sort -u || true)

    bad="$t_leaks"
    if [[ -n "$wv_leaks" ]]; then
        [[ -n "$bad" ]] && bad+=$'\n'
        bad+="$wv_leaks"
    fi
    local weak_internal
    weak_internal=$(internal_weak_exports "$so")
    if [[ -n "$weak_internal" ]]; then
        [[ -n "$bad" ]] && bad+=$'\n'
        bad+="$weak_internal"
    fi

    if [[ -n "$bad" ]]; then
        echo "LEAK in $(basename "$so"):"
        echo "$bad" | sed 's/^/  /'
        return 1
    fi
    return 0
}

# LM core .so scan. LIBRESCRS_INTERNAL on Impl structs is honored by GCC at
# .so link-edit, so ANY ::Impl:: T-binding or vtable/typeinfo over Impl
# reaching the export table is a real visibility hole.
core_leaks=0
core_sos_scanned=0
symbols_seen=0
while IFS= read -r so; do
    core_sos_scanned=$((core_sos_scanned + 1))
    scan_core_so_against_surface "$so" || core_leaks=$((core_leaks + 1))
done < <(find "$BUILD_DIR/lib/LibreSCRS" \
              -maxdepth 1 -name 'libLibreSCRS_*.so' 2>/dev/null | sort)

if [[ $core_sos_scanned -ne $EXPECTED_CORE_SOS ]]; then
    echo "ERROR: expected $EXPECTED_CORE_SOS LM core .so file(s) under" >&2
    echo "       '$BUILD_DIR/lib/LibreSCRS/', found $core_sos_scanned." >&2
    echo "       Build broken, wrong dir, or LM core library set changed?" >&2
    exit 2
fi

if [[ $symbols_seen -eq 0 ]]; then
    echo "ERROR: LM core .so pass read $core_sos_scanned file(s) and 0 symbols." >&2
    echo "       Nothing was measured; refusing to report a clean result." >&2
    exit 2
fi

if [[ $core_leaks -gt 0 ]]; then
    echo
    echo "ERROR: $core_leaks LM core .so file(s) export something the recorded" >&2
    echo "       surface does not list." >&2
    echo "  - A new public symbol: add it to ci/abi/5.x-baseline.txt in the" >&2
    echo "    same change, so the addition is visible as an ABI change." >&2
    echo "  - Implementation detail: apply LIBRESCRS_INTERNAL to it. Its" >&2
    echo "    spelling does not matter -- Impl, Impl_, Priv, Detail all fail." >&2
    echo "  - A standard-library template on a LibreSCRS type: the export" >&2
    echo "    version script must not reach it (cmake/librescrs-public-exports.map)." >&2
    exit 1
fi

echo "LM core .so files match the recorded surface — $core_sos_scanned scanned."

# Plugin .so scan. The plugins have no recorded surface, so this pass reads
# the spelling: a new ::Impl:: T-binding or `vtable for ...::Impl` W/V-binding
# can slip into a plugin TU at any time (e.g. a refactor that exposes an
# internal handle by value across an exported plugin entry point).

so_leaks=0
sos_scanned=0
symbols_seen=0
while IFS= read -r so; do
    sos_scanned=$((sos_scanned + 1))
    scan_so_for_impl_leaks "$so" || so_leaks=$((so_leaks + 1))
done < <(find "$BUILD_DIR/plugins" \
              -maxdepth 2 -name '*.so' 2>/dev/null | sort)

if [[ $sos_scanned -eq 0 ]]; then
    echo "ERROR: no public .so files found under '$BUILD_DIR/plugins/'." >&2
    echo "       Build broken or wrong build dir?" >&2
    exit 2
fi

if [[ $symbols_seen -eq 0 ]]; then
    echo "ERROR: plugin .so pass read $sos_scanned file(s) and 0 symbols." >&2
    echo "       Nothing was measured; refusing to report a clean result." >&2
    exit 2
fi

if [[ $so_leaks -gt 0 ]]; then
    echo
    echo "ERROR: $so_leaks .so file(s) leaked pimpl Impl symbols." >&2
    echo "  Apply LIBRESCRS_INTERNAL to leaked Impl structs, or refactor" >&2
    echo "  std-template instantiations that embed internal Impl types." >&2
    exit 1
fi

echo "Plugin .so files clean — $sos_scanned scanned."
echo "Impl visibility clean — $((core_sos_scanned + sos_scanned)) .so file(s), no leaks."

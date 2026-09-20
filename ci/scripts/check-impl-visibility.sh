#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# check-impl-visibility.sh — nm-based guard against pimpl leak regression
#
# Guards against pimpl `struct Impl` symbols escaping public static archives
# as extern-T (they must be static/local or, under shared-library, hidden)
# AND against std-library template instantiations parameterised on internal
# `Impl` types leaking as W/V-binding weak symbols (vtable/typeinfo entries
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
# Linux coverage: libLibreSCRS_*.a archives (static builds) or the seven
# libLibreSCRS_*.so core libraries (shared builds), plus plugins/*.so and
# lib/pkcs11/*.so in either config.
# macOS coverage: the libLibreSCRS_*.dylib core libraries in shared builds,
# plus lib/pkcs11/*.dylib and plugins/*.dylib (Apple Clang enforces
# visibility at link-edit, so the static-archive level is not informative on
# macOS — see note below).
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
#
# Why the archive scan stays, even though no consumer static-links LM
# today: LibreCelik's main line links the shared libraries, the agent
# client branch dropped LM entirely, LibreKDE is LM-free, and LibreLinux
# consumes an installed shared LM. But LibreCelik pulls LM in through
# FetchContent, and that path builds LM with the default
# BUILD_SHARED_LIBS=OFF unless the consumer overrides it — which produces
# exactly these archives. Static consumption therefore remains a
# supported configuration and keeps its gate.
#
# Scope note: archive glob currently matches only `libLibreSCRS_*.a`.
# Other archives (libSmartCard.a, libCardPlugin.a, libEMRTD.a, etc.)
# are not yet renamed; widen and bump EXPECTED_ARCHIVES when they are.
#
# ── Allow-lists ───────────────────────────────────────────────────────
# Four blocks, ALL of them scoped to a single named archive and applied
# ONLY to the static-archive pass. Two are T-binding (a real function
# symbol at default visibility), two are W/V-binding (vague-linkage
# vtable/typeinfo over a std template instantiated on an Impl type).
#
#   T-binding, libLibreSCRS_Trust.a — TrustStoreService::Impl::runWorker.
#     GCC does not propagate LIBRESCRS_INTERNAL from the class to its
#     static-member symbols, and the attribute is a no-op on the function
#     declaration in this position. Hiding it the other way — moving the
#     worker into an anonymous namespace — would mean breaking up the
#     private nested type it operates on.
#
#   T-binding, libLibreSCRS_SmartCard.a — MonitorService::Impl:: members.
#     Same GCC behaviour, but anonymous-namespace is not merely awkward
#     here, it is impossible: Impl lives in an LM-internal header
#     (LibreSCRS_internal/SmartCard/MonitorServiceImpl.h) that the
#     production TU and the LibreSCRS_SmartCard_TestHelpers archive both
#     include, so the definition must have external linkage.
#
#   W/V-binding, libLibreSCRS_Trust.a — the inplace-deleter vtable and
#     typeinfo for std::shared_ptr<TrustStoreService::Impl>.
#   W/V-binding, libLibreSCRS_Auth.a — the same for
#     std::shared_ptr<CancelToken::Impl>.
#     Shared-pimpl ownership is part of the public semantics in both
#     cases (TrustStoreService's async generation-counter observer;
#     CancelSource and CancelToken sharing Impl through token()), so
#     these instantiations are not going away.
#
# All four are emitted WEAK HIDDEN or link-edit-hidden in their own
# object files and the linker strips them from every exported dynamic
# symbol table. That is what makes them .a-level residuals rather than
# real leaks — and it is why the .so scan below carries NO allow-list at
# all: on a linked shared object any of these names appearing in the
# export table would be a genuine visibility hole. The .so side is
# already at its end state; the allow-lists exist only because a static
# archive shows the linker's input rather than its output.

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

# Platform-specific visibility semantics for static archives:
#
#   Linux ELF (GCC):
#     `__attribute__((visibility("hidden")))` propagates through to the
#     static archive — `nm` reports hidden symbols as 't' (lowercase,
#     local), so the T-binding scan over libLibreSCRS_*.a naturally skips
#     them. The .a-level scan below is the canonical Linux gate.
#
#   macOS Mach-O (Apple Clang):
#     The same attribute is enforced at LINK-EDIT time (when the linker
#     creates the dylib), NOT at the static archive level. `nm` on a .a
#     always reports defined globals at full visibility regardless of
#     the source-level attribute. The canonical macOS check is therefore
#     against the linked dylibs (lib/pkcs11/*.dylib, plugins/*.dylib) —
#     once the linker emits them, the export table is what users see.
#
# The two branches below converge on the same intent (no `::Impl::`
# T-binding, no vtable/typeinfo over `::Impl` types), with platform-
# appropriate scan targets.

PLATFORM="$(uname -s)"

if [[ "$PLATFORM" == "Darwin" ]]; then
    # Darwin Impl-visibility check covers the same surface as the Linux
    # branch: plugin/pkcs11 dylibs PLUS, in shared-instance builds, the seven
    # LM core dylibs (libLibreSCRS_*.dylib). The leak pattern is
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

    # Plugins + standalone PKCS#11 module (present in both STATIC and
    # SHARED LM modes — they're plugin .dylib regardless).
    while IFS= read -r dylib; do
        plugin_count=$((plugin_count + 1))
        scan_dylib "$dylib" || leaks=$((leaks + 1))
    done < <(find "$BUILD_DIR/lib/pkcs11" "$BUILD_DIR/plugins" \
                  -maxdepth 2 -name '*.dylib' 2>/dev/null | sort)

    # LM core dylibs — present only when LIBREMIDDLEWARE_BUILD_SHARED=ON.
    # Detect by probing for the SmartCard module's SOVERSION'd dylib.
    if [[ -f "$BUILD_DIR/lib/LibreSCRS/libLibreSCRS_SmartCard.dylib" ]]; then
        while IFS= read -r dylib; do
            core_count=$((core_count + 1))
            scan_dylib "$dylib" || leaks=$((leaks + 1))
        done < <(find "$BUILD_DIR/lib/LibreSCRS" -maxdepth 1 \
                      -name 'libLibreSCRS_*.dylib' 2>/dev/null | sort)
    fi

    if [[ $plugin_count -eq 0 && $core_count -eq 0 ]]; then
        echo "ERROR: no public dylibs found under '$BUILD_DIR/lib/pkcs11/'," >&2
        echo "       '$BUILD_DIR/plugins/', or '$BUILD_DIR/lib/LibreSCRS/'." >&2
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

# The recorded residuals of the static-archive pass, and the rule that makes
# them mortal. Each row names an archive, a demangled prefix and a reason; a row
# whose prefix matches nothing in the archives that were actually scanned fails,
# so an exemption cannot outlive what it excused. Rows are only judged when the
# archive pass ran at all -- in a shared build no archive is scanned and every
# row would read as stale.
RESIDUALS_FILE="${LIBRESCRS_IMPL_RESIDUALS:-$(cd "$(dirname "$0")/.." && pwd)/impl-visibility-residuals.txt}"
declare -a RESIDUAL_ARCHIVE=() RESIDUAL_PREFIX=() RESIDUAL_REASON=()
declare -a RESIDUAL_USED=()

load_residuals() {
    [[ -r "$RESIDUALS_FILE" ]] || {
        echo "FATAL: no residuals file at $RESIDUALS_FILE — cannot judge which archive symbols are allowed" >&2
        exit 2
    }
    local line archive prefix reason
    while IFS= read -r line; do
        [[ -z "${line// /}" || "$line" =~ ^[[:space:]]*# ]] && continue
        archive=$(printf '%s' "$line" | sed -E 's/[[:space:]]{2,}.*$//')
        prefix=$(printf '%s' "$line" | sed -E 's/^[^[:space:]]+[[:space:]]{2,}//; s/[[:space:]]{2,}.*$//')
        reason=$(printf '%s' "$line" | sed -E 's/^[^[:space:]]+[[:space:]]{2,}[^\n]*?//' )
        reason=$(printf '%s' "$line" | awk -F'[[:space:]][[:space:]]+' '{ $1=""; $2=""; sub(/^ +/, ""); print }' | sed -E 's/^[[:space:]]+//')
        if [[ -z "$archive" || -z "$prefix" || -z "${reason// /}" ]]; then
            echo "FATAL: $RESIDUALS_FILE: a row without all three fields cannot be judged: $line" >&2
            exit 2
        fi
        RESIDUAL_ARCHIVE+=("$archive")
        RESIDUAL_PREFIX+=("$prefix")
        RESIDUAL_REASON+=("$reason")
        RESIDUAL_USED+=(0)
    done < "$RESIDUALS_FILE"
    if [[ ${#RESIDUAL_ARCHIVE[@]} -eq 0 ]]; then
        echo "FATAL: $RESIDUALS_FILE records no row — refusing to judge with an empty allowance list" >&2
        exit 2
    fi
}

# Drops the rows' symbols from one list, marking each row that matched.
apply_residuals() {
    local archive="$1" list="$2" i
    [[ -z "$list" ]] && { printf '%s' ""; return 0; }
    for i in "${!RESIDUAL_ARCHIVE[@]}"; do
        [[ "${RESIDUAL_ARCHIVE[$i]}" == "$archive" ]] || continue
        if printf '%s\n' "$list" | grep -qF -- "${RESIDUAL_PREFIX[$i]}"; then
            RESIDUAL_USED[$i]=1
            list=$(printf '%s\n' "$list" | grep -vF -- "${RESIDUAL_PREFIX[$i]}" || true)
        fi
    done
    printf '%s' "$list"
}

report_stale_residuals() {
    local i stale=0
    for i in "${!RESIDUAL_ARCHIVE[@]}"; do
        [[ "${RESIDUAL_USED[$i]}" == 1 ]] && continue
        echo "STALE: $RESIDUALS_FILE row $((i + 1)) allows '${RESIDUAL_PREFIX[$i]}' in ${RESIDUAL_ARCHIVE[$i]}," >&2
        echo "       and nothing there carries it any more. Delete the row." >&2
        stale=$((stale + 1))
    done
    [[ $stale -eq 0 ]]
}

# Linux branch — scan static archives (GCC visibility propagates to .a),
# the plugin/pkcs11 .so files, AND, in shared-library builds, the LM core
# .so files (Auth, Certificate, Plugin, SecureChannel, Signing, SmartCard,
# Trust).
#
# Build-config detection: presence of $BUILD_DIR/lib/LibreSCRS/
# libLibreSCRS_SmartCard.so indicates LIBREMIDDLEWARE_BUILD_SHARED=ON.
# In that mode the seven LM core libraries are .so files; no public
# static archive ships separately (the SessionRegistry / AttachHook
# `Pkcs11Inject` archive was deleted with the legacy C-ABI manual-attach
# surface). Static mode emits the same seven libraries as .a archives.
#
# The expected counts are firm: LOUD failure on drift (renamed archive,
# new public library added or removed) is preferred over silent green.

if [[ -f "$BUILD_DIR/lib/LibreSCRS/libLibreSCRS_SmartCard.so" ]]; then
    BUILD_CONFIG=shared
    EXPECTED_ARCHIVES=0
    EXPECTED_CORE_SOS=7     # Auth, Certificate, Plugin, SecureChannel,
                            # Signing, SmartCard, Trust
else
    BUILD_CONFIG=static
    EXPECTED_ARCHIVES=7     # Auth, Certificate, Plugin, SecureChannel,
                            # Signing, SmartCard, Trust
    EXPECTED_CORE_SOS=0
fi

load_residuals

leaks=0
archives_scanned=0
archive_symbols_seen=0
while IFS= read -r archive; do
    archives_scanned=$((archives_scanned + 1))

    # One `nm` read per archive; both passes below filter this text. The count
    # is what turns "found no leak" apart from "read nothing".
    archive_syms=$(nm -U "$archive" 2>/dev/null || true)
    if [[ -n "$archive_syms" ]]; then
        archive_symbols_seen=$((archive_symbols_seen + $(printf '%s\n' "$archive_syms" | wc -l)))
    fi

    # Pass 1 — T-binding (global text, default-visible) whose demangled
    # name contains the `::Impl::` namespace segment. The `::Impl::`
    # match must run AFTER c++filt — mangled names encode `Impl` as
    # `4Impl` via Itanium ABI, so filtering before demangle would never
    # match.
    t_leaks=$(printf '%s\n' "$archive_syms" \
        | awk '$2 == "T" { print $3 }' \
        | c++filt \
        | grep -F '::Impl::' \
        | sort -u || true)

    # ALLOW-LIST: TrustStoreService::Impl::runWorker is a static member of an
    # internal-tagged class that GCC currently emits at default visibility
    # (LIBRESCRS_INTERNAL on the class doesn't propagate to static-member
    # symbols, and applying the attribute on the function declaration is a
    # no-op in this position on GCC 13/14). Refactoring to anonymous-namespace
    # would require breaking the private nested type. Accepted as a
    # static-archive-only residual (.a archives don't expose this symbol
    # at link time); re-evaluate before any .so migration that exposes it.
    t_leaks=$(apply_residuals "$(basename "$archive")" "$t_leaks")

    # ALLOW-LIST: MonitorService::Impl member functions
    # (snapshotCallbacks, dispatch, diffReadersAndDispatch). Same GCC
    # pattern as TrustStoreService::Impl::runWorker above. Impl is declared
    # in an LM-internal header (lib/SmartCard/include/LibreSCRS_internal/
    # SmartCard/MonitorServiceImpl.h) consumed by both the production
    # translation unit AND the LibreSCRS_SmartCard_TestHelpers archive —
    # so anonymous-namespace is not an option. The linker hides these
    # symbols at .so link-edit time on GCC; confirmed absent from every
    # build/plugins/*.so and from every build-shared/**/*.so.

    # Pass 2 — W/V-binding (weak / vague-linkage) vtable/typeinfo
    # entries containing `::Impl` as a word segment. These are emitted
    # with DEFAULT visibility for std-template instantiations
    # parameterised over internal types (e.g. std::async, std::future,
    # std::shared_ptr inplace, std::thread state), and would export
    # from a shared library despite the `LIBRESCRS_INTERNAL` attribute
    # on the `Impl` struct itself.
    wv_leaks=$(printf '%s\n' "$archive_syms" \
        | awk '$2 == "W" || $2 == "V" { print $3 }' \
        | c++filt \
        | grep -E '^(vtable for|typeinfo (for|name for))\b.*::Impl\b' \
        | sort -u || true)

    # ALLOW-LIST: std::shared_ptr<TrustStoreService::Impl> inplace-deleter
    # vtable/typeinfo. The shared-pimpl pattern is a deliberate design
    # choice (async tasks must be able to extend Impl lifetime). Static
    # archives don't surface these symbols to the linker. See header note
    # on known residuals for the SO-migration follow-up.
    wv_leaks=$(apply_residuals "$(basename "$archive")" "$wv_leaks")

    # ALLOW-LIST: std::shared_ptr<CancelToken::Impl> inplace-deleter
    # vtable/typeinfo. Same rationale as Trust above — CancelSource and
    # CancelToken share Impl ownership by design (token() copies hand out
    # observers; the source keeps the writable side). Symbols are emitted
    # WEAK HIDDEN in CancelToken.cpp.o and are absent from every linked
    # .so / .dylib; .a-level residual only.

    bad="$t_leaks"
    if [[ -n "$wv_leaks" ]]; then
        [[ -n "$bad" ]] && bad+=$'\n'
        bad+="$wv_leaks"
    fi

    if [[ -n "$bad" ]]; then
        echo "LEAK in $(basename "$archive"):"
        echo "$bad" | sed 's/^/  /'
        leaks=$((leaks + 1))
    fi
done < <(find "$BUILD_DIR" -name 'libLibreSCRS_*.a' | sort)

if [[ $archives_scanned -ne $EXPECTED_ARCHIVES ]]; then
    echo "ERROR: expected $EXPECTED_ARCHIVES libLibreSCRS_*.a archive(s) under '$BUILD_DIR'" >&2
    echo "       ($BUILD_CONFIG build), found $archives_scanned." >&2
    echo "       Build broken, wrong dir, or archive set changed?" >&2
    echo "       If the archive set changed intentionally, update the" >&2
    echo "       expected counts in $(basename "$0")." >&2
    exit 2
fi

if [[ $archives_scanned -gt 0 && $archive_symbols_seen -eq 0 ]]; then
    echo "ERROR: static-archive pass read $archives_scanned archive(s) and 0 symbols." >&2
    echo "       Nothing was measured; refusing to report a clean result." >&2
    exit 2
fi

if [[ $leaks -gt 0 ]]; then
    echo
    echo "ERROR: $leaks archive(s) leaked pimpl Impl symbols." >&2
    echo "  - T-binding leaks: apply LIBRESCRS_INTERNAL to each Impl struct." >&2
    echo "  - W/V-binding leaks: refactor to avoid std-template instantiations" >&2
    echo "    that embed internal Impl types (e.g. move async work into a free" >&2
    echo "    function or anonymous-namespace type instead of a lambda inside" >&2
    echo "    Impl)." >&2
    exit 1
fi

if [[ $archives_scanned -gt 0 ]] && ! report_stale_residuals; then
    echo "ERROR: an allowance in $(basename "$RESIDUALS_FILE") excuses a symbol that is gone." >&2
    exit 1
fi

echo "Static archives clean — $archives_scanned scanned ($BUILD_CONFIG build)."

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
# No allow-list: the .a-level Impl residuals (Trust, Auth, SmartCard)
# are emitted WEAK HIDDEN in their TUs and the linker strips them from
# every .so dynamic export table — so their presence in any .so here
# is a real leak.
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

    t_all=$(printf '%s\n' "$dyn" \
        | awk '$2 == "T" { print $3 }' \
        | c++filt \
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
    # in the .so, and this pass judges plugins/*.so and lib/pkcs11/*.so --
    # including the module Firefox, Thunderbird, gpgsm and Kleopatra load. The
    # core pass moved from the spelling to the recorded surface in the same
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

    if [[ -n "$bad" ]]; then
        echo "LEAK in $(basename "$so"):"
        echo "$bad" | sed 's/^/  /'
        return 1
    fi
    return 0
}

# LM core .so scan (shared build only). The core libraries become exported
# .so files in shared builds; LIBRESCRS_INTERNAL on Impl structs is honored
# by GCC at .so link-edit, so ANY ::Impl:: T-binding or vtable/typeinfo
# over Impl reaching the export table is a real visibility hole.
core_leaks=0
core_sos_scanned=0
symbols_seen=0
if [[ $EXPECTED_CORE_SOS -gt 0 ]]; then
    while IFS= read -r so; do
        core_sos_scanned=$((core_sos_scanned + 1))
        scan_core_so_against_surface "$so" || core_leaks=$((core_leaks + 1))
    done < <(find "$BUILD_DIR/lib/LibreSCRS" \
                  -maxdepth 1 -name 'libLibreSCRS_*.so' 2>/dev/null | sort)

    if [[ $core_sos_scanned -ne $EXPECTED_CORE_SOS ]]; then
        echo "ERROR: expected $EXPECTED_CORE_SOS LM core .so file(s) under" >&2
        echo "       '$BUILD_DIR/lib/LibreSCRS/' (shared build), found" >&2
        echo "       $core_sos_scanned. Build broken, wrong dir, or LM" >&2
        echo "       core library set changed?" >&2
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
        exit 1
    fi

    echo "LM core .so files match the recorded surface — $core_sos_scanned scanned."
fi

# Plugin/pkcs11 .so scan (always — these are .so in both build configs).
#
# Why archive-cleanness is not sufficient: the .a-level allow-listed
# residuals (shared_ptr<TrustStoreService::Impl> +
# shared_ptr<CancelToken::Impl> vague-linkage entries, plus the
# MonitorService::Impl member functions) are emitted WEAK HIDDEN in their
# TUs; the linker strips them from the exported dynamic symbol table of
# every .so. But a *new* ::Impl:: T-binding or `vtable for ...::Impl`
# W/V-binding could slip into a plugin TU at any time (e.g. a refactor
# that exposes an internal handle by value across an exported plugin
# entry point). The pkcs11 module is even more sensitive — it is the
# single .so consumed by every external host (Firefox, Thunderbird,
# gpgsm, Kleopatra, Evolution via p11-kit) and must export only the
# PKCS#11 v3 C_* entry points.

so_leaks=0
sos_scanned=0
symbols_seen=0
while IFS= read -r so; do
    sos_scanned=$((sos_scanned + 1))
    scan_so_for_impl_leaks "$so" || so_leaks=$((so_leaks + 1))
done < <(find "$BUILD_DIR/lib/pkcs11" "$BUILD_DIR/plugins" \
              -maxdepth 2 -name '*.so' 2>/dev/null | sort)

if [[ $sos_scanned -eq 0 ]]; then
    echo "ERROR: no public .so files found under '$BUILD_DIR/lib/pkcs11/' or" >&2
    echo "       '$BUILD_DIR/plugins/'. Build broken or wrong build dir?" >&2
    exit 2
fi

if [[ $symbols_seen -eq 0 ]]; then
    echo "ERROR: plugin/pkcs11 .so pass read $sos_scanned file(s) and 0 symbols." >&2
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

echo "Plugin/pkcs11 .so files clean — $sos_scanned scanned."
echo "Impl visibility clean — $archives_scanned archive(s) + $((core_sos_scanned + sos_scanned)) .so file(s), no leaks."

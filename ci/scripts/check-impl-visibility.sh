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
# Runs after LM build; scans both static archives AND the linked plugin
# / pkcs11 shared libraries for:
#   1) T-binding (global text) symbols whose demangled name contains
#      `::Impl::`.
#   2) W/V-binding (weak / vague-linkage) symbols whose demangled name is a
#      `vtable for` / `typeinfo for` / `typeinfo name for` entry containing
#      `::Impl` as a word segment.
#
# Linux coverage: libLibreSCRS_*.a archives + plugins/*.so + lib/pkcs11/*.so.
# macOS coverage: lib/pkcs11/*.dylib + plugins/*.dylib (Apple Clang enforces
# visibility at link-edit, so the static-archive level is not informative on
# macOS — see note below).
#
# Fails the build if any leaking symbol is found.
#
# Why this matters under the planned .so transition:
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
# Scope note: archive glob currently matches only `libLibreSCRS_*.a`.
# Other archives (libSmartCard.a, libCardPlugin.a, libEMRTD.a, etc.)
# are not yet renamed; widen and bump EXPECTED_ARCHIVES when they are.
#
# Known residuals (allow-listed below): vague-linkage leaks from
# `std::shared_ptr<TrustStoreService::Impl>` and
# `std::shared_ptr<CancelToken::Impl>` template instantiations.
# Shared-pimpl ownership is part of the public semantics in both cases
# (TrustStoreService's async generation-counter observer; CancelSource
# and CancelToken sharing Impl through token()). Symbols are emitted
# WEAK HIDDEN in their respective .cpp.o files and are absent from every
# linked .so on Linux + every linked dylib on macOS — confirmed residual
# is .a-level only.

set -euo pipefail

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
    leaks=0
    binaries_scanned=0
    while IFS= read -r dylib; do
        binaries_scanned=$((binaries_scanned + 1))

        t_leaks=$(nm -gU "$dylib" 2>/dev/null \
            | awk '$2 == "T" { print $3 }' \
            | c++filt 2>/dev/null \
            | grep -F '::Impl::' \
            | sort -u || true)

        wv_leaks=$(nm -gU "$dylib" 2>/dev/null \
            | awk '$2 == "W" || $2 == "V" { print $3 }' \
            | c++filt 2>/dev/null \
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
            leaks=$((leaks + 1))
        fi
    done < <(find "$BUILD_DIR/lib/pkcs11" "$BUILD_DIR/plugins" \
                  -maxdepth 2 -name '*.dylib' 2>/dev/null | sort)

    if [[ $binaries_scanned -eq 0 ]]; then
        echo "ERROR: no public dylibs found under '$BUILD_DIR/lib/pkcs11/' or" >&2
        echo "       '$BUILD_DIR/plugins/'. Build broken or wrong build dir?" >&2
        exit 2
    fi

    if [[ $leaks -gt 0 ]]; then
        echo
        echo "ERROR: $leaks dylib(s) leaked pimpl Impl symbols." >&2
        echo "  Apply LIBRESCRS_INTERNAL to leaked Impl structs, or refactor" >&2
        echo "  std-template instantiations that embed internal Impl types." >&2
        exit 1
    fi

    echo "Impl visibility clean — $binaries_scanned dylib(s) scanned, no leaks."
    exit 0
fi

# Linux branch — scan static archives (GCC visibility propagates to .a).

# Exact count of public libLibreSCRS_*.a archives expected. Fails LOUD
# (not silently green) when the set drifts — e.g., when an archive is
# renamed, or a new public library is added or removed.
EXPECTED_ARCHIVES=8

leaks=0
archives_scanned=0
while IFS= read -r archive; do
    archives_scanned=$((archives_scanned + 1))

    # Pass 1 — T-binding (global text, default-visible) whose demangled
    # name contains the `::Impl::` namespace segment. The `::Impl::`
    # match must run AFTER c++filt — mangled names encode `Impl` as
    # `4Impl` via Itanium ABI, so filtering before demangle would never
    # match.
    t_leaks=$(nm -U "$archive" 2>/dev/null \
        | awk '$2 == "T" { print $3 }' \
        | c++filt 2>/dev/null \
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
    if [[ "$(basename "$archive")" == "libLibreSCRS_Trust.a" ]]; then
        t_leaks=$(printf '%s\n' "$t_leaks" \
            | grep -v '^LibreSCRS::Trust::TrustStoreService::Impl::runWorker' \
            || true)
    fi

    # ALLOW-LIST: MonitorService::Impl member functions
    # (snapshotCallbacks, dispatch, diffReadersAndDispatch). Same GCC
    # pattern as TrustStoreService::Impl::runWorker above. Impl is declared
    # in an LM-internal header (lib/SmartCard/include/LibreSCRS_internal/
    # SmartCard/MonitorServiceImpl.h) consumed by both the production
    # translation unit AND the LibreSCRS_SmartCard_TestHelpers archive —
    # so anonymous-namespace is not an option. The linker hides these
    # symbols at .so link-edit time on GCC; confirmed absent from every
    # build/plugins/*.so and from every build-shared/**/*.so.
    if [[ "$(basename "$archive")" == "libLibreSCRS_SmartCard.a" ]]; then
        t_leaks=$(printf '%s\n' "$t_leaks" \
            | grep -v '^LibreSCRS::SmartCard::MonitorService::Impl::' \
            || true)
    fi

    # Pass 2 — W/V-binding (weak / vague-linkage) vtable/typeinfo
    # entries containing `::Impl` as a word segment. These are emitted
    # with DEFAULT visibility for std-template instantiations
    # parameterised over internal types (e.g. std::async, std::future,
    # std::shared_ptr inplace, std::thread state), and would export
    # from a shared library despite the `LIBRESCRS_INTERNAL` attribute
    # on the `Impl` struct itself.
    wv_leaks=$(nm -U "$archive" 2>/dev/null \
        | awk '$2 == "W" || $2 == "V" { print $3 }' \
        | c++filt 2>/dev/null \
        | grep -E '^(vtable for|typeinfo (for|name for))\b.*::Impl\b' \
        | sort -u || true)

    # ALLOW-LIST: std::shared_ptr<TrustStoreService::Impl> inplace-deleter
    # vtable/typeinfo. The shared-pimpl pattern is a deliberate design
    # choice (async tasks must be able to extend Impl lifetime). Static
    # archives don't surface these symbols to the linker. See header note
    # on known residuals for the SO-migration follow-up.
    if [[ "$(basename "$archive")" == "libLibreSCRS_Trust.a" ]]; then
        wv_leaks=$(printf '%s\n' "$wv_leaks" \
            | grep -vE '_Sp_counted_ptr_inplace<LibreSCRS::Trust::TrustStoreService::Impl' \
            || true)
    fi

    # ALLOW-LIST: std::shared_ptr<CancelToken::Impl> inplace-deleter
    # vtable/typeinfo. Same rationale as Trust above — CancelSource and
    # CancelToken share Impl ownership by design (token() copies hand out
    # observers; the source keeps the writable side). Symbols are emitted
    # WEAK HIDDEN in CancelToken.cpp.o and are absent from every linked
    # .so / .dylib; .a-level residual only.
    if [[ "$(basename "$archive")" == "libLibreSCRS_Auth.a" ]]; then
        wv_leaks=$(printf '%s\n' "$wv_leaks" \
            | grep -vE '_Sp_counted_ptr_inplace<LibreSCRS::CancelToken::Impl' \
            || true)
    fi

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
    echo "ERROR: expected $EXPECTED_ARCHIVES libLibreSCRS_*.a archive(s) under '$BUILD_DIR'," >&2
    echo "       found $archives_scanned. Build broken, wrong dir, or archive set changed?" >&2
    echo "       If the archive set changed intentionally, update" >&2
    echo "       EXPECTED_ARCHIVES in $(basename "$0")." >&2
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

echo "Static archives clean — $archives_scanned scanned."

# Linux .so scan — plugin MODULE shared libraries and the librescrs-pkcs11.so
# dynamic library. Parity with the macOS dylib scan above.
#
# Why archive-cleanness is not sufficient: the .a-level allow-listed
# residuals (shared_ptr<TrustStoreService::Impl> +
# shared_ptr<CancelToken::Impl> vague-linkage entries, plus the
# MonitorService::Impl member functions) are emitted WEAK HIDDEN in their
# TUs; the linker strips them from the exported dynamic symbol table of
# every .so. But a *new* `::Impl::` T-binding or `vtable for ...::Impl`
# W/V-binding could slip into a plugin TU at any time (e.g. a refactor
# that exposes an internal handle by value across an exported plugin
# entry point). The pkcs11 module is even more sensitive — it is the
# single .so consumed by every external host (Firefox, Thunderbird,
# gpgsm, Kleopatra, etc.) and must export only the PKCS#11 v3 C_*
# entry points.
#
# `nm -gU` here mirrors the macOS branch:
#   -g = external symbols only (the ELF dynamic symbol table on stripped
#        .so; the combined static+dynamic export view otherwise)
#   -U = defined symbols only
# We deliberately do NOT use -D (dynamic-only, GNU-only) because the
# combined -gU view also catches unstripped local-but-default-visible
# symbols that some build configurations leave behind.
#
# No allow-list: the Trust/Auth/SmartCard Impl residuals are
# .a-archive-only by design — their presence in any .so is a real leak.

so_leaks=0
sos_scanned=0
while IFS= read -r so; do
    sos_scanned=$((sos_scanned + 1))

    t_leaks=$(nm -gU "$so" 2>/dev/null \
        | awk '$2 == "T" { print $3 }' \
        | c++filt 2>/dev/null \
        | grep -F '::Impl::' \
        | sort -u || true)

    wv_leaks=$(nm -gU "$so" 2>/dev/null \
        | awk '$2 == "W" || $2 == "V" { print $3 }' \
        | c++filt 2>/dev/null \
        | grep -E '^(vtable for|typeinfo (for|name for))\b.*::Impl\b' \
        | sort -u || true)

    bad="$t_leaks"
    if [[ -n "$wv_leaks" ]]; then
        [[ -n "$bad" ]] && bad+=$'\n'
        bad+="$wv_leaks"
    fi

    if [[ -n "$bad" ]]; then
        echo "LEAK in $(basename "$so"):"
        echo "$bad" | sed 's/^/  /'
        so_leaks=$((so_leaks + 1))
    fi
done < <(find "$BUILD_DIR/lib/pkcs11" "$BUILD_DIR/plugins" \
              -maxdepth 2 -name '*.so' 2>/dev/null | sort)

if [[ $sos_scanned -eq 0 ]]; then
    echo "ERROR: no public .so files found under '$BUILD_DIR/lib/pkcs11/' or" >&2
    echo "       '$BUILD_DIR/plugins/'. Build broken or wrong build dir?" >&2
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
echo "Impl visibility clean — $archives_scanned archive(s) + $sos_scanned .so file(s), no leaks."

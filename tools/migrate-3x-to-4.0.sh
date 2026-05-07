#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# migrate-3x-to-4.0.sh — assist SDK consumers migrating from LibreSCRS 3.x
# to 4.0.
#
# Applies the mechanical sed-rules for the renames + namespace moves that
# happened during the 4.0 hardening cycle. Manual changes are still
# required for the architectural shifts (e.g. SigningService now takes
# TrustStoreService); those are flagged with WARN comments inserted at
# call sites.
#
# Usage:
#   tools/migrate-3x-to-4.0.sh [--dry-run] <path-to-consumer-source-tree>
#
# --dry-run prints the rules that would apply without touching files.
#
# What this script DOES handle (mechanical):
#   - <LibreSCRS/Signing/TrustConfig.h> -> <LibreSCRS/Trust/TrustConfig.h>
#   - LibreSCRS::Signing::TrustConfig -> LibreSCRS::Trust::TrustConfig
#   - LibreSCRS::Auth::LocalizedText -> LibreSCRS::LocalizedText
#   - <LibreSCRS/Auth/LocalizedText.h> -> <LibreSCRS/LocalizedText.h>
#   - includes for SigningService::trustStore() callers (flagged with WARN)
#   - Tier 4 Phase F (CC6) — Service-suffix consistency:
#       AutoReader              -> AutoReaderService
#       CardPluginRegistry      -> CardPluginService
#       LibreSCRS::SmartCard::Monitor -> LibreSCRS::SmartCard::MonitorService
#       <LibreSCRS/Plugin/AutoReader.h>           -> <LibreSCRS/Plugin/AutoReaderService.h>
#       <LibreSCRS/Plugin/CardPluginRegistry.h>   -> <LibreSCRS/Plugin/CardPluginService.h>
#       <LibreSCRS/SmartCard/Monitor.h>           -> <LibreSCRS/SmartCard/MonitorService.h>
#
# What this script DOES NOT handle (manual):
#   - SigningService(TrustConfig, TsaProvider) -> SigningService(
#       TrustStoreService::create(...), TsaProvider)
#     The constructor shape changed; consumers must obtain a TrustStoreService
#     via its create() factory and pass it in. Inserts a WARN comment at the
#     ctor call site.
#   - signingService->trustStore() -> trustService->trustStore()
#     The accessor moved; flagged in-place.
#   - CardPlugin::canHandle signature: now takes std::span<const std::uint8_t>.
#     Code that called canHandle(std::vector<...>) Just Works (implicit conv);
#     code that took a typedef may need updating.
#   - PIN: now Secure::String through CredentialResult. QString consumers
#     should switch to Secure::String for PIN material; flagged.

set -eu

DRY_RUN=0
TARGET=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help)
            sed -n '2,/^$/p' "$0" | sed 's/^# \?//'
            exit 0
            ;;
        *) TARGET="$1"; shift ;;
    esac
done

if [[ -z "$TARGET" ]]; then
    echo "ERROR: target tree not specified" >&2
    echo "Usage: $0 [--dry-run] <path-to-consumer-source-tree>" >&2
    exit 2
fi
if [[ ! -d "$TARGET" ]]; then
    echo "ERROR: target tree '$TARGET' is not a directory" >&2
    exit 2
fi

# Mechanical sed rules. Each rule is "match-pattern => replacement".
# We use Perl regex semantics for portability across GNU and BSD sed.
declare -a RULES=(
    # --- Header path renames ---
    's|<LibreSCRS/Signing/TrustConfig\.h>|<LibreSCRS/Trust/TrustConfig.h>|g'
    's|<LibreSCRS/Auth/LocalizedText\.h>|<LibreSCRS/LocalizedText.h>|g'
    # Tier 4 Phase F (CC6): Service-suffix consistency
    's|<LibreSCRS/Plugin/AutoReader\.h>|<LibreSCRS/Plugin/AutoReaderService.h>|g'
    's|<LibreSCRS/Plugin/CardPluginRegistry\.h>|<LibreSCRS/Plugin/CardPluginService.h>|g'
    's|<LibreSCRS/SmartCard/Monitor\.h>|<LibreSCRS/SmartCard/MonitorService.h>|g'

    # --- Namespace moves ---
    's|LibreSCRS::Signing::TrustConfig\b|LibreSCRS::Trust::TrustConfig|g'
    's|LibreSCRS::Auth::LocalizedText\b|LibreSCRS::LocalizedText|g'
    's|Signing::TrustConfig\b|Trust::TrustConfig|g'
    's|Auth::LocalizedText\b|LocalizedText|g'

    # --- Tier 4 Phase F (CC6): Service-suffix consistency ---
    # AutoReader / CardPluginRegistry are unique names — safe word-boundary swap.
    's|\bAutoReader\b|AutoReaderService|g'
    's|\bCardPluginRegistry\b|CardPluginService|g'
    # SmartCard::Monitor only — leaves the unrelated 3.x internal `smartcard::Monitor`
    # alone (no public 4.0 surface uses that name; consumers that do are
    # already on a private path).
    's|LibreSCRS::SmartCard::Monitor\b|LibreSCRS::SmartCard::MonitorService|g'
)

# Files in scope: C++ sources and headers. We deliberately avoid binary
# files, build outputs, and the migrate script itself.
mapfile -t files < <(find "$TARGET" \
    \( -name 'build' -o -name '_deps' -o -name '.git' -o -name 'thirdparty' \) -prune -o \
    -type f \
    \( -name '*.cpp' -o -name '*.h' -o -name '*.hpp' -o -name '*.cc' -o -name '*.cxx' -o -name '*.hxx' \) \
    -print)

if [[ ${#files[@]} -eq 0 ]]; then
    echo "No C++ source files found under '$TARGET'."
    exit 0
fi

if [[ $DRY_RUN -eq 1 ]]; then
    echo "Dry run — would scan ${#files[@]} files under '$TARGET' with these rules:"
    for r in "${RULES[@]}"; do
        echo "  $r"
    done
    echo
    echo "Files that would be touched (sample of first 20 with at least one matching rule):"
    matched=0
    for f in "${files[@]}"; do
        for r in "${RULES[@]}"; do
            # Extract pattern from sed expression for grep test.
            pattern=$(printf '%s' "$r" | sed -E 's|^s\|([^|]+)\|.*|\1|')
            if grep -qE "$pattern" "$f" 2>/dev/null; then
                echo "  $f"
                matched=$((matched + 1))
                break
            fi
        done
        [[ $matched -ge 20 ]] && break
    done
    exit 0
fi

# Apply each rule across every file.
echo "Applying ${#RULES[@]} mechanical migration rules to ${#files[@]} files..."
touched=0
for f in "${files[@]}"; do
    cp "$f" "$f.librescrs-bak"
    for r in "${RULES[@]}"; do
        sed -i.tmp -E "$r" "$f"
        rm -f "$f.tmp"
    done
    if cmp -s "$f" "$f.librescrs-bak"; then
        rm -f "$f.librescrs-bak"
    else
        rm -f "$f.librescrs-bak"
        touched=$((touched + 1))
    fi
done

# Surface manual-review touchpoints. We do NOT modify these — only flag
# them so the author can decide.
echo
echo "$touched file(s) modified by mechanical rules."
echo
echo "Manual review required for the following 4.0 architectural shifts:"
echo

flag_pattern='\bSigningService\s*\(\s*Trust(Config)?\s*'
hits=$(grep -rEln "$flag_pattern" "$TARGET" 2>/dev/null \
    --include='*.cpp' --include='*.h' --include='*.hpp' --include='*.cc' \
    --include='*.cxx' --include='*.hxx' || true)
if [[ -n "$hits" ]]; then
    echo "  - SigningService ctor: now takes a shared_ptr<TrustStoreService>"
    echo "    instead of TrustConfig. Obtain via TrustStoreService::create()."
    echo "    Files to inspect:"
    printf '      %s\n' $hits
    echo
fi

trustStore_hits=$(grep -rEln '\.trustStore\s*\(\s*\)|->trustStore\s*\(\s*\)' "$TARGET" 2>/dev/null \
    --include='*.cpp' --include='*.h' --include='*.hpp' --include='*.cc' \
    --include='*.cxx' --include='*.hxx' || true)
if [[ -n "$trustStore_hits" ]]; then
    echo "  - .trustStore() / ->trustStore() accessor moved from SigningService"
    echo "    to TrustStoreService. Inspect callers:"
    printf '      %s\n' $trustStore_hits
    echo
fi

opensession_hits=$(grep -rEln '\.session\.has_value\(\)|->session\.has_value\(\)|\.error\.has_value\(\)|->error\.has_value\(\)|OpenSessionResult\b' "$TARGET" 2>/dev/null \
    --include='*.cpp' --include='*.h' --include='*.hpp' --include='*.cc' \
    --include='*.cxx' --include='*.hxx' || true)
if [[ -n "$opensession_hits" ]]; then
    echo "  - CardSession::open now returns std::expected<CardSession, OpenError>"
    echo "    (the variant intermediary OpenSessionResult is removed). Replace"
    echo "    sessionResult.session.has_value() / std::get_if<CardSession>(&r)"
    echo "    patterns with the std::expected idiom: 'if (!result) {...}; auto&"
    echo "    s = *result;'. See the dev-guide page expected-result-handling"
    echo "    for the canonical short-circuit / and_then / kind-dispatch idioms:"
    echo "    https://librescrs.github.io/developer-guide/sdk-reference/expected-result-handling/"
    echo "    Inspect callers:"
    printf '      %s\n' $opensession_hits
    echo
fi

parsed_cert_hits=$(grep -rEln 'std::optional\s*<\s*ParsedCertificate\s*>|optional<ParsedCertificate>' "$TARGET" 2>/dev/null \
    --include='*.cpp' --include='*.h' --include='*.hpp' --include='*.cc' \
    --include='*.cxx' --include='*.hxx' || true)
if [[ -n "$parsed_cert_hits" ]]; then
    echo "  - ParsedCertificate::parse now returns std::expected<ParsedCertificate,"
    echo "    ParseError> instead of std::optional<ParsedCertificate>. Replace"
    echo "    .has_value() / *opt patterns with the std::expected idiom:"
    echo "    'if (!result) { handle(result.error()); ... }'. See the dev-guide page"
    echo "    expected-result-handling for canonical idioms:"
    echo "    https://librescrs.github.io/developer-guide/sdk-reference/expected-result-handling/"
    echo "    Inspect callers:"
    printf '      %s\n' $parsed_cert_hits
    echo
fi

trust_service_hits=$(grep -rEln 'std::shared_ptr\s*<\s*(LibreSCRS::Trust::)?TrustStoreService\s*>|shared_ptr<TrustStoreService>' "$TARGET" 2>/dev/null \
    --include='*.cpp' --include='*.h' --include='*.hpp' --include='*.cc' \
    --include='*.cxx' --include='*.hxx' || true)
if [[ -n "$trust_service_hits" ]]; then
    echo "  - TrustStoreService::create now returns std::expected<"
    echo "    std::shared_ptr<TrustStoreService>, TrustStoreError> instead of a"
    echo "    bare std::shared_ptr where nullptr signalled failure. Replace"
    echo "    'if (!ptr) {...}' nullptr-on-fail checks with the std::expected"
    echo "    idiom: 'if (!result) { handle(result.error()); }; auto svc = *result;'."
    echo "    See the dev-guide page expected-result-handling for canonical idioms:"
    echo "    https://librescrs.github.io/developer-guide/sdk-reference/expected-result-handling/"
    echo "    Inspect callers (note: only the create() return type changed; passing"
    echo "    shared_ptr<TrustStoreService> as a dependency is still correct):"
    printf '      %s\n' $trust_service_hits
    echo
fi

pin_qstring=$(grep -rEln '\bQString\b.*\bpin\b|\bpin\b.*\bQString\b' "$TARGET" 2>/dev/null \
    --include='*.cpp' --include='*.h' --include='*.hpp' --include='*.cc' \
    --include='*.cxx' --include='*.hxx' || true)
if [[ -n "$pin_qstring" ]]; then
    echo "  - PIN material now flows through LibreSCRS::Secure::String for"
    echo "    cleansing-on-destruction. Switch QString PIN holders to"
    echo "    Secure::String at the boundary. Files with 'pin' + 'QString'"
    echo "    co-occurrences:"
    printf '      %s\n' $pin_qstring
    echo
fi

cat <<EOF
See the full SDK migration guide at:
  https://librescrs.github.io/dev-guide/migration-3x-to-4.0/

After resolving the manual touchpoints above, rebuild + test against
LibreSCRS 4.0 headers. The ABI-stability snapshot at
ci/abi/4.0-baseline.txt is the source of truth for the 4.0 surface.
EOF

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "signing_service.h"

#include <LibreSCRS/Trust/TrustStore.h> // for LibreSCRS::Trust::TrustAnchor

#include <functional>
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace libresign {

class TlCache;
class TlSignatureVerifier;
class SigningKey;

class NativeSigningService : public SigningService
{
public:
    bool configure(const TrustConfig& config) override;

    bool isAvailable() const override;

    SigningResult sign(const SigningRequest& request, SigningKey& key) override;

    SigningResult appendSigner(const SigningRequest& request, std::span<const uint8_t> priorSignature,
                               std::span<const uint8_t> originalDocument, SigningKey& key) override;

    /// True if configure() was called (even if some TLs failed — degraded mode).
    bool isConfigured() const
    {
        return configured;
    }

    /// Callback invoked when @ref loadTrustList successfully fetches+verifies+
    /// parses a Trusted List and extracts trust anchors from it. The Signing-
    /// side bridge (LibreSCRS::Signing::SigningService) binds a lambda that
    /// merges the emitted anchors into its public TrustStore via the
    /// LM-internal access shim. Inverting the call direction (libresign
    /// emits, the bridge merges) keeps libresign free of any direct call
    /// into LibreSCRS_Trust internals — critical for the SHARED-build
    /// target graph since it removes the libresign → LibreSCRS_Trust link
    /// edge, breaking the static-only-tolerated cycle.
    using AnchorEmitter = std::function<void(std::vector<LibreSCRS::Trust::TrustAnchor>, std::string)>;
    void setAnchorEmitter(AnchorEmitter emit)
    {
        anchorEmitter = std::move(emit);
    }

private:
    TrustConfig trustConfig;
    std::map<std::string, std::vector<uint8_t>> lotlDerivedCerts; // URL -> signing cert DER

    // DER of every CA cert extracted from the configured Trusted List(s),
    // retained at configure() time. Long-term (B-LT/B-LTA) signing uses these
    // as the candidate issuer set to complete the card's signer chain — cards
    // typically carry only the leaf, so the issuing CA must come from the TL.
    std::vector<std::vector<uint8_t>> tlAnchorCerts;
    bool configured = false;
    /// Set once @ref loadLazyTrustLists has run for the current
    /// @ref configure cycle, and cleared by that call. The two must stay in
    /// step: configure() empties @ref tlAnchorCerts, so a flag that outlived
    /// it would leave the next long-term sign with no anchors and no attempt
    /// to fetch any.
    bool lazyListsLoaded = false;
    AnchorEmitter anchorEmitter;

    void loadTrustList(const std::string& url, bool isLotl, TlCache& cache, TlSignatureVerifier& verifier, int depth);

    /// Fetch every configured Trusted List that @ref configure deliberately
    /// left alone, i.e. every source whose @c eager flag is false.
    ///
    /// This is the deferred half of that flag, and the only caller is
    /// @ref completeLongTermChain — the one place that knows a level actually
    /// needs an anchor, which is precisely the condition
    /// @c TrustedListSource::eager documents for the deferred fetch. A source
    /// that fails here leaves the anchor set short and the caller's chain gate
    /// refuses, which is the correct outcome and carries its own message.
    /// Idempotent within one @ref configure cycle.
    void loadLazyTrustLists();

    /// Complete the key's certificate chain from the configured Trusted-List
    /// anchors for long-term (B-LT/B-LTA) levels, then install it via
    /// @ref SigningKey::setResolvedChain. Shared by @ref sign and
    /// @ref appendSigner so the fail-closed policy stays single-sourced.
    /// At B_LT and above this is also where any deferred Trusted List is
    /// fetched — see @ref loadLazyTrustLists.
    /// @returns std::nullopt when there is nothing to do (level below B_LT or no
    ///          TL configured) or the chain completed successfully; a populated
    ///          @ref SigningResult (fail-closed failure) when the issuing CA was
    ///          not found in the configured Trusted List(s).
    std::optional<SigningResult> completeLongTermChain(SigningKey& key, SignatureLevel level);

    /// Reject an expired signer certificate unless the request carries the
    /// user-consent opt-in. Shared by @ref sign and @ref appendSigner for the
    /// same reason as @ref completeLongTermChain: adding a signer to an
    /// already-signed document is signing, and @ref sign redirects several
    /// formats into @ref appendSigner itself, so a check that lived on only
    /// one entry point would be dropped by the service's own dispatch.
    /// @returns std::nullopt when the signer is acceptable (in date, opted in,
    ///          or carrying no readable certificate to judge); a populated
    ///          @ref SigningResult carrying @ref SignFailureKind::PolicyViolation
    ///          when an expired signer is used without the opt-in.
    std::optional<SigningResult> enforceSignerCertPolicy(SigningKey& key, const SigningRequest& request);
};

} // namespace libresign

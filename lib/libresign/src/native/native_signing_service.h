// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "signing_service.h"

#include <LibreSCRS/Trust/TrustStore.h> // for LibreSCRS::Trust::TrustAnchor

#include <functional>
#include <optional>
#include <utility>
#include <vector>

namespace libresign {

class SigningKey;

class NativeSigningService : public SigningService
{
public:
    bool configure(const TrustConfig& config) override;

    SigningResult sign(const SigningRequest& request, SigningKey& key) override;

    /// Called when this signature has loaded the Trusted Lists of a phase
    /// completely: with @c false once configure() loaded every eager list,
    /// with @c true once a signature level made it load every deferred one.
    /// Not called when one of them failed. The Signing-side bridge
    /// (LibreSCRS::Signing::SigningService) has the trust store service
    /// adopt those lists, which it reads from the cache directory the two
    /// share, so the anchors reach the public TrustStore through the service
    /// that owns it -- one download, and no second wait when the network is
    /// down. libresign never touches that store.
    using TrustedListsLoadedHook = std::function<void(bool deferred)>;
    void setTrustedListsLoadedHook(TrustedListsLoadedHook hook)
    {
        trustedListsLoadedHook = std::move(hook);
    }

private:
    TrustConfig trustConfig;

    // DER of every CA cert extracted from the configured Trusted List(s),
    // retained at configure() time. Long-term (B-LT/B-LTA) signing uses these
    // as the candidate issuer set to complete the card's signer chain — cards
    // typically carry only the leaf, so the issuing CA must come from the TL.
    std::vector<std::vector<uint8_t>> tlAnchorCerts;
    // DER of the qualified time-stamping services among them: the only TL
    // anchors a time-stamp token's signer may chain to.
    std::vector<std::vector<uint8_t>> tlTimestampAnchors;
    /// Set once @ref loadLazyTrustLists has run for the current
    /// @ref configure cycle, and cleared by that call. The two must stay in
    /// step: configure() empties @ref tlAnchorCerts, so a flag that outlived
    /// it would leave the next long-term sign with no anchors and no attempt
    /// to fetch any.
    bool lazyListsLoaded = false;
    TrustedListsLoadedHook trustedListsLoadedHook;

    /// Fetch, verify and take the anchors of @p entry and, for a List of
    /// Trusted Lists, of every list it points to. A list that fails is
    /// logged and skipped; returns whether @p entry itself loaded, and sets
    /// @p complete when every list of the walk did.
    bool loadTrustList(const TrustedListEntry& entry, bool& complete);

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
    /// @ref SigningKey::setResolvedChain. Run by @ref sign for a fresh
    /// signature and for one added to a signed document alike.
    /// At B_LT and above this is also where any deferred Trusted List is
    /// fetched — see @ref loadLazyTrustLists.
    /// @returns std::nullopt when there is nothing to do (level below B_LT or no
    ///          TL configured) or the chain completed successfully; a populated
    ///          @ref SigningResult (fail-closed failure) when the issuing CA was
    ///          not found in the configured Trusted List(s).
    std::optional<SigningResult> completeLongTermChain(SigningKey& key, SignatureLevel level);

    /// Reject an expired signer certificate unless the request carries the
    /// user-consent opt-in. Run by @ref sign before it dispatches, so adding a
    /// signer to an already-signed document is held to it as much as a fresh
    /// signature is.
    /// @returns std::nullopt when the signer is acceptable (in date, opted in,
    ///          or carrying no readable certificate to judge); a populated
    ///          @ref SigningResult carrying @ref SignFailureKind::PolicyViolation
    ///          when an expired signer is used without the opt-in.
    std::optional<SigningResult> enforceSignerCertPolicy(SigningKey& key, const SigningRequest& request);

    /// The format modules' TSA configuration for @p request: its URL and
    /// credentials, the host's CRL/OCSP posture, and the anchors a time-stamp
    /// token must chain to — the Trusted Lists' time-stamping services and,
    /// unless the host opted out, the system store. A deferred list is
    /// fetched only when a token verifies against neither, so a level that
    /// time-stamps through an authority the system store already vouches for
    /// fetches nothing.
    TSAConfig timestampConfig(const SigningRequest& request);
};

} // namespace libresign

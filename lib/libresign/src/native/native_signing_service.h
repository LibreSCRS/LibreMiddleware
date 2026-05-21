// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "signing_service.h"
#include "native/pkcs11_module_manager.h"

#include <LibreSCRS/Trust/TrustStore.h> // for LibreSCRS::Trust::TrustAnchor

#include <functional>
#include <map>
#include <utility>
#include <vector>

namespace libresign {

class TlCache;
class TlSignatureVerifier;

class NativeSigningService : public SigningService
{
public:
    bool configure(const TrustConfig& config) override;

    SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath,
                       const LibreSCRS::Secure::Buffer& pin, const std::string& keyAlias, const std::string& readerName,
                       std::shared_ptr<LibreSCRS::SmartCard::CardSession> sharedSession = nullptr) override;

    SigningResult appendSigner(const SigningRequest& request, std::span<const uint8_t> priorSignature,
                               std::span<const uint8_t> originalDocument, const LibreSCRS::Secure::Buffer& pin,
                               const std::string& pkcs11Module, const std::string& keyAlias,
                               const std::string& readerName,
                               std::shared_ptr<LibreSCRS::SmartCard::CardSession> sharedSession = nullptr) override;

    bool isAvailable() const override;

    /// True if configure() was called (even if some TLs failed — degraded mode).
    bool isConfigured() const
    {
        return configured;
    }

    /// True if all eager TLs loaded successfully (no degraded mode).
    bool isFullyConfigured() const
    {
        return configured && fullyConfigured;
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
    bool configured = false;
    bool fullyConfigured = false;
    AnchorEmitter anchorEmitter;

    /// Process-shared loaded-module cache. Tokens constructed from
    /// @ref sign / @ref appendSigner acquire a handle into this manager
    /// so a single C_Initialize spans every sign call against the same
    /// PKCS#11 module path. Destroyed AFTER any in-flight Token via
    /// natural member-destruction order (Tokens are stack-scoped in
    /// the sign methods and unwind before this service's dtor runs).
    Pkcs11ModuleManager moduleManager;

    void loadTrustList(const std::string& url, bool isLotl, TlCache& cache, TlSignatureVerifier& verifier, int depth);
};

} // namespace libresign

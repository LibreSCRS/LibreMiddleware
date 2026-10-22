// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "dss/dss_service_manager.h"
#include "signing_service.h"

#include <memory>
#include <string>

namespace libresign {

class HttpClient;

/// DSS-based signing service. Primarily used in tests and the cross-backend
/// validation oracle (DSSValidationClient); the production signing path is
/// NativeSigningService (Backend::Native). DSS remains a supported backend
/// for parity verification against the eSig DSS Java reference.
class DSSSigningService : public SigningService
{
public:
    DSSSigningService();
    explicit DSSSigningService(DSSServiceManager& serviceManager);
    ~DSSSigningService() override;

    // Configure trust lists and revocation sources on the DSS service.
    // Idempotent: skips if the same config was already sent.
    bool configure(const TrustConfig& config) override;

    bool isConfigured() const;

    bool isAvailable() const override;

    /// @brief Sign through the Java oracle with @p key, which the caller holds:
    ///        the oracle returns the bytes to sign, @p key signs them here, and
    ///        the oracle builds the document around the signature. No PIN and
    ///        no key reaches the oracle.
    ///
    /// RSA keys only, over SHA-256: an ECDSA key returns
    /// @ref SignFailureKind::EngineError.
    /// A key's own failure (a refused PIN, a blocked card) keeps its kind.
    SigningResult sign(const SigningRequest& request, SigningKey& key) override;

    /// @brief Not supported — returns EngineError. The oracle is a
    ///        cross-verification reference; adding a signer is the native
    ///        engine's.
    SigningResult appendSigner(const SigningRequest& request, std::span<const uint8_t> priorSignature,
                               std::span<const uint8_t> originalDocument, SigningKey& key) override;

private:
    DSSServiceManager& manager();

    DSSServiceManager* serviceManagerRef = nullptr;
    std::unique_ptr<DSSServiceManager> ownedManager;
    std::unique_ptr<HttpClient> httpClient;
    bool trustConfigured = false;
};

} // namespace libresign

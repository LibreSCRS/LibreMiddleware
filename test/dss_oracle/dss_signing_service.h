// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "dss_oracle/dss_service_manager.h"
#include "signing_service.h"

#include <memory>
#include <string>

namespace libresign {

/// The DSS Java reference as a second signing engine, for the tests only: the
/// cross-backend cases sign through it to check the native engine (the only
/// one that ships) against the eSig DSS reference.
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

    bool isAvailable() const;

    /// @brief Sign through the Java oracle with @p key, which the caller holds:
    ///        the oracle returns the bytes to sign, @p key signs them here, and
    ///        the oracle builds the document around the signature. No PIN and
    ///        no key reaches the oracle.
    ///
    /// RSA keys only, over SHA-256: an ECDSA key returns
    /// @ref SignFailureKind::EngineError.
    /// A key's own failure (a refused PIN, a blocked card) keeps its kind.
    SigningResult sign(const SigningRequest& request, SigningKey& key) override;

private:
    DSSServiceManager& manager();

    DSSServiceManager* serviceManagerRef = nullptr;
    std::unique_ptr<DSSServiceManager> ownedManager;
    bool trustConfigured = false;
};

} // namespace libresign

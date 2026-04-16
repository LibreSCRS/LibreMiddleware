// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "libresign/signing_service.h"

#include <map>

namespace libresign {

class TlCache;
class TlSignatureVerifier;
class TrustStoreManager;

class NativeSigningService : public SigningService
{
public:
    bool configure(const TrustConfig& config) override;

    SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath, std::span<const uint8_t> pin,
                       const std::string& keyAlias, const std::string& tokenLabel = "") override;

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

    /// Set the TrustStoreManager used to receive TL-derived certificates.
    void setTrustStoreManager(TrustStoreManager* mgr)
    {
        trustStoreMgr = mgr;
    }

private:
    TrustConfig trustConfig;
    std::map<std::string, std::vector<uint8_t>> lotlDerivedCerts; // URL -> signing cert DER
    bool configured = false;
    bool fullyConfigured = false;
    TrustStoreManager* trustStoreMgr = nullptr;

    void loadTrustList(const std::string& url, bool isLotl, TlCache& cache, TlSignatureVerifier& verifier, int depth);
};

} // namespace libresign

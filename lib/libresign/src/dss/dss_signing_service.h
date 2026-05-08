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

/// @deprecated The DSS signing backend is deprecated. Use NativeSigningService (Backend::Native).
/// DSS remains available for backward compatibility and may be removed in a future release.
/// The DSS validation oracle (DSSValidationClient) remains supported for test verification.
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

    // Note: PIN is transmitted as plaintext JSON over the Unix domain socket
    // to the Java DSS service. The PIN resides in non-cleansable JVM String
    // memory during signing. This is an inherent limitation of the IPC-to-Java
    // architecture; the Unix socket restricts exposure to the local machine.
    // Any std::string we form on the C++ side as part of the JSON request is
    // explicitly cleansed before return.
    SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath, std::span<const uint8_t> pin,
                       const std::string& keyAlias, const std::string& readerName) override;

    bool isAvailable() const override;

private:
    DSSServiceManager& manager();

    DSSServiceManager* serviceManagerRef = nullptr;
    std::unique_ptr<DSSServiceManager> ownedManager;
    std::unique_ptr<HttpClient> httpClient;
    bool trustConfigured = false;
};

} // namespace libresign

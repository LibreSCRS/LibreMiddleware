// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "libresign/signing_service.h"

namespace libresign {

class NativeSigningService : public SigningService
{
public:
    bool configure(const TrustConfig& config) override;

    SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath,
                       std::span<const uint8_t> pin, const std::string& keyAlias,
                       const std::string& tokenLabel = "") override;

    bool isAvailable() const override;

private:
    TrustConfig trustConfig;
};

} // namespace libresign

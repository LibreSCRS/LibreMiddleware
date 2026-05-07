// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <cstdint>
#include <span>
#include <string_view>

namespace libresign {

// Helper for callers that have the PIN as a std::string_view (e.g. test
// fixtures with string literals). Production callers SHOULD store the PIN in
// a self-cleansing buffer (smartcard::SecureBuffer) and pass that directly
// via its implicit span<const uint8_t> conversion — see LibreCelik signpage.
inline std::span<const uint8_t> as_pin(std::string_view pin)
{
    return {reinterpret_cast<const uint8_t*>(pin.data()), pin.size()};
}

class SigningService
{
public:
    virtual ~SigningService() = default;

    // Configure trust lists and revocation sources.
    // Default implementation is a no-op (native backend uses bundled certs).
    virtual bool configure(const TrustConfig& /*config*/)
    {
        return true;
    }

    // PKCS#11 path — backend drives the card session.
    //
    // pin: byte view into caller-owned storage. The caller is responsible for
    //      cleansing that storage (e.g. via smartcard::SecureBuffer). The
    //      service implementation MUST NOT retain the view past return and
    //      MUST cleanse any intermediate copies it creates internally.
    //
    // tokenLabel: PKCS#11 token label for slot lookup (empty = auto-detect).
    virtual SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath,
                               std::span<const uint8_t> pin, const std::string& keyAlias,
                               const std::string& tokenLabel = "") = 0;

    virtual bool isAvailable() const = 0;
};

} // namespace libresign

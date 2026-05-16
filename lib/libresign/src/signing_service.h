// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace LibreSCRS::SmartCard {
class CardSession;
}

namespace libresign {

// Helper for callers that have the PIN as a std::string_view (e.g. test
// fixtures with string literals). Production callers SHOULD store the PIN in
// a self-cleansing buffer (LibreSCRS::SmartCard::Internal::SecureBuffer) and pass that directly
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
    //      cleansing that storage (e.g. via LibreSCRS::SmartCard::Internal::SecureBuffer). The
    //      service implementation MUST NOT retain the view past return and
    //      MUST cleanse any intermediate copies it creates internally.
    //
    // readerName: the FULL PCSC reader name the caller wants to sign on.
    // Mandatory: legacy auto-pick paths (`tokenLabel = ""` → slots[0])
    // were removed in 4.0 — they routed PIN to whatever card the PCSC
    // daemon enumerated first, which broke under any multi-card setup
    // (the user's eID at port 02 vs another card at port 00 = silent
    // PIN-to-wrong-card → spurious "wrong PIN"). The signing engine
    // resolves the slot via FNV-1a hash of @p readerName embedded in
    // the LM PKCS#11 module's slotDescription — see
    // `lib/pkcs11/include/pkcs11/internal/slot_hash.h`.
    //
    // sharedSession (optional, default null): live caller-owned
    // CardSession to forward into the loaded librescrs-pkcs11 module
    // so its PKCS#15 provider's probe can adopt it instead of opening
    // a second standalone session against the same reader. Required
    // for PACE-protected cards where the active SecureChannel must
    // not be torn down between display and sign. Legacy callers that
    // omit this argument get the standalone-bind behaviour.
    /// @since 4.2
    virtual SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath,
                               std::span<const uint8_t> pin, const std::string& keyAlias, const std::string& readerName,
                               std::shared_ptr<LibreSCRS::SmartCard::CardSession> sharedSession = nullptr) = 0;

    virtual bool isAvailable() const = 0;
};

} // namespace libresign

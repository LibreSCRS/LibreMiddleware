// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <emrtd/crypto/chip_auth.h>
#include <emrtd/crypto/secure_messaging.h>
#include <cstdint>
#include <vector>

namespace smartcard { class PCSCConnection; }

namespace emrtd::crypto {

struct AAPublicKey {
    enum Algorithm { RSA, ECDSA, UNKNOWN };
    Algorithm algorithm = UNKNOWN;
    std::vector<uint8_t> publicKeyDER;
};

AAPublicKey parseDG15(const std::vector<uint8_t>& dg15Raw);

ChipAuthResult performActiveAuth(smartcard::PCSCConnection& conn,
                                 const std::vector<uint8_t>& dg15Raw,
                                 SecureMessaging& currentSM);
} // namespace emrtd::crypto

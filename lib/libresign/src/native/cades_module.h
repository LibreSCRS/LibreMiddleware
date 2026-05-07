// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"
#include "native/revocation_client.h"

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token;

class CAdESModule
{
public:
    // Create CAdES B-B detached signature.
    // Returns DER-encoded CMS SignedData.
    std::vector<uint8_t> signBB(const std::vector<uint8_t>& data, Pkcs11Token& token);

    // Upgrade B-B -> B-T: add signature timestamp.
    std::vector<uint8_t> addTimestamp(const std::vector<uint8_t>& cms, const TSAConfig& tsa);

    // Upgrade B-T -> B-LT: add revocation data.
    std::vector<uint8_t> addRevocationData(const std::vector<uint8_t>& cms, const RevocationData& revData);

    // Upgrade B-LT -> B-LTA: add archive timestamp.
    std::vector<uint8_t> addArchiveTimestamp(const std::vector<uint8_t>& cms, const TSAConfig& tsa);

    // Convenience: sign at requested level in one call.
    SigningResult sign(const std::vector<uint8_t>& data, Pkcs11Token& token, SignatureLevel level,
                       const TSAConfig& tsa);
};

} // namespace libresign

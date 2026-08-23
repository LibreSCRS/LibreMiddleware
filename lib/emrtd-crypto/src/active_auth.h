// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "chip_auth.h"
#include "secure_messaging.h"
#include <cstdint>
#include <vector>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}

namespace emrtd::crypto {

struct AAPublicKey
{
    enum Algorithm { RSA, ECDSA, UNKNOWN };
    Algorithm algorithm = UNKNOWN;
    std::vector<uint8_t> publicKeyDER;
};

AAPublicKey parseDG15(const std::vector<uint8_t>& dg15Raw);

/// @brief Run ICAO Doc 9303 Active Authentication over the supplied secure
///        channel. INTERNAL AUTHENTICATE flows through @p channel which
///        owns the SM wrap/unwrap. Returns
///        @ref ChipAuthResult::activeAuthentication status; no key
///        rotation occurs on success.
ChipAuthResult performActiveAuth(LibreSCRS::SecureChannel::ISecureChannel& channel, const std::vector<uint8_t>& dg15Raw,
                                 LibreSCRS::CancelToken token = {});
} // namespace emrtd::crypto

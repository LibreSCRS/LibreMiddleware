// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pcsc_classify.h"

#include <cstdint>
#include <utility>

namespace LibreSCRS::SmartCard::Internal {

// 32 bits on both sides: the SDK macros are unsigned on macOS and signed LONG
// elsewhere, and a wider cast would sign-extend only one of the two.
TransportError::Kind classifyPcscCode(LONG code) noexcept
{
    switch (static_cast<std::uint32_t>(code)) {
    case static_cast<std::uint32_t>(SCARD_E_NO_SMARTCARD):
    case static_cast<std::uint32_t>(SCARD_W_REMOVED_CARD):
        return TransportError::Kind::NoCardPresent;
    case static_cast<std::uint32_t>(SCARD_W_RESET_CARD):
        return TransportError::Kind::CardReset;
    case static_cast<std::uint32_t>(SCARD_E_PROTO_MISMATCH):
    case static_cast<std::uint32_t>(SCARD_W_UNRESPONSIVE_CARD):
    case static_cast<std::uint32_t>(SCARD_W_UNPOWERED_CARD):
    case static_cast<std::uint32_t>(SCARD_F_COMM_ERROR):
        return TransportError::Kind::ProtocolError;
    case static_cast<std::uint32_t>(SCARD_E_SHARING_VIOLATION):
        return TransportError::Kind::SessionRefused;
    default:
        return TransportError::Kind::ReaderUnavailable;
    }
}

TransportError pcscFailure(LONG code, std::string detail)
{
    return TransportError{classifyPcscCode(code), std::move(detail)};
}

} // namespace LibreSCRS::SmartCard::Internal

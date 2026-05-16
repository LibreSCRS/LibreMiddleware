// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "emrtd_types.h"
#include <apdu.h>

#include <optional>
#include <vector>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}

namespace emrtd {

enum class DGReadStatus { OK, ACCESS_DENIED, NOT_PRESENT, ERROR };

struct DGReadResult
{
    DGReadStatus status;
    std::vector<uint8_t> data;
};

/// @brief ICAO Doc 9303 data-group read protocol over a pre-established
///        secure channel.
///
/// EMRTDCard is a thin protocol class: PACE / BAC handshakes and the
/// PC/SC transaction are owned by @ref LibreSCRS::SmartCard::CardSession,
/// not by this object. The caller passes an
/// @ref LibreSCRS::SecureChannel::ISecureChannel reference (typically
/// retrieved via @ref LibreSCRS::SmartCard::ActiveChannelHolder::activeChannel)
/// and EMRTDCard issues wrapped SELECT FILE + READ BINARY APDUs through it.
/// Chip Authentication's SM-key rotation is handled by the caller invoking
/// @ref LibreSCRS::SecureChannel::ISecureChannel::replaceKeys after a
/// successful @ref emrtd::crypto::performChipAuth.
class EMRTDCard
{
public:
    explicit EMRTDCard(LibreSCRS::SecureChannel::ISecureChannel& channel);

    std::vector<int> readCOM();
    /// Reads EF.SOD (FID 011D) and returns raw bytes for PA processing
    std::optional<std::vector<uint8_t>> readSOD();
    std::optional<std::vector<uint8_t>> readDataGroup(int dgNumber);

    /// Reads a data group with access-denied handling for EAC-protected DGs
    DGReadResult readDataGroupSafe(int dgNumber);

    /// Parses DG16 (persons to notify) from raw bytes
    static std::vector<ContactPerson> parseDG16(const std::vector<uint8_t>& raw);

private:
    LibreSCRS::SecureChannel::ISecureChannel& channel;

    std::optional<std::vector<uint8_t>> readFile(uint16_t fid, bool skipSelect = false);
};

} // namespace emrtd

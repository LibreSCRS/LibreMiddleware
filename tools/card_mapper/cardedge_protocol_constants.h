// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Card-Edge / PKCS#15 protocol constants used by card_mapper for AID
// recognition + read-procedure documentation. Local copy: the in-tree
// CardEdge implementation has been retired in favour of upstream OpenSC's
// card-srbeid driver, but card_mapper is a documentation/discovery tool
// that still needs to recognise the canonical AID and document the
// READ BINARY chunk size for Gemalto IDPrime-based cards.

#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace cardedge::protocol {

// CardEdge PKI applet AID — shared by Serbian eID (Gemalto/IF2020), PKS
// Chamber of Commerce card, Serbian health insurance card, and other
// Gemalto IDPrime-based cards.
inline const std::vector<uint8_t> AID_PKCS15 = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};

// Root directory FID inside the PKI applet filesystem.
constexpr uint16_t PKI_ROOT_DIR_FID = 0x7000;

// Maximum bytes per READ BINARY on the CardEdge applet (internal buffer limit).
constexpr uint8_t PKI_READ_CHUNK = 0x80;

} // namespace cardedge::protocol

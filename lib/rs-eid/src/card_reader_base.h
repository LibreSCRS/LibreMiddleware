// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <vector>

namespace LibreSCRS::SmartCard::Internal {
class PCSCConnection;
}

namespace eidcard {

class CardReaderBase
{
public:
    virtual ~CardReaderBase() = default;
    virtual std::vector<uint8_t> readFile(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2) = 0;

    // Read file including the raw TLV header (from offset 0).
    // Needed for hash verification where the full file content must be hashed.
    virtual std::vector<uint8_t> readFileRaw(LibreSCRS::SmartCard::Internal::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2) = 0;
};

} // namespace eidcard

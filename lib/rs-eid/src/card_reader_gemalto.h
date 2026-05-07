// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "card_reader_base.h"
#include "eidtypes.h"

namespace eidcard {

class CardReaderGemalto : public CardReaderBase
{
public:
    // Try selecting an AID on the card. Returns the detected card type.
    static CardType selectApplication(smartcard::PCSCConnection& conn);

    std::vector<uint8_t> readFile(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2) override;

    std::vector<uint8_t> readFileRaw(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2) override;
};

} // namespace eidcard

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_CARD_READER_GEMALTO_H
#define EIDCARD_CARD_READER_GEMALTO_H

#include "card_reader_base.h"
#include "eidcard/eidtypes.h"

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

#endif // EIDCARD_CARD_READER_GEMALTO_H

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "card_reader_base.h"

namespace eidcard {

class CardReaderApollo : public CardReaderBase
{
public:
    std::vector<uint8_t> readFile(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2) override;

    std::vector<uint8_t> readFileRaw(smartcard::PCSCConnection& conn, uint8_t fileId1, uint8_t fileId2) override;
};

} // namespace eidcard

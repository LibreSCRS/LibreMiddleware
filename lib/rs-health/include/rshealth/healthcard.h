// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "rshealth/healthtypes.h"
#include <memory>
#include <string>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace healthcard {

class HealthCard
{
public:
    static bool probe(const std::string& readerName);
    static bool probe(smartcard::PCSCConnection& conn);

    explicit HealthCard(const std::string& readerName);
    explicit HealthCard(smartcard::PCSCConnection& conn);
    ~HealthCard();
    HealthCard(const HealthCard&) = delete;
    HealthCard& operator=(const HealthCard&) = delete;

    HealthDocumentData readDocumentData();

private:
    std::unique_ptr<smartcard::PCSCConnection> ownedConnection;
    smartcard::PCSCConnection* conn = nullptr;

    void initCard();
    std::vector<uint8_t> readFile(const std::vector<uint8_t>& fileId);
};

} // namespace healthcard

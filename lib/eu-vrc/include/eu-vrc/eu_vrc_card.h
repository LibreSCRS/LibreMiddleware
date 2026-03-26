// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <eu-vrc/eu_vrc_types.h>

#include <memory>
#include <string>

namespace smartcard {
class PCSCConnection;
struct BERField;
} // namespace smartcard

namespace euvrc {

class EuVrcCard
{
public:
    static bool probe(const std::string& readerName);
    static bool probe(smartcard::PCSCConnection& conn);

    explicit EuVrcCard(const std::string& readerName);
    explicit EuVrcCard(smartcard::PCSCConnection& conn);
    ~EuVrcCard();

    EuVrcCard(const EuVrcCard&) = delete;
    EuVrcCard& operator=(const EuVrcCard&) = delete;

    EuVrcData readCard();

private:
    std::unique_ptr<smartcard::PCSCConnection> ownedConnection;
    smartcard::PCSCConnection* conn = nullptr;

    std::vector<uint8_t> readFile(uint8_t fidHi, uint8_t fidLo);
};

// Extract EU VRC fields from a merged BER tree
EuVrcData extractFields(const smartcard::BERField& root);

// Convert YYYYMMDD -> DD.MM.YYYY
std::string formatVrcDate(const std::string& yyyymmdd);

} // namespace euvrc

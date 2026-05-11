// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "eu_vrc_types.h"

#include <memory>
#include <string>

namespace LibreSCRS::SmartCard::Internal {
class PCSCConnection;
struct BERField;
} // namespace LibreSCRS::SmartCard::Internal

namespace euvrc {

class EuVrcCard
{
public:
    static bool probe(const std::string& readerName);
    static bool probe(LibreSCRS::SmartCard::Internal::PCSCConnection& conn);

    explicit EuVrcCard(const std::string& readerName);
    explicit EuVrcCard(LibreSCRS::SmartCard::Internal::PCSCConnection& conn);
    ~EuVrcCard();

    EuVrcCard(const EuVrcCard&) = delete;
    EuVrcCard& operator=(const EuVrcCard&) = delete;

    EuVrcData readCard();

private:
    std::unique_ptr<LibreSCRS::SmartCard::Internal::PCSCConnection> ownedConnection;
    LibreSCRS::SmartCard::Internal::PCSCConnection* conn = nullptr;

    std::vector<uint8_t> readFile(uint8_t fidHi, uint8_t fidLo);
};

// Extract EU VRC fields from a merged BER tree
EuVrcData extractFields(const LibreSCRS::SmartCard::Internal::BERField& root);

// Convert YYYYMMDD -> DD.MM.YYYY
std::string formatVrcDate(const std::string& yyyymmdd);

} // namespace euvrc

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "eu_vrc_types.h"

#include <smartcard/chunked_read.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>

namespace LibreSCRS::SmartCard::Internal {
class PCSCConnection;
struct BERField;
} // namespace LibreSCRS::SmartCard::Internal

namespace euvrc {

class EuVrcCard
{
public:
    static bool probe(LibreSCRS::SmartCard::Internal::PCSCConnection& conn);

    explicit EuVrcCard(LibreSCRS::SmartCard::Internal::PCSCConnection& conn);
    ~EuVrcCard();

    EuVrcCard(const EuVrcCard&) = delete;
    EuVrcCard& operator=(const EuVrcCard&) = delete;

    EuVrcData readCard();

private:
    LibreSCRS::SmartCard::Internal::PCSCConnection* conn = nullptr;

    std::vector<uint8_t> readFile(uint8_t fidHi, uint8_t fidLo);
};

namespace detail {

/// Decide, from the first bytes of a file and whatever the FCI said about its
/// size, where the body starts and how many bytes still have to be read.
///
/// `fciFileSize == 0` means the FCI said nothing, and that is the branch that
/// decodes a BER length: the value it returns is a DECLARATION of how many
/// bytes the card still owes, so it legitimately exceeds @p hdr. Every other
/// caller of that decoder asks whether a length fits bytes already in hand.
/// Both contracts are real; a test holds each.
///
/// Returns `std::nullopt` when the header cannot be read at all.
std::optional<LibreSCRS::SmartCard::Internal::HeaderParseResult> deriveEuVrcHeader(std::span<const std::uint8_t> hdr,
                                                                                   std::size_t fciFileSize);

} // namespace detail

// Extract EU VRC fields from a merged BER tree
EuVrcData extractFields(const LibreSCRS::SmartCard::Internal::BERField& root);

// Convert YYYYMMDD -> DD.MM.YYYY
std::string formatVrcDate(const std::string& yyyymmdd);

} // namespace euvrc

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <rs_document_profile.h>

#include <cstdint>
#include <optional>
#include <vector>

namespace LibreSCRS::SmartCard {
class CardConnection;
}

namespace eidcard {

class CardReaderGemalto
{
public:
    /// Select the first application, in the order ID, IF, RP, EL, that the card
    /// accepts. An application the card refuses is "not this one", whichever
    /// status word the chip uses to say so.
    /// @return Its profile, or null when the card hosts none of them.
    static const LibreSCRS::RsEId::Core::DocumentProfile* selectApplication(LibreSCRS::SmartCard::CardConnection& conn);

    /// Read one file of @p profile as its @p spec says: a Header file up to its
    /// declared length, an Allocation file as many bytes as SELECT reports.
    ///
    /// A final answer (protected, absent) is the file's answer: it ends the
    /// attempt without re-selecting or reconnecting. Any other failure is
    /// retried, and throws once the retries are spent.
    /// @return The bytes as they stand on the card, or nothing when the card
    ///         will not give the file out.
    static std::optional<std::vector<std::uint8_t>> readFile(LibreSCRS::SmartCard::CardConnection& conn,
                                                             const LibreSCRS::RsEId::Core::DocumentProfile& profile,
                                                             const LibreSCRS::RsEId::Core::FileSpec& spec);
};

} // namespace eidcard

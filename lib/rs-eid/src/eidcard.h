// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <memory>
#include <set>
#include <span>
#include <vector>
#include "eidtypes.h"

#include <rs_document_profile.h>

namespace LibreSCRS::SmartCard {
class CardConnection;
}

namespace eidcard {

class CardVerifier;

/// One CardEdge card: the document type it is, the files read from it so far,
/// and the verdicts about them.
class EIdCard
{
public:
    /// @throws std::runtime_error when the card hosts none of the known applications.
    explicit EIdCard(LibreSCRS::SmartCard::CardConnection& conn);
    ~EIdCard();

    EIdCard(const EIdCard&) = delete;
    EIdCard& operator=(const EIdCard&) = delete;

    const LibreSCRS::RsEId::Core::DocumentProfile& profile() const;

    /// Read the files of @p fids not yet tried. A file the card gave a final
    /// answer for (absent, protected) is not asked for again and is not in the
    /// result; nothing is read twice.
    /// @return Every file read so far.
    const LibreSCRS::RsEId::Core::RawFiles& load(std::span<const std::uint16_t> fids);

    /// The portrait: what the photo file holds once read, or empty.
    PhotoData readPortrait();

    // Verification
    // Add a single DER-encoded trusted certificate (use when certs come from
    // memory / Qt resources rather than a filesystem directory). Without one
    // every verdict is Unknown and no file is read for it.
    void addTrustedCertificate(const std::vector<uint8_t>& derCert);
    VerificationResult verifyCard();
    VerificationResult verifyFixedData();
    VerificationResult verifyVariableData();

private:
    LibreSCRS::SmartCard::CardConnection* conn = nullptr; // borrowed: the single card session's connection
    const LibreSCRS::RsEId::Core::DocumentProfile* selected = nullptr;
    LibreSCRS::RsEId::Core::RawFiles files;
    std::set<std::uint16_t> tried;
    std::unique_ptr<CardVerifier> verifier;

    template <typename Verdict>
    VerificationResult verdict(std::vector<std::uint16_t> fids, Verdict&& judge);
};

} // namespace eidcard

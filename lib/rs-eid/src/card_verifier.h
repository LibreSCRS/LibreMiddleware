// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>
#include "eidtypes.h"

#include <rs_trust_store.h>

namespace LibreSCRS::SmartCard {
class CardConnection;
}

namespace eidcard {

class CardReaderBase;

class CardVerifier
{
public:
    explicit CardVerifier(const std::string& certificateFolderPath);
    ~CardVerifier();

    CardVerifier(const CardVerifier&) = delete;
    CardVerifier& operator=(const CardVerifier&) = delete;

    // Add a single DER-encoded trusted certificate to the store.
    // Use this when certs are provided as raw bytes (e.g. from Qt resources).
    void addCertificate(const std::vector<uint8_t>& derCert);

    VerificationResult verifyCard(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                  CardType cardType);

    VerificationResult verifyFixedData(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                       CardType cardType);

    VerificationResult verifyVariableData(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                          CardType cardType);

private:
    // Gemalto (new card) card-level certificate verification
    VerificationResult verifyGemaltoCardCert(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader);

    // Gemalto (new card) SOD/PKCS#7 verification
    VerificationResult verifyGemaltoSOD(LibreSCRS::SmartCard::CardConnection& conn, CardReaderBase& reader,
                                        uint8_t sodFileH, uint8_t sodFileL,
                                        const std::vector<std::pair<uint8_t, uint8_t>>& dataFileIds);

    LibreSCRS::RsEId::Core::TrustStore trust;
};

} // namespace eidcard

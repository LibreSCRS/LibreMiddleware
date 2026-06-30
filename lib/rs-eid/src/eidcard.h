// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <memory>
#include <string>
#include <vector>
#include "eidtypes.h"

namespace LibreSCRS::SmartCard::Internal {
class PCSCConnection;
}

namespace eidcard {

class CardReaderBase;

class CardVerifier;

class EIdCard
{
public:
    explicit EIdCard(LibreSCRS::SmartCard::Internal::PCSCConnection& conn);
    ~EIdCard();

    EIdCard(const EIdCard&) = delete;
    EIdCard& operator=(const EIdCard&) = delete;

    CardType getCardType() const;
    DocumentData readDocumentData();
    FixedPersonalData readFixedPersonalData();
    VariablePersonalData readVariablePersonalData();
    PhotoData readPortrait();

    // Verification
    void setCertificateFolderPath(const std::string& path);
    // Add a single DER-encoded trusted certificate (use when certs come from
    // memory / Qt resources rather than a filesystem directory).
    void addTrustedCertificate(const std::vector<uint8_t>& derCert);
    VerificationResult verifyCard();
    VerificationResult verifyFixedData();
    VerificationResult verifyVariableData();

private:
    LibreSCRS::SmartCard::Internal::PCSCConnection* conn = nullptr; // borrowed: the single card session's connection
    std::unique_ptr<CardReaderBase> cardReader;
    std::unique_ptr<CardVerifier> verifier;
    std::string certFolderPath;
    CardType cardType = CardType::Unknown;

    void detectCardType();
    void ensureVerifier();
};

} // namespace eidcard

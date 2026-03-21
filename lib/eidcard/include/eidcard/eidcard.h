// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_EIDCARD_H
#define EIDCARD_EIDCARD_H

#include <memory>
#include <string>
#include <vector>
#include "eidtypes.h"

namespace smartcard {
class PCSCConnection;
}

namespace eidcard {

class CardReaderBase;

class CardVerifier;

class EIdCard
{
public:
    // Check if an eID card is present on the given reader without opening a full session.
    static bool probe(const std::string& readerName);

    explicit EIdCard(const std::string& readerName);
    explicit EIdCard(smartcard::PCSCConnection& conn);
    ~EIdCard();

    EIdCard(const EIdCard&) = delete;
    EIdCard& operator=(const EIdCard&) = delete;

    CardType getCardType() const;
    DocumentData readDocumentData();
    FixedPersonalData readFixedPersonalData();
    VariablePersonalData readVariablePersonalData();
    PhotoData readPortrait();

    // Reconnect the underlying PC/SC connection after SCARD_W_RESET_CARD.
    void reconnectConnection();

    // Verification
    void setCertificateFolderPath(const std::string& path);
    // Add a single DER-encoded trusted certificate (use when certs come from
    // memory / Qt resources rather than a filesystem directory).
    void addTrustedCertificate(const std::vector<uint8_t>& derCert);
    VerificationResult verifyCard();
    VerificationResult verifyFixedData();
    VerificationResult verifyVariableData();

private:
    std::unique_ptr<smartcard::PCSCConnection> ownedConnection;
    smartcard::PCSCConnection* conn = nullptr; // always valid: points to owned or borrowed
    std::unique_ptr<CardReaderBase> cardReader;
    std::unique_ptr<CardVerifier> verifier;
    std::string certFolderPath;
    CardType cardType = CardType::Unknown;

    void detectCardType();
    void ensureVerifier();
};

} // namespace eidcard

#endif // EIDCARD_EIDCARD_H

// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_EIDCARD_H
#define EIDCARD_EIDCARD_H

#include <memory>
#include <string>
#include "eidtypes.h"

namespace smartcard {
class PCSCConnection;
}

namespace eidcard {

class CardReaderBase;

class CardVerifier;

class EIdCard {
public:
    // Check if an eID card is present on the given reader without opening a full session.
    static bool probe(const std::string& readerName);

    explicit EIdCard(const std::string& readerName);
    ~EIdCard();

    EIdCard(const EIdCard&) = delete;
    EIdCard& operator=(const EIdCard&) = delete;

    CardType getCardType() const;
    DocumentData readDocumentData();
    FixedPersonalData readFixedPersonalData();
    VariablePersonalData readVariablePersonalData();
    PhotoData readPortrait();
    CertificateList readCertificates();

    // PIN management (Gemalto/IF2020 only)
    PINResult getPINTriesLeft();
    PINResult verifyPIN(const std::string& pin);
    PINResult changePIN(const std::string& oldPin, const std::string& newPin);

    // Verification
    void setCertificateFolderPath(const std::string& path);
    VerificationResult verifyCard();
    VerificationResult verifyFixedData();
    VerificationResult verifyVariableData();

private:
    std::unique_ptr<smartcard::PCSCConnection> connection;
    std::unique_ptr<CardReaderBase> cardReader;
    std::unique_ptr<CardVerifier> verifier;
    std::string certFolderPath;
    CardType cardType = CardType::Unknown;

    void ensureVerifier();
};

} // namespace eidcard

#endif // EIDCARD_EIDCARD_H

// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_EIDCARD_H
#define EIDCARD_EIDCARD_H

#include <memory>
#include <string>
#include <utility>
#include <vector>
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

    // PKCS#11 signing (Gemalto/IF2020 only)
    // Sign data using MSE SET (algo=0x02, PKCS#1 v1.5) + PSO on the PKI applet.
    // data = DER DigestInfo; the card applies PKCS#1 v1.5 padding.
    std::vector<uint8_t> signData(uint16_t keyReference, const std::vector<uint8_t>& data);

    // Discover private key FIDs by parsing the cmapfile on the PKI applet.
    // Returns list of {label, keyFID} pairs matching certificate order.
    std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences();

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
    std::unique_ptr<smartcard::PCSCConnection> connection;
    std::unique_ptr<CardReaderBase> cardReader;
    std::unique_ptr<CardVerifier> verifier;
    std::string certFolderPath;
    CardType cardType = CardType::Unknown;

    void ensureVerifier();
};

} // namespace eidcard

#endif // EIDCARD_EIDCARD_H

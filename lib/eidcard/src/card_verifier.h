// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright hirashix0@proton.me

#ifndef EIDCARD_CARD_VERIFIER_H
#define EIDCARD_CARD_VERIFIER_H

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "eidcard/eidtypes.h"

namespace smartcard {
class PCSCConnection;
}

namespace eidcard {

class CardReaderBase;

class CardVerifier {
public:
    explicit CardVerifier(const std::string& certificateFolderPath);
    ~CardVerifier();

    CardVerifier(const CardVerifier&) = delete;
    CardVerifier& operator=(const CardVerifier&) = delete;

    // Add a single DER-encoded trusted certificate to the store.
    // Use this when certs are provided as raw bytes (e.g. from Qt resources).
    void addCertificate(const std::vector<uint8_t>& derCert);

    VerificationResult verifyCard(smartcard::PCSCConnection& conn,
                                  CardReaderBase& reader,
                                  CardType cardType);

    VerificationResult verifyFixedData(smartcard::PCSCConnection& conn,
                                       CardReaderBase& reader,
                                       CardType cardType);

    VerificationResult verifyVariableData(smartcard::PCSCConnection& conn,
                                          CardReaderBase& reader,
                                          CardType cardType);

private:
    // Gemalto (new card) card-level certificate verification
    VerificationResult verifyGemaltoCardCert(smartcard::PCSCConnection& conn,
                                              CardReaderBase& reader);

    // Gemalto (new card) SOD/PKCS#7 verification
    VerificationResult verifyGemaltoSOD(smartcard::PCSCConnection& conn,
                                        CardReaderBase& reader,
                                        uint8_t sodFileH, uint8_t sodFileL,
                                        const std::vector<std::pair<uint8_t, uint8_t>>& dataFileIds);

    // Apollo (old card) certificate chain verification
    VerificationResult verifyApolloCardCert(smartcard::PCSCConnection& conn,
                                            CardReaderBase& reader);

    // Apollo (old card) RSA signature verification
    VerificationResult verifyApolloSignature(smartcard::PCSCConnection& conn,
                                             CardReaderBase& reader,
                                             uint8_t sigFileH, uint8_t sigFileL,
                                             uint8_t certFileH, uint8_t certFileL,
                                             const std::vector<std::pair<uint8_t, uint8_t>>& dataFileIds);

    // OpenSSL helpers
    bool verifyCertificateChain(const std::vector<uint8_t>& certDER);
    bool verifyPKCS7Signature(const std::vector<uint8_t>& pkcs7DER,
                              std::vector<uint8_t>& extractedContent);
    bool verifyRSASignature(const std::vector<uint8_t>& certDER,
                            const std::vector<uint8_t>& data,
                            const std::vector<uint8_t>& signature);
    static std::vector<uint8_t> computeSHA256(const std::vector<uint8_t>& data);

    // PIMPL to avoid OpenSSL headers in this header
    struct CertStore;
    std::unique_ptr<CertStore> certStore;
    std::string certFolderPath;

    void loadTrustedCertificates();
};

} // namespace eidcard

#endif // EIDCARD_CARD_VERIFIER_H

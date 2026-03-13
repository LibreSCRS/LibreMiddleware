// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef PKSCARD_PKSCARD_H
#define PKSCARD_PKSCARD_H

#include <memory>
#include <string>
#include <utility>
#include <vector>
#include "cardedge/cardedgetypes.h"

namespace smartcard {
class PCSCConnection;
}

namespace pkscard {

// PKS Chamber of Commerce card (Privredna komora Srbije, qualified signature card).
// ATR: 3B DE 97 00 80 31 FE 45 53 43 45 20 38 2E 30 2D 43 31 56 30 0D 0A 2E
// Applet: CardEdge PKI (AID A0 00 00 00 63 50 4B 43 53 2D 31 35)
// Contains 2 certificates (key-exchange + digital-signature) and RSA-2048 private keys.
class PKSCard
{
public:
    // Check if a PKS card is present on the given reader without opening a full session.
    // Uses AID selection only; factory ordering ensures this is called after eID probes.
    static bool probe(const std::string& readerName);

    explicit PKSCard(const std::string& readerName);
    ~PKSCard();

    PKSCard(const PKSCard&) = delete;
    PKSCard& operator=(const PKSCard&) = delete;

    // Read and decompress all certificates from the mscp/ directory.
    cardedge::CertificateList readCertificates();

    // Return the current PIN retry counter without consuming a retry.
    cardedge::PINResult getPINTriesLeft();

    // Verify the user PIN.
    cardedge::PINResult verifyPIN(const std::string& pin);

    // Change the user PIN.
    cardedge::PINResult changePIN(const std::string& oldPin, const std::string& newPin);

    // Compute a digital signature (RSA-2048, PKCS#1 v1.5).
    // data must be a DER DigestInfo; the applet applies padding.
    std::vector<uint8_t> signData(uint16_t keyReference, const std::vector<uint8_t>& data);

    // Discover private key FIDs by parsing the cmapfile.
    std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences();

private:
    std::unique_ptr<smartcard::PCSCConnection> connection;
};

} // namespace pkscard

#endif // PKSCARD_PKSCARD_H

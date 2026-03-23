// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#pragma once

#include <string>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace pkscard {

// PKS Chamber of Commerce card (Privredna komora Srbije, qualified signature card).
// ATR: 3B DE 97 00 80 31 FE 45 53 43 45 20 38 2E 30 2D 43 31 56 30 0D 0A 2E
// Applet: CardEdge PKI (AID A0 00 00 00 63 50 4B 43 53 2D 31 35)
// Contains 2 certificates (key-exchange + digital-signature) and RSA-2048 private keys.
// PKI operations (certificates, PIN, signing) are handled by the CardEdge plugin.
class PKSCard
{
public:
    // Check if a PKS card is present on the given reader without opening a full session.
    // Uses AID selection only; factory ordering ensures this is called after eID probes.
    static bool probe(const std::string& readerName);
    static bool probe(smartcard::PCSCConnection& conn);
};

} // namespace pkscard

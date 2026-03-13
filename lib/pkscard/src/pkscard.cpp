// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "pkscard/pkscard.h"
#include "cardedge/cardedge.h"
#include "cardedge/pki_applet_guard.h"
#include "smartcard/apdu.h"
#include "smartcard/pcsc_connection.h"

namespace pkscard {

bool PKSCard::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        // Health cards also support PKCS15 — reject them by checking for the
        // SERVSZK health insurance applet (AID F3 81 00 00 02 SERVSZK 01).
        static const std::vector<uint8_t> AID_SERVSZK = {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45,
                                                         0x52, 0x56, 0x53, 0x5A, 0x4B, 0x01};
        if (conn.transmit(smartcard::selectByAID(AID_SERVSZK)).isSuccess())
            return false;
        cardedge::PkiAppletGuard guard(conn);
        return true;
    } catch (...) {
        return false;
    }
}

PKSCard::PKSCard(const std::string& readerName)
{
    connection = std::make_unique<smartcard::PCSCConnection>(readerName);
}

PKSCard::~PKSCard() = default;

cardedge::CertificateList PKSCard::readCertificates()
{
    cardedge::PkiAppletGuard guard(*connection);
    return cardedge::readCertificates(*connection);
}

cardedge::PINResult PKSCard::getPINTriesLeft()
{
    cardedge::PkiAppletGuard guard(*connection);
    return cardedge::getPINTriesLeft(*connection);
}

cardedge::PINResult PKSCard::verifyPIN(const std::string& pin)
{
    cardedge::PkiAppletGuard guard(*connection);
    return cardedge::verifyPIN(*connection, pin);
}

cardedge::PINResult PKSCard::changePIN(const std::string& oldPin, const std::string& newPin)
{
    cardedge::PkiAppletGuard guard(*connection);
    return cardedge::changePIN(*connection, oldPin, newPin);
}

std::vector<uint8_t> PKSCard::signData(uint16_t keyReference, const std::vector<uint8_t>& data)
{
    cardedge::PkiAppletGuard guard(*connection);
    return cardedge::signData(*connection, keyReference, data);
}

std::vector<std::pair<std::string, uint16_t>> PKSCard::discoverKeyReferences()
{
    cardedge::PkiAppletGuard guard(*connection);
    return cardedge::discoverKeyReferences(*connection);
}

} // namespace pkscard

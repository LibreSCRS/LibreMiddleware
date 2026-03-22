// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "pkscard/pkscard.h"
#include "cardedge/pki_applet_guard.h"
#include "smartcard/apdu.h"
#include "smartcard/pcsc_connection.h"

namespace pkscard {

bool PKSCard::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        return probe(conn);
    } catch (...) {
        return false;
    }
}

bool PKSCard::probe(smartcard::PCSCConnection& conn)
{
    try {
        // Health cards also support PKCS15 — reject them by checking for the
        // SERVSZK health insurance applet (AID F3 81 00 00 02 SERVSZK 01).
        static const std::vector<uint8_t> AID_SERVSZK = {0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45,
                                                         0x52, 0x56, 0x53, 0x5A, 0x4B, 0x01};
        if (conn.transmit(smartcard::selectByAID(AID_SERVSZK)).isSuccess())
            return false;
        cardedge::PkiAppletGuard guard(conn);
        // Verify CardEdge root dir (0x7000) exists — rejects generic PKCS#15 cards
        auto resp = conn.transmit(smartcard::selectByFileId(0x70, 0x00));
        return resp.isSuccess();
    } catch (...) {
        return false;
    }
}

} // namespace pkscard

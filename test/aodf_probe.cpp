// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me
//
// AODF + PIN reference probe: reads the real authObjects file from ODF
// and probes VERIFY with different P2 values to discover PIN references.

#include "smartcard/pcsc_connection.h"
#include "smartcard/apdu.h"

#include <cstdio>
#include <string>
#include <vector>

static void hexDump(const std::vector<uint8_t>& d)
{
    for (size_t i = 0; i < d.size(); ++i) {
        printf("%02X ", d[i]);
        if (i % 24 == 23 && i + 1 < d.size())
            printf("\n  ");
    }
    printf("\n");
}

static std::vector<uint8_t> readFile(smartcard::PCSCConnection& conn, uint16_t fid, const char* name)
{
    uint8_t fidH = static_cast<uint8_t>((fid >> 8) & 0xFF);
    uint8_t fidL = static_cast<uint8_t>(fid & 0xFF);

    auto s = conn.transmit({0x00, 0xA4, 0x02, 0x0C, {fidH, fidL}, 0x00, true});
    printf("\n--- %s (FID %04X) ---\n", name, fid);
    printf("  SELECT SW=%02X%02X\n", s.sw1, s.sw2);
    if (!s.isSuccess())
        return {};

    std::vector<uint8_t> data;
    size_t offset = 0;
    while (offset < 4096) {
        uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0x7F);
        uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
        auto r = conn.transmit({0x00, 0xB0, p1, p2, {}, 0x00, true});
        if (!r.isSuccess() || r.data.empty())
            break;
        data.insert(data.end(), r.data.begin(), r.data.end());
        offset += r.data.size();
        if (r.data.size() < 256)
            break;
    }

    if (!data.empty()) {
        printf("  Data (%zu bytes):\n  ", data.size());
        hexDump(data);
    } else {
        printf("  (empty)\n");
    }
    return data;
}

int main(int argc, char* argv[])
{
    printf("=== AODF + PIN Reference Probe ===\n");

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty()) {
        fprintf(stderr, "No readers found.\n");
        return 1;
    }

    std::string readerName = (argc > 1) ? argv[1] : readers.back();
    printf("Using: %s\n", readerName.c_str());

    try {
        smartcard::PCSCConnection conn(readerName);

        auto atr = conn.getATR();
        printf("ATR: ");
        hexDump(atr);

        // Select PKCS#15 applet
        printf("\n--- SELECT PKCS#15 ---\n");
        auto sel = conn.transmit({0x00,
                                  0xA4,
                                  0x04,
                                  0x00,
                                  {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35},
                                  0x00,
                                  true});
        printf("  SW=%02X%02X\n", sel.sw1, sel.sw2);

        // ODF maps these FIDs (from previous probe):
        // A0=4400 A1=4401 A2=4402 A3=4403 A4=4404 A5=4405 A6=4406 A7=4407 A8=4408
        // We read 4401 (PrKDF) and 4404 (CDF) last time. Now read the rest.

        readFile(conn, 0x4400, "ODF[A0] - privateKeys?");
        readFile(conn, 0x4403, "ODF[A3] - secretKeys");
        readFile(conn, 0x4405, "ODF[A5] - trustedCerts");
        readFile(conn, 0x4407, "ODF[A7] - dataObjects");
        readFile(conn, 0x4408, "ODF[A8] - authObjects (PINs)");

        // Also try reading certs by their actual paths from CDF
        printf("\n======== CERTIFICATE FILES ========\n");

        // Re-select PKCS#15
        conn.transmit({0x00,
                       0xA4,
                       0x04,
                       0x00,
                       {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35},
                       0x00,
                       true});

        // Certs from CDF: 4409, 440A, 440C (in PKCS#15 DF)
        readFile(conn, 0x4409, "Intermediate Sign cert");
        readFile(conn, 0x440A, "Intermediate Auth cert");
        readFile(conn, 0x440C, "Auth end-entity cert");

        // Sign cert is in eSignature DF: 3F00/0DF5/0115
        // Need to navigate: SELECT MF, SELECT 0DF5, SELECT 0115
        printf("\n--- Sign cert (3F00/0DF5/0115) ---\n");
        conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true});
        auto s2 = conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x0D, 0xF5}, 0x00, true});
        printf("  SELECT 0DF5: SW=%02X%02X\n", s2.sw1, s2.sw2);
        if (s2.isSuccess()) {
            readFile(conn, 0x0115, "Sign end-entity cert");
        }

        // VERIFY PIN probe
        printf("\n======== VERIFY PIN PROBE ========\n");
        printf("Sending VERIFY with empty data to discover PIN references\n\n");

        // Re-select PKCS#15
        conn.transmit({0x00,
                       0xA4,
                       0x04,
                       0x00,
                       {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35},
                       0x00,
                       true});

        for (uint8_t p2 = 0x00; p2 <= 0x85; ++p2) {
            auto v = conn.transmit({0x00, 0x20, 0x00, p2, {}, 0, false});
            if (v.sw1 == 0x6A && v.sw2 == 0x88)
                continue; // ref not found, skip
            if (v.sw1 == 0x6A && v.sw2 == 0x82)
                continue; // not found
            printf("  VERIFY P2=%02X: SW=%02X%02X", p2, v.sw1, v.sw2);
            if (v.sw1 == 0x63 && (v.sw2 & 0xF0) == 0xC0)
                printf("  *** PIN FOUND — %d tries left ***", v.sw2 & 0x0F);
            else if (v.sw1 == 0x69 && v.sw2 == 0x83)
                printf("  *** PIN FOUND — BLOCKED ***");
            else if (v.sw1 == 0x69 && v.sw2 == 0x82)
                printf("  (security not satisfied)");
            else if (v.sw1 == 0x90 && v.sw2 == 0x00)
                printf("  *** PIN ALREADY VERIFIED ***");
            else if (v.sw1 == 0x6D)
                printf("  (INS not supported)");
            printf("\n");
        }

        // Also try in eSignature DF context
        printf("\n--- VERIFY in eSignature DF context ---\n");
        conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true});
        conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x0D, 0xF5}, 0x00, true});

        for (uint8_t p2 = 0x00; p2 <= 0x85; ++p2) {
            auto v = conn.transmit({0x00, 0x20, 0x00, p2, {}, 0, false});
            if (v.sw1 == 0x6A && v.sw2 == 0x88)
                continue;
            if (v.sw1 == 0x6A && v.sw2 == 0x82)
                continue;
            printf("  VERIFY P2=%02X: SW=%02X%02X", p2, v.sw1, v.sw2);
            if (v.sw1 == 0x63 && (v.sw2 & 0xF0) == 0xC0)
                printf("  *** PIN FOUND — %d tries left ***", v.sw2 & 0x0F);
            else if (v.sw1 == 0x69 && v.sw2 == 0x83)
                printf("  *** PIN FOUND — BLOCKED ***");
            else if (v.sw1 == 0x90 && v.sw2 == 0x00)
                printf("  *** PIN ALREADY VERIFIED ***");
            printf("\n");
        }

        printf("\n======== PROBE COMPLETE ========\n");

    } catch (const std::exception& ex) {
        fprintf(stderr, "\nError: %s\n", ex.what());
        return 1;
    }
    return 0;
}

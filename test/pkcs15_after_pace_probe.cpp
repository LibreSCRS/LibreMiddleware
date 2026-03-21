// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me
//
// PKCS#15-after-PACE probe: authenticates via PACE (CAN), then probes
// PKCS#15 applet structure. Tests the hypothesis that PKCS#15 becomes
// accessible after eMRTD authentication.
//
// Usage: pkcs15_after_pace_probe <CAN> [reader-name]

#include "smartcard/pcsc_connection.h"
#include "smartcard/apdu.h"
#include <emrtd/emrtd_card.h>
#include <emrtd/crypto/pace.h>

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static void hexDump(const char* prefix, const std::vector<uint8_t>& data)
{
    printf("%s (%zu bytes):\n  ", prefix, data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        printf("%02X ", data[i]);
        if (i % 24 == 23 && i + 1 < data.size())
            printf("\n  ");
    }
    printf("\n");
}

static void printSW(uint8_t sw1, uint8_t sw2)
{
    printf("  SW=%02X%02X", sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00)
        printf(" OK");
    else if (sw1 == 0x6A && sw2 == 0x82)
        printf(" NOT FOUND");
    else if (sw1 == 0x69 && sw2 == 0x82)
        printf(" SECURITY NOT SATISFIED");
    else if (sw1 == 0x69 && sw2 == 0x85)
        printf(" CONDITIONS NOT SATISFIED");
    else if (sw1 == 0x61)
        printf(" (more data: %d bytes)", sw2);
    printf("\n");
}

static bool trySelect(smartcard::PCSCConnection& conn, const char* name, const std::vector<uint8_t>& aid)
{
    printf("\n--- SELECT %s ---\n", name);
    auto resp = conn.transmit({0x00, 0xA4, 0x04, 0x00, aid, 0x00, true});
    printSW(resp.sw1, resp.sw2);
    if (!resp.data.empty())
        hexDump("  Response", resp.data);
    return resp.isSuccess();
}

static bool trySelectByPath(smartcard::PCSCConnection& conn, const char* name, uint16_t fid)
{
    printf("\n--- SELECT %s (FID %04X) ---\n", name, fid);
    uint8_t fidH = static_cast<uint8_t>((fid >> 8) & 0xFF);
    uint8_t fidL = static_cast<uint8_t>(fid & 0xFF);

    // Try P1=0x02 (select EF under current DF)
    auto resp = conn.transmit({0x00, 0xA4, 0x02, 0x0C, {fidH, fidL}, 0x00, true});
    if (!resp.isSuccess()) {
        // Try P1=0x00
        resp = conn.transmit({0x00, 0xA4, 0x00, 0x00, {fidH, fidL}, 0x00, true});
    }
    printSW(resp.sw1, resp.sw2);
    if (!resp.data.empty())
        hexDump("  Response", resp.data);
    return resp.isSuccess();
}

static std::vector<uint8_t> readBinary(smartcard::PCSCConnection& conn, const char* name)
{
    std::vector<uint8_t> fileData;
    size_t offset = 0;
    while (offset < 8192) {
        uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0x7F);
        uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
        auto resp = conn.transmit({0x00, 0xB0, p1, p2, {}, 0x00, true});
        if (!resp.isSuccess() || resp.data.empty())
            break;
        fileData.insert(fileData.end(), resp.data.begin(), resp.data.end());
        offset += resp.data.size();
        if (resp.data.size() < 256)
            break;
    }
    if (!fileData.empty())
        hexDump(name, fileData);
    else
        printf("  %s: (empty or unreadable)\n", name);
    return fileData;
}

int main(int argc, char* argv[])
{
    printf("=== PKCS#15 After PACE Probe ===\n\n");

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <CAN> [reader-name]\n", argv[0]);
        return 1;
    }

    std::string can = argv[1];
    printf("CAN: %s\n", can.c_str());

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty()) {
        fprintf(stderr, "No readers found.\n");
        return 1;
    }

    std::string readerName;
    if (argc >= 3) {
        readerName = argv[2];
    } else {
        readerName = readers[0];
        printf("Available readers:\n");
        for (const auto& r : readers)
            printf("  %s %s\n", (r == readerName ? ">>>" : "   "), r.c_str());
    }

    printf("Using: %s\n\n", readerName.c_str());

    try {
        smartcard::PCSCConnection conn(readerName);

        auto atr = conn.getATR();
        printf("ATR: ");
        for (auto b : atr)
            printf("%02X ", b);
        printf("\n");

        // ============================================================
        // Step 1: Try SELECT PKCS#15 BEFORE authentication
        // ============================================================
        printf("\n======== BEFORE PACE ========\n");

        const std::vector<uint8_t> PKCS15_AID = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50,
                                                 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
        const std::vector<uint8_t> SSCD_AID = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x53, 0x53, 0x43, 0x44};

        trySelect(conn, "PKCS#15 (before PACE)", PKCS15_AID);
        trySelect(conn, "eSignature/SSCD (before PACE)", SSCD_AID);

        // Also try path-based selection to PKCS#15 DF
        printf("\n--- SELECT MF ---\n");
        auto mfResp = conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true});
        printSW(mfResp.sw1, mfResp.sw2);

        trySelectByPath(conn, "PKCS#15 DF (path 5015)", 0x5015);
        trySelectByPath(conn, "eSignature DF (path 0DF5)", 0x0DF5);

        // ============================================================
        // Step 2: Authenticate via PACE with CAN
        // ============================================================
        printf("\n======== PACE AUTHENTICATION ========\n");

        emrtd::EMRTDCard card(conn, can);
        auto authResult = card.authenticate();
        printf("PACE result: %s\n", authResult.success ? "SUCCESS" : "FAILED");
        if (!authResult.success) {
            printf("Error: %s\n", authResult.error.c_str());
            printf("Auth method: %d\n", static_cast<int>(authResult.method));
            return 1;
        }
        printf("Auth method: %s\n", authResult.method == emrtd::AuthMethod::PACE_CAN   ? "PACE_CAN"
                                    : authResult.method == emrtd::AuthMethod::PACE_MRZ ? "PACE_MRZ"
                                    : authResult.method == emrtd::AuthMethod::BAC      ? "BAC"
                                                                                       : "unknown");

        // ============================================================
        // Step 3: Try SELECT PKCS#15 AFTER authentication
        // ============================================================
        printf("\n======== AFTER PACE ========\n");

        // Note: after PACE, we have Secure Messaging active on the eMRTD applet.
        // Selecting a different applet (PKCS#15) may or may not invalidate SM.
        // Some cards maintain security state at card level, not applet level.

        bool pkcs15ok = trySelect(conn, "PKCS#15 (after PACE, raw SELECT)", PKCS15_AID);
        bool sscdok = trySelect(conn, "eSignature/SSCD (after PACE, raw SELECT)", SSCD_AID);

        // Try path-based too
        printf("\n--- SELECT MF (after PACE) ---\n");
        mfResp = conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true});
        printSW(mfResp.sw1, mfResp.sw2);

        bool pkcs15PathOk = trySelectByPath(conn, "PKCS#15 DF (path 5015, after PACE)", 0x5015);
        bool sscdPathOk = trySelectByPath(conn, "eSignature DF (path 0DF5, after PACE)", 0x0DF5);

        // ============================================================
        // Step 4: If PKCS#15 accessible, read structure
        // ============================================================
        if (pkcs15ok || pkcs15PathOk) {
            printf("\n======== PKCS#15 STRUCTURE (after PACE) ========\n");

            // Re-select PKCS#15
            if (pkcs15ok)
                conn.transmit({0x00, 0xA4, 0x04, 0x00, PKCS15_AID, 0x00, true});
            else
                conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x50, 0x15}, 0x00, true});

            // Read standard PKCS#15 files
            struct FileEntry
            {
                uint16_t fid;
                const char* name;
            };
            FileEntry files[] = {
                {0x5031, "EF.ODF"},
                {0x5032, "EF.TokenInfo"},
                {0x4401, "EF.PrKDF (Private Keys)"},
                {0x4402, "EF.PuKDF (Public Keys)"},
                {0x4404, "EF.CDF (Certificates)"},
                {0x4406, "EF.AODF (Auth/PINs)"},
            };

            for (const auto& f : files) {
                if (trySelectByPath(conn, f.name, f.fid)) {
                    readBinary(conn, f.name);
                }
            }

            // Try reading certificate files
            printf("\n--- Certificate file scan ---\n");
            for (uint16_t fid = 0x4101; fid <= 0x4110; ++fid) {
                uint8_t fidH = static_cast<uint8_t>((fid >> 8) & 0xFF);
                uint8_t fidL = static_cast<uint8_t>(fid & 0xFF);
                auto selResp = conn.transmit({0x00, 0xA4, 0x02, 0x0C, {fidH, fidL}, 0x00, true});
                if (selResp.isSuccess()) {
                    printf("  *** FOUND file at FID %04X\n", fid);
                    auto peek = conn.transmit({0x00, 0xB0, 0x00, 0x00, {}, 0x10, true});
                    if (!peek.data.empty())
                        hexDump("    First 16 bytes", peek.data);
                }
            }
        }

        if (sscdok || sscdPathOk) {
            printf("\n======== eSignature/SSCD STRUCTURE (after PACE) ========\n");

            if (sscdok)
                conn.transmit({0x00, 0xA4, 0x04, 0x00, SSCD_AID, 0x00, true});
            else
                conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x0D, 0xF5}, 0x00, true});

            // Same PKCS#15 files within SSCD context
            if (trySelectByPath(conn, "EF.ODF (SSCD)", 0x5031))
                readBinary(conn, "EF.ODF (SSCD)");
            if (trySelectByPath(conn, "EF.TokenInfo (SSCD)", 0x5032))
                readBinary(conn, "EF.TokenInfo (SSCD)");
            if (trySelectByPath(conn, "EF.CDF (SSCD)", 0x4404))
                readBinary(conn, "EF.CDF (SSCD)");
            if (trySelectByPath(conn, "EF.AODF (SSCD)", 0x4406))
                readBinary(conn, "EF.AODF (SSCD)");
        }

        if (!pkcs15ok && !pkcs15PathOk && !sscdok && !sscdPathOk) {
            printf("\n======== PKCS#15/SSCD STILL NOT ACCESSIBLE AFTER PACE ========\n");
            printf("The card may require:\n");
            printf("  - Contact interface (not contactless)\n");
            printf("  - PIN verification before PKCS#15 access\n");
            printf("  - Extended Access Control (EAC) / Terminal Authentication\n");
        }

        printf("\n======== PROBE COMPLETE ========\n");

    } catch (const std::exception& ex) {
        fprintf(stderr, "\nError: %s\n", ex.what());
        return 1;
    }
    return 0;
}

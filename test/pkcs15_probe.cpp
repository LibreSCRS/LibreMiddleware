// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// PKCS#15 applet probe: discovers PKCS#15 structure on cards that may have
// multiple applets (e.g., eMRTD + PKI). Sends raw APDUs to find:
//   1. Which AIDs are present (PKCS#15, PIV, various national IDs)
//   2. EF.DIR contents (application directory)
//   3. PKCS#15 file structure (ODF, TokenInfo, certificates, keys, PINs)
//
// Usage: pkcs15_probe [reader-name]

#include "smartcard/pcsc_connection.h"
#include "smartcard/apdu.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static void hexDump(const char* prefix, const std::vector<uint8_t>& data)
{
    printf("%s (%zu bytes): ", prefix, data.size());
    for (size_t i = 0; i < data.size(); ++i) {
        printf("%02X ", data[i]);
        if (i % 32 == 31 && i + 1 < data.size())
            printf("\n%*s", static_cast<int>(strlen(prefix) + 12), "");
    }
    printf("\n");
}

static void printSW(const smartcard::APDUResponse& resp)
{
    printf("  SW=%02X%02X", resp.sw1, resp.sw2);
    if (resp.isSuccess())
        printf(" OK");
    else if (resp.sw1 == 0x6A && resp.sw2 == 0x82)
        printf(" NOT FOUND");
    else if (resp.sw1 == 0x6A && resp.sw2 == 0x86)
        printf(" INCORRECT P1/P2");
    else if (resp.sw1 == 0x69 && resp.sw2 == 0x82)
        printf(" SECURITY NOT SATISFIED");
    else if (resp.sw1 == 0x6D)
        printf(" INS NOT SUPPORTED");
    printf("\n");
}

// Try to SELECT an AID and report result
static bool trySelectAID(smartcard::PCSCConnection& conn, const char* name, const std::vector<uint8_t>& aid)
{
    printf("\n--- SELECT %s ---\n", name);
    printf("  AID: ");
    for (auto b : aid)
        printf("%02X", b);
    printf("\n");

    try {
        auto resp = conn.transmit({0x00, 0xA4, 0x04, 0x00, aid, 0x00, true});
        printSW(resp);
        if (!resp.data.empty())
            hexDump("  Response", resp.data);
        return resp.isSuccess();
    } catch (const std::exception& e) {
        printf("  Exception: %s\n", e.what());
        return false;
    }
}

// Read a file by FID (SELECT + READ BINARY in chunks)
static std::vector<uint8_t> readFileByFID(smartcard::PCSCConnection& conn, uint16_t fid, const char* name)
{
    printf("\n--- READ %s (FID %04X) ---\n", name, fid);

    // SELECT by FID
    uint8_t fidH = static_cast<uint8_t>((fid >> 8) & 0xFF);
    uint8_t fidL = static_cast<uint8_t>(fid & 0xFF);

    auto selResp = conn.transmit({0x00, 0xA4, 0x02, 0x0C, {fidH, fidL}, 0x00, true});
    if (!selResp.isSuccess()) {
        // Try P1=0x00 P2=0x00
        selResp = conn.transmit({0x00, 0xA4, 0x00, 0x00, {fidH, fidL}, 0x00, true});
    }
    printSW(selResp);
    if (!selResp.isSuccess() && selResp.sw1 != 0x61)
        return {};

    // READ BINARY in chunks
    std::vector<uint8_t> fileData;
    size_t offset = 0;
    while (offset < 8192) { // safety limit
        uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0x7F);
        uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
        auto readResp = conn.transmit({0x00, 0xB0, p1, p2, {}, 0x00, true});

        if (!readResp.isSuccess() || readResp.data.empty())
            break;

        fileData.insert(fileData.end(), readResp.data.begin(), readResp.data.end());
        offset += readResp.data.size();

        // Less than 256 bytes returned = last chunk
        if (readResp.data.size() < 256)
            break;
    }

    if (!fileData.empty())
        hexDump("  Data", fileData);
    else
        printf("  (empty or unreadable)\n");

    return fileData;
}

// Read file using short FID (SFI) in READ BINARY P1
static std::vector<uint8_t> readFileBySFI(smartcard::PCSCConnection& conn, uint8_t sfi, const char* name)
{
    printf("\n--- READ %s (SFI %02X) ---\n", name, sfi);

    std::vector<uint8_t> fileData;
    // First read: P1 = 0x80 | SFI, P2 = 0x00
    auto resp = conn.transmit({0x00, 0xB0, static_cast<uint8_t>(0x80 | sfi), 0x00, {}, 0x00, true});
    printSW(resp);
    if (!resp.isSuccess() || resp.data.empty()) {
        printf("  (empty or unreadable)\n");
        return {};
    }
    fileData = resp.data;

    // Continue reading if we got a full chunk
    size_t offset = fileData.size();
    while (offset < 8192 && resp.data.size() >= 256) {
        uint8_t p1 = static_cast<uint8_t>((offset >> 8) & 0x7F);
        uint8_t p2 = static_cast<uint8_t>(offset & 0xFF);
        resp = conn.transmit({0x00, 0xB0, p1, p2, {}, 0x00, true});
        if (!resp.isSuccess() || resp.data.empty())
            break;
        fileData.insert(fileData.end(), resp.data.begin(), resp.data.end());
        offset += resp.data.size();
        if (resp.data.size() < 256)
            break;
    }

    hexDump("  Data", fileData);
    return fileData;
}

int main(int argc, char* argv[])
{
    printf("=== PKCS#15 Applet Probe ===\n\n");

    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty()) {
        fprintf(stderr, "No readers found.\n");
        return 1;
    }

    std::string readerName;
    if (argc >= 2) {
        readerName = argv[1];
    } else {
        // Pick contact reader if available (prefer slot 01)
        for (const auto& r : readers) {
            if (r.find("5422 Smartcard Reader") != std::string::npos || r.find("01 00") != std::string::npos) {
                readerName = r;
                break;
            }
        }
        if (readerName.empty())
            readerName = readers.back(); // last reader = usually contact
        printf("Available readers:\n");
        for (const auto& r : readers)
            printf("  %s %s\n", (r == readerName ? ">>>" : "   "), r.c_str());
    }

    printf("Using: %s\n", readerName.c_str());

    try {
        smartcard::PCSCConnection conn(readerName);

        auto atr = conn.getATR();
        printf("ATR: ");
        for (auto b : atr)
            printf("%02X ", b);
        printf("\n");

        // ============================================================
        // Phase 1: Probe known AIDs
        // ============================================================
        printf("\n======== PHASE 1: AID PROBING ========\n");

        struct AIDEntry
        {
            const char* name;
            std::vector<uint8_t> aid;
        };

        AIDEntry aids[] = {
            {"PKCS#15", {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35}},
            {"eMRTD (ICAO)", {0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01}},
            {"PIV", {0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01, 0x00}},
            {"OpenPGP", {0xD2, 0x76, 0x00, 0x01, 0x24, 0x01}},
            {"GlobalPlatform ISD", {0xA0, 0x00, 0x00, 0x01, 0x51, 0x00, 0x00}},
            {"CardEdge (MS)", {0xA0, 0x00, 0x00, 0x00, 0x01, 0x01}},
        };

        bool hasPKCS15 = false;
        for (auto& entry : aids) {
            bool ok = trySelectAID(conn, entry.name, entry.aid);
            if (ok && std::string(entry.name) == "PKCS#15")
                hasPKCS15 = true;
        }

        // ============================================================
        // Phase 2: Read EF.DIR (MF level)
        // ============================================================
        printf("\n======== PHASE 2: EF.DIR (Application Directory) ========\n");

        // SELECT MF first
        printf("\n--- SELECT MF ---\n");
        auto mfResp = conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true});
        printSW(mfResp);

        // EF.DIR is at FID 2F00 under MF
        readFileByFID(conn, 0x2F00, "EF.DIR");

        // Also try SFI 30 (common for EF.DIR)
        readFileBySFI(conn, 0x1E, "EF.DIR (SFI 30)");

        // ============================================================
        // Phase 3: If PKCS#15 found, read its structure
        // ============================================================
        if (hasPKCS15) {
            printf("\n======== PHASE 3: PKCS#15 STRUCTURE ========\n");

            // Re-select PKCS#15 applet
            conn.transmit({0x00,
                           0xA4,
                           0x04,
                           0x00,
                           {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35},
                           0x00,
                           true});

            // Standard PKCS#15 FIDs:
            // 5031 = EF.ODF (Object Directory File)
            // 5032 = EF.TokenInfo
            // 5033 = EF.UnusedSpace
            // 4401 = EF(PrKDF) - Private Key Directory
            // 4402 = EF(PuKDF) - Public Key Directory
            // 4403 = EF(SKD)   - Secret Key Directory (symmetric)
            // 4404 = EF(CDF)   - Certificate Directory
            // 4405 = EF(DODF)  - Data Object Directory
            // 4406 = EF(AODF)  - Auth Object Directory (PINs)

            readFileByFID(conn, 0x5031, "EF.ODF");
            readFileByFID(conn, 0x5032, "EF.TokenInfo");

            // Try common PKCS#15 directories
            readFileByFID(conn, 0x4401, "EF.PrKDF (Private Keys)");
            readFileByFID(conn, 0x4402, "EF.PuKDF (Public Keys)");
            readFileByFID(conn, 0x4404, "EF.CDF (Certificates)");
            readFileByFID(conn, 0x4406, "EF.AODF (Auth/PINs)");

            // Also try reading via SFIs (some cards use SFI instead of FID)
            printf("\n--- Trying SFI reads ---\n");
            readFileBySFI(conn, 0x11, "EF.ODF (SFI 17)");
            readFileBySFI(conn, 0x12, "EF.TokenInfo (SFI 18)");
        } else {
            printf("\n======== PHASE 3: SKIPPED (no PKCS#15 applet found) ========\n");

            // Try reading PKCS#15-like files at MF level anyway
            printf("\nTrying PKCS#15 FIDs at MF level...\n");
            conn.transmit({0x00, 0xA4, 0x00, 0x00, {0x3F, 0x00}, 0x00, true});
            readFileByFID(conn, 0x5031, "EF.ODF (at MF)");
            readFileByFID(conn, 0x5032, "EF.TokenInfo (at MF)");
        }

        // ============================================================
        // Phase 4: Try to enumerate certificates
        // ============================================================
        printf("\n======== PHASE 4: CERTIFICATE ENUMERATION ========\n");

        // Common cert FIDs
        uint16_t certFids[] = {
            0x4101, 0x4102, 0x4103, 0x4104, // Common PKCS#15 cert files
            0xCE01, 0xCE02, 0xCE03,         // Alternative cert files
            0x0001, 0x0002, 0x0003,         // Some cards use low FIDs
        };

        if (hasPKCS15) {
            conn.transmit({0x00,
                           0xA4,
                           0x04,
                           0x00,
                           {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35},
                           0x00,
                           true});
        }

        for (auto fid : certFids) {
            char name[32];
            snprintf(name, sizeof(name), "Cert FID %04X", fid);

            uint8_t fidH = static_cast<uint8_t>((fid >> 8) & 0xFF);
            uint8_t fidL = static_cast<uint8_t>(fid & 0xFF);

            auto selResp = conn.transmit({0x00, 0xA4, 0x02, 0x0C, {fidH, fidL}, 0x00, true});
            if (selResp.isSuccess()) {
                printf("\n  *** FOUND file at FID %04X ***\n", fid);
                // Read first 4 bytes to check if it's a cert (starts with 0x30)
                auto peek = conn.transmit({0x00, 0xB0, 0x00, 0x00, {}, 0x04, true});
                if (!peek.data.empty()) {
                    printf("  First bytes: ");
                    for (auto b : peek.data)
                        printf("%02X ", b);
                    printf("%s\n", (peek.data[0] == 0x30) ? "(SEQUENCE — likely certificate)" : "");
                }
            }
        }

        printf("\n======== PROBE COMPLETE ========\n");

    } catch (const std::exception& ex) {
        fprintf(stderr, "\nError: %s\n", ex.what());
        return 1;
    }
    return 0;
}

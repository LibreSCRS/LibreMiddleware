// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me
//
// PKCS#15 card investigation probe.
// Run with a card inserted; outputs a complete hex trace suitable for analysis.
// Usage: pkcs15_probe [reader-name]

#include "smartcard/pcsc_connection.h"
#include "smartcard/apdu.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <stdexcept>

// ---------------------------------------------------------------------------
// Output helpers
// ---------------------------------------------------------------------------

static void hexDump(const std::vector<uint8_t>& data)
{
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0)
            printf("  %04zx: ", i);
        printf("%02X ", data[i]);
        if ((i % 16 == 15) || (i + 1 == data.size()))
            printf("\n");
    }
}

static void printSW(uint8_t sw1, uint8_t sw2)
{
    printf("SW: %02X %02X", sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00)
        printf("  (SUCCESS)");
    else if (sw1 == 0x61)
        printf("  (more data: %d bytes)", sw2);
    else if (sw1 == 0x6A && sw2 == 0x82)
        printf("  (FILE NOT FOUND)");
    else if (sw1 == 0x6A && sw2 == 0x86)
        printf("  (INCORRECT P1/P2)");
    else if (sw1 == 0x69 && sw2 == 0x82)
        printf("  (SECURITY STATUS NOT SATISFIED)");
    else if (sw1 == 0x69 && sw2 == 0x85)
        printf("  (CONDITIONS OF USE NOT SATISFIED)");
    else if (sw1 == 0x6D && sw2 == 0x00)
        printf("  (INS NOT SUPPORTED)");
    else if (sw1 == 0x6E && sw2 == 0x00)
        printf("  (CLA NOT SUPPORTED)");
    printf("\n");
}

static void printResp(const smartcard::APDUResponse& resp)
{
    printSW(resp.sw1, resp.sw2);
    if (!resp.data.empty()) {
        printf("  Response data (%zu bytes):\n", resp.data.size());
        hexDump(resp.data);
    }
}

// ---------------------------------------------------------------------------
// APDU builders not in the shared library
// ---------------------------------------------------------------------------

// SELECT EF from current DF (P1=0x02, P2=0x04 = no FCP returned)
static smartcard::APDUCommand selectEFcurrent(uint8_t fid1, uint8_t fid2)
{
    return {0x00, 0xA4, 0x02, 0x04, {fid1, fid2}, 0, false};
}

// SELECT EF from current DF, return FCP (P1=0x02, P2=0x00)
static smartcard::APDUCommand selectEFcurrentFCP(uint8_t fid1, uint8_t fid2)
{
    return {0x00, 0xA4, 0x02, 0x00, {fid1, fid2}, 4, true};
}

// SELECT by FID from MF (P1=0x00, P2=0x04)
static smartcard::APDUCommand selectByFIDfromMF(uint8_t fid1, uint8_t fid2)
{
    return {0x00, 0xA4, 0x00, 0x04, {fid1, fid2}, 0, false};
}

// GET DATA
static smartcard::APDUCommand getData(uint8_t p1, uint8_t p2)
{
    return {0x00, 0xCA, p1, p2, {}, 0xFF, true};
}

// MSE SET for PSO signature preparation (to probe key availability)
static smartcard::APDUCommand mseSet(const std::vector<uint8_t>& data)
{
    return {0x00, 0x22, 0x41, 0xB6, data, 0, false};
}

// ---------------------------------------------------------------------------
// CardEdge PKI filesystem helpers
// (mirrors eidcard::readCertificates() navigation logic)
// ---------------------------------------------------------------------------

// CardEdge PKI applet read chunk — applet internal buffer is 128 bytes.
constexpr uint8_t CE_READ_CHUNK = 0x80;

struct CeDirEntry
{
    std::string name;
    uint16_t fid;
    bool isDir;
};

// Parse a CardEdge directory file.
// Header (10 bytes): LeftFiles(1) LeftDirs(1) NextFileFID(2 LE) NextDirFID(2 LE)
//                    EntriesCount(2 LE) WriteACL(2 LE)
// Entry  (12 bytes): Name(8) FID(2 LE) IsDir(1) pad(1)
static std::vector<CeDirEntry> parseCeDirFile(const std::vector<uint8_t>& data)
{
    std::vector<CeDirEntry> entries;
    constexpr size_t HEADER = 10, ENTRY = 12;
    if (data.size() < HEADER) {
        printf("    (dir data too short: %zu bytes)\n", data.size());
        return entries;
    }

    uint16_t count = static_cast<uint16_t>(data[6]) | (static_cast<uint16_t>(data[7]) << 8);
    printf("    CE dir header: LeftFiles=%u LeftDirs=%u NextFileFID=%04X "
           "NextDirFID=%04X Count=%u\n",
           data[0], data[1], static_cast<uint16_t>(data[2] | (data[3] << 8)),
           static_cast<uint16_t>(data[4] | (data[5] << 8)), count);

    for (uint16_t i = 0; i < count; ++i) {
        size_t off = HEADER + i * ENTRY;
        if (off + ENTRY > data.size())
            break;
        CeDirEntry e;
        e.name.assign(reinterpret_cast<const char*>(data.data() + off),
                      strnlen(reinterpret_cast<const char*>(data.data() + off), 8));
        e.fid = static_cast<uint16_t>(data[off + 8]) | (static_cast<uint16_t>(data[off + 9]) << 8);
        e.isDir = data[off + 10] != 0;
        printf("    Entry[%u]: name=\"%s\" fid=%04X isDir=%d\n", i, e.name.c_str(), e.fid, (int)e.isDir);
        entries.push_back(std::move(e));
    }
    return entries;
}

// SELECT a CardEdge PKI file by FID using selectByFileId (P1=0x00, P2=0x00 with Le=0).
// Parses FCI bytes [2:3] (big-endian) for file size, then reads in 128-byte chunks.
static std::vector<uint8_t> readCeFile(smartcard::PCSCConnection& conn, uint16_t fid)
{
    uint8_t h = static_cast<uint8_t>((fid >> 8) & 0xFF);
    uint8_t l = static_cast<uint8_t>(fid & 0xFF);

    auto sel = conn.transmit(smartcard::selectByFileId(h, l));
    printf("  SELECT FID %04X (P1=00 P2=00 Le=00): ", fid);
    printSW(sel.sw1, sel.sw2);
    if (!sel.isSuccess())
        return {};

    if (!sel.data.empty()) {
        printf("    FCI (%zu bytes): ", sel.data.size());
        for (auto b : sel.data)
            printf("%02X ", b);
        printf("\n");
    }

    uint16_t fileSize = 0;
    if (sel.data.size() >= 4)
        fileSize = static_cast<uint16_t>((sel.data[2] << 8) | sel.data[3]);
    printf("    File size from FCI [2:3] big-endian: %u\n", fileSize);

    if (fileSize == 0) {
        // Try a single read to see if the card returns something anyway
        auto rd = conn.transmit(smartcard::readBinary(0, CE_READ_CHUNK));
        printf("    READ BINARY (size=0 probe): ");
        printResp(rd);
        if (rd.isSuccess() && !rd.data.empty())
            return rd.data;
        return {};
    }

    std::vector<uint8_t> data;
    data.reserve(fileSize);
    for (uint16_t offset = 0; offset < fileSize;) {
        uint8_t toRead = static_cast<uint8_t>(
            std::min(static_cast<uint16_t>(CE_READ_CHUNK), static_cast<uint16_t>(fileSize - offset)));
        auto rd = conn.transmit(smartcard::readBinary(offset, toRead));
        if (!rd.isSuccess() || rd.data.empty()) {
            printf("    READ BINARY at offset %u: ", offset);
            printSW(rd.sw1, rd.sw2);
            break;
        }
        data.insert(data.end(), rd.data.begin(), rd.data.end());
        offset += static_cast<uint16_t>(rd.data.size());
    }
    return data;
}

// ---------------------------------------------------------------------------
// Read full file content after a successful SELECT
// ---------------------------------------------------------------------------

static std::vector<uint8_t> readFileContent(smartcard::PCSCConnection& conn, size_t sizeHint = 0)
{
    std::vector<uint8_t> result;
    uint16_t offset = 0;

    while (true) {
        uint8_t toRead = 0xFF;
        if (sizeHint > 0 && (result.size() + toRead) > sizeHint)
            toRead = static_cast<uint8_t>(sizeHint - result.size());

        auto resp = conn.transmit(smartcard::readBinary(offset, toRead));
        if (!resp.isSuccess()) {
            if (result.empty())
                printf("  READ BINARY failed: ");
            else
                printf("  READ BINARY stopped at offset %u: ", offset);
            printSW(resp.sw1, resp.sw2);
            break;
        }
        if (resp.data.empty())
            break;
        result.insert(result.end(), resp.data.begin(), resp.data.end());
        offset += static_cast<uint16_t>(resp.data.size());
        if (resp.data.size() < toRead)
            break;
        if (sizeHint > 0 && result.size() >= sizeHint)
            break;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Try to read a file by trying several SELECT variants
// Returns the file content (empty if all selects failed).
// ---------------------------------------------------------------------------

static std::vector<uint8_t> tryReadEF(smartcard::PCSCConnection& conn, uint8_t fid1, uint8_t fid2, const char* name)
{
    printf("\n--- EF(%s) [%02X %02X] ---\n", name, fid1, fid2);

    // Variant A: P1=0x02, P2=0x04 (standard JavaCard PKCS#15)
    printf("  SELECT (P1=02 P2=04, current DF): ");
    auto respA = conn.transmit(selectEFcurrent(fid1, fid2));
    printSW(respA.sw1, respA.sw2);
    if (respA.isSuccess()) {
        auto data = readFileContent(conn);
        if (!data.empty()) {
            printf("  Content (%zu bytes):\n", data.size());
            hexDump(data);
        }
        return data;
    }

    // Variant B: P1=0x02, P2=0x00 (return FCP)
    printf("  SELECT (P1=02 P2=00, return FCP): ");
    auto respB = conn.transmit(selectEFcurrentFCP(fid1, fid2));
    printSW(respB.sw1, respB.sw2);
    if (!respB.data.empty()) {
        printf("  FCP:\n");
        hexDump(respB.data);
    }
    if (respB.isSuccess() || respB.sw1 == 0x61) {
        auto data = readFileContent(conn);
        if (!data.empty()) {
            printf("  Content (%zu bytes):\n", data.size());
            hexDump(data);
        }
        return data;
    }

    // Variant C: P1=0x00, P2=0x04 (from MF)
    printf("  SELECT (P1=00 P2=04, from MF): ");
    auto respC = conn.transmit(selectByFIDfromMF(fid1, fid2));
    printSW(respC.sw1, respC.sw2);
    if (respC.isSuccess()) {
        auto data = readFileContent(conn);
        if (!data.empty()) {
            printf("  Content (%zu bytes):\n", data.size());
            hexDump(data);
        }
        return data;
    }

    printf("  (all SELECT variants failed)\n");
    return {};
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char* argv[])
{
    printf("=== PKCS#15 Card Probe ===\n\n");

    // Select reader
    auto readers = smartcard::PCSCConnection::listReaders();
    if (readers.empty()) {
        fprintf(stderr, "No readers found.\n");
        return 1;
    }

    std::string readerName;
    if (argc >= 2) {
        readerName = argv[1];
    } else if (readers.size() == 1) {
        readerName = readers[0];
    } else {
        printf("Available readers:\n");
        for (size_t i = 0; i < readers.size(); ++i)
            printf("  [%zu] %s\n", i, readers[i].c_str());
        printf("Usage: pkcs15_probe [reader-name]\n");
        return 1;
    }

    printf("Reader: %s\n", readerName.c_str());

    try {
        smartcard::PCSCConnection conn(readerName);

        // Print ATR
        auto atr = conn.getATR();
        printf("ATR:    ");
        for (auto b : atr)
            printf("%02X ", b);
        printf("\n");

        // -------------------------------------------------------------------
        // Step 1 — SELECT PKCS#15 AID
        // -------------------------------------------------------------------
        printf("\n--- Step 1: SELECT PKCS#15 AID ---\n");
        const std::vector<uint8_t> AID_PKCS15 = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50,
                                                 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
        printf("  AID: ");
        for (auto b : AID_PKCS15)
            printf("%02X ", b);
        printf("\n  ");
        auto selResp = conn.transmit(smartcard::selectByAID(AID_PKCS15));
        printResp(selResp);

        if (!selResp.isSuccess()) {
            printf("\nPKCS#15 AID not found. Trying GlobalPlatform ISD...\n");
            const std::vector<uint8_t> AID_GP = {0xA0, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
            printf("  AID: ");
            for (auto b : AID_GP)
                printf("%02X ", b);
            printf("\n  ");
            auto gpResp = conn.transmit(smartcard::selectByAID(AID_GP));
            printResp(gpResp);
            if (!gpResp.isSuccess()) {
                printf("\nNo known AID responded. Stopping.\n");
                return 1;
            }
            printf("GP ISD responded. Card may need PKCS#15 AID with different bytes.\n");
            return 1;
        }

        // -------------------------------------------------------------------
        // Step 2 — Standard ISO 7816-15 PKCS#15 files
        // -------------------------------------------------------------------
        printf("\n=== Standard PKCS#15 files (ISO 7816-15) ===\n");

        // Must re-select PKCS#15 before each EF read since tryReadEF may
        // change current DF with P1=0x00 variants.
        auto resel = [&]() { conn.transmit(smartcard::selectByAID(AID_PKCS15)); };

        resel();
        auto tokenInfo = tryReadEF(conn, 0x50, 0x32, "TokenInfo");

        resel();
        auto odf = tryReadEF(conn, 0x50, 0x31, "ODF");

        // Common CDF paths referenced from ODF (try blindly)
        resel();
        tryReadEF(conn, 0x50, 0x34, "PrKDF"); // private key directory

        resel();
        tryReadEF(conn, 0x50, 0x35, "PuKDF"); // public key directory

        resel();
        tryReadEF(conn, 0x50, 0x36, "CDF"); // certificate directory

        resel();
        tryReadEF(conn, 0x50, 0x33, "AODF"); // authentication object directory

        // -------------------------------------------------------------------
        // Step 3 — GET DATA probes (some cards use instead of SELECT+READ)
        // -------------------------------------------------------------------
        printf("\n=== GET DATA probes ===\n");
        resel();
        for (auto [p1, p2, label] : std::initializer_list<std::tuple<uint8_t, uint8_t, const char*>>{
                 {0x00, 0x00, "P1=00 P2=00"},
                 {0x7F, 0x70, "BER-TLV dir (7F70)"},
                 {0x5F, 0x50, "URL (5F50)"},
                 {0xDF, 0x28, "DF.28"},
             }) {
            printf("  GET DATA (%s): ", label);
            auto resp = conn.transmit(getData(p1, p2));
            printResp(resp);
        }

        // -------------------------------------------------------------------
        // Step 4 — Try some non-standard FID paths (proprietary cards)
        // -------------------------------------------------------------------
        printf("\n=== Non-standard/proprietary FID attempts ===\n");
        resel();

        // Some GemXpresso/Axalto cards put certs at 0x4300, 0x4301 ...
        // Some cards use 0x0001, 0x0002 ...
        // Some use 0x1001, 0x1002 ...
        for (auto [f1, f2, label] : std::initializer_list<std::tuple<uint8_t, uint8_t, const char*>>{
                 {0x43, 0x00, "4300"},
                 {0x43, 0x01, "4301"},
                 {0x10, 0x01, "1001"},
                 {0x10, 0x02, "1002"},
                 {0x00, 0x01, "0001"},
                 {0x00, 0x02, "0002"},
                 {0x00, 0x30, "0030"},
                 {0x00, 0x31, "0031"},
                 {0x3F, 0x00, "MF (3F00)"},
             }) {
            printf("  SELECT EF %s (P1=02): ", label);
            auto resp = conn.transmit(selectEFcurrent(f1, f2));
            printSW(resp.sw1, resp.sw2);
            if (resp.isSuccess()) {
                auto data = readFileContent(conn);
                if (!data.empty()) {
                    printf("  Content (%zu bytes):\n", data.size());
                    hexDump(data);
                }
            }
            resel();
        }

        // -------------------------------------------------------------------
        // Step 5 — VERIFY PIN status (don't use PIN yet, just check ref)
        // -------------------------------------------------------------------
        printf("\n=== PIN reference probe (status only, no PIN sent) ===\n");
        resel();
        for (uint8_t ref : {0x01, 0x02, 0x81, 0x82, 0x00, 0x80}) {
            printf("  VERIFY PIN status (P2=%02X): ", ref);
            auto resp = conn.transmit(smartcard::verifyPINStatus(ref));
            printSW(resp.sw1, resp.sw2);
            // 63 Cx = C-x retries remaining (success reading status)
            // 69 83 = blocked
            // 6A 86 = ref not found
        }

        // -------------------------------------------------------------------
        // Step 6 — CardEdge PKI filesystem navigation
        // The eID Gemalto2014 uses the same AID + PIN ref 0x80.
        // CardEdge uses selectByFileId (P1=0x00 P2=0x00 with Le) for all PKI
        // file accesses. Root directory is at FID 0x7000.
        // -------------------------------------------------------------------
        printf("\n=== CardEdge PKI filesystem (P1=0x00 P2=0x00, like eID Gemalto) ===\n");

        resel();
        printf("\n--- Root directory (FID 0x7000) ---\n");
        auto ceRoot = readCeFile(conn, 0x7000);
        if (!ceRoot.empty()) {
            printf("  Raw root dir (%zu bytes):\n", ceRoot.size());
            hexDump(ceRoot);
            auto rootEntries = parseCeDirFile(ceRoot);
            for (const auto& re : rootEntries) {
                printf("\n  --- %s \"%s\" (FID %04X) ---\n", re.isDir ? "Dir" : "File", re.name.c_str(), re.fid);
                resel();
                auto subData = readCeFile(conn, re.fid);
                if (subData.empty()) {
                    printf("  (empty or unreadable)\n");
                    continue;
                }
                printf("  Raw (%zu bytes):\n", subData.size());
                hexDump(subData);
                if (re.isDir) {
                    auto subEntries = parseCeDirFile(subData);
                    for (const auto& se : subEntries) {
                        printf("\n    --- %s \"%s\" (FID %04X) ---\n", se.isDir ? "Dir" : "File", se.name.c_str(),
                               se.fid);
                        resel();
                        auto fileData = readCeFile(conn, se.fid);
                        if (!fileData.empty()) {
                            printf("    Content (%zu bytes):\n", fileData.size());
                            hexDump(fileData);
                        }
                        resel();
                    }
                }
                resel();
            }
        } else {
            printf("  Root dir at 0x7000 not accessible.\n");
            // Try a few adjacent FIDs in case the root is elsewhere
            for (uint16_t fid : {0x3F00u, 0x5000u, 0x5015u, 0xA000u}) {
                printf("\n  Trying FID %04X: ", fid);
                resel();
                auto d = readCeFile(conn, fid);
                if (!d.empty()) {
                    printf("  Content (%zu bytes):\n", d.size());
                    hexDump(d);
                }
            }
        }

        // -------------------------------------------------------------------
        // Step 7 — READ BINARY directly after AID select (no SELECT FILE)
        // Some applets expose a data stream directly without a file select.
        // -------------------------------------------------------------------
        printf("\n=== READ BINARY immediately after AID select (no SELECT FILE) ===\n");
        resel();
        {
            auto rb = conn.transmit(smartcard::readBinary(0, CE_READ_CHUNK));
            printf("  READ BINARY offset=0 len=128: ");
            printResp(rb);
        }

        // -------------------------------------------------------------------
        // Step 8 — SELECT by path (P1=0x08, as used by eID SERID data files)
        // -------------------------------------------------------------------
        printf("\n=== SELECT by path (P1=0x08 P2=0x00, from current DF) ===\n");
        for (auto [f1, f2, label] : std::initializer_list<std::tuple<uint8_t, uint8_t, const char*>>{
                 {0x70, 0x00, "7000 (CardEdge root)"},
                 {0x50, 0x31, "5031 (ODF)"},
                 {0x50, 0x32, "5032 (TokenInfo)"},
                 {0x3F, 0x00, "3F00 (MF)"},
             }) {
            printf("\n  SELECT PATH %s (P1=08): ", label);
            resel();
            auto resp = conn.transmit(smartcard::selectByPath(f1, f2));
            printResp(resp);
            if (resp.isSuccess() || resp.sw1 == 0x61) {
                auto data = readFileContent(conn);
                if (!data.empty()) {
                    printf("  Content (%zu bytes):\n", data.size());
                    hexDump(data);
                }
            }
        }

        printf("\n=== Probe complete ===\n");
    } catch (const std::exception& ex) {
        fprintf(stderr, "\nError: %s\n", ex.what());
        return 1;
    }
    return 0;
}

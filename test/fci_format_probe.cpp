// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// FCI format probe: tests whether CardEdge SELECT FILE ever returns
// ISO 7816-4 TLV-wrapped FCI (tag 0x6F or 0x62).
//
// Background: OpenSC's iso7816_select_file() checks apdu.resp[0] for
// 0x6F (FCI template) or 0x62 (FCP template) and rejects anything else
// with SC_ERROR_UNKNOWN_DATA_RECEIVED, before process_fci() is ever called.
//
// This probe sends SELECT FILE with every relevant P2 value to a known
// CardEdge file (root dir 0x7000) to determine if any combination
// produces a TLV-wrapped response that would pass that gate.
//
// Usage: fci_format_probe [reader-name]

#include "smartcard/pcsc_connection.h"
#include "smartcard/apdu.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static void hexDump(const std::vector<uint8_t>& data)
{
    for (size_t i = 0; i < data.size(); ++i) {
        printf("%02X ", data[i]);
        if ((i % 16 == 15) || (i + 1 == data.size()))
            printf("\n");
    }
}

static void printSW(uint8_t sw1, uint8_t sw2)
{
    printf("SW=%02X%02X", sw1, sw2);
    if (sw1 == 0x90 && sw2 == 0x00)
        printf(" (OK)");
    else if (sw1 == 0x61)
        printf(" (more: %d)", sw2);
    else if (sw1 == 0x6A && sw2 == 0x86)
        printf(" (INCORRECT P1/P2)");
    else if (sw1 == 0x6A && sw2 == 0x82)
        printf(" (FILE NOT FOUND)");
    printf("\n");
}

// Build a raw SELECT FILE APDU with explicit P1, P2, data, Le
static smartcard::APDUCommand selectRaw(uint8_t p1, uint8_t p2, const std::vector<uint8_t>& data, uint8_t le,
                                        bool hasLe)
{
    return {0x00, 0xA4, p1, p2, data, le, hasLe};
}

int main(int argc, char* argv[])
{
    printf("=== CardEdge FCI Format Probe ===\n");
    printf("Purpose: determine if SELECT FILE ever returns ISO 7816-4\n");
    printf("         TLV-wrapped FCI (tag 0x6F or 0x62).\n\n");

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
        printf("Usage: fci_format_probe [reader-name]\n");
        return 1;
    }

    printf("Reader: %s\n", readerName.c_str());

    try {
        smartcard::PCSCConnection conn(readerName);

        auto atr = conn.getATR();
        printf("ATR:    ");
        for (auto b : atr)
            printf("%02X ", b);
        printf("\n");

        // Select PKI applet first
        const std::vector<uint8_t> AID_PKCS15 = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50,
                                                 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
        auto aidResp = conn.transmit(smartcard::selectByAID(AID_PKCS15));
        printf("\nSELECT AID: SW=%02X%02X\n", aidResp.sw1, aidResp.sw2);
        if (!aidResp.isSuccess()) {
            fprintf(stderr, "PKI applet not found.\n");
            return 1;
        }
        if (!aidResp.data.empty()) {
            printf("  AID SELECT response (%zu bytes): ", aidResp.data.size());
            hexDump(aidResp.data);
            printf("  First byte: 0x%02X %s\n", aidResp.data[0],
                   (aidResp.data[0] == 0x6F)   ? "== 0x6F (FCI template!)"
                   : (aidResp.data[0] == 0x62) ? "== 0x62 (FCP template!)"
                                               : "(!= 0x6F/0x62, NOT ISO TLV)");
        }

        // Test FIDs: root dir and a cert file
        const uint16_t testFids[] = {0x7000, 0x6005};
        const char* fidNames[] = {"root dir (0x7000)", "key file (0x6005)"};

        // P2 variants per ISO 7816-4:
        //   0x00 = return FCI (tag 0x6F expected)
        //   0x04 = return FCP (tag 0x62 expected)
        //   0x08 = return FMD (tag 0x64 expected)
        //   0x0C = return nothing
        struct P2Variant
        {
            uint8_t p2;
            const char* desc;
        };
        const P2Variant p2Variants[] = {
            {0x00, "P2=0x00 (return FCI, expect 0x6F)"},
            {0x04, "P2=0x04 (return FCP, expect 0x62)"},
            {0x08, "P2=0x08 (return FMD, expect 0x64)"},
            {0x0C, "P2=0x0C (return nothing)"},
        };

        // P1 variants
        struct P1Variant
        {
            uint8_t p1;
            const char* desc;
        };
        const P1Variant p1Variants[] = {
            {0x00, "P1=0x00 (select by FID)"},
            {0x02, "P1=0x02 (select EF under current DF)"},
        };

        // Le variants
        struct LeVariant
        {
            uint8_t le;
            bool hasLe;
            const char* desc;
        };
        const LeVariant leVariants[] = {
            {0x00, true, "Le=0x00 (up to 256)"},
            {0x0A, true, "Le=0x0A (10 bytes)"},
            {0x00, false, "No Le"},
        };

        bool foundTLV = false;

        for (int f = 0; f < 2; f++) {
            uint8_t fidH = static_cast<uint8_t>((testFids[f] >> 8) & 0xFF);
            uint8_t fidL = static_cast<uint8_t>(testFids[f] & 0xFF);

            printf("\n========================================\n");
            printf("Testing FID: %s\n", fidNames[f]);
            printf("========================================\n");

            for (const auto& p1v : p1Variants) {
                for (const auto& p2v : p2Variants) {
                    for (const auto& lev : leVariants) {
                        // Re-select AID before each test
                        conn.transmit(smartcard::selectByAID(AID_PKCS15));

                        printf("\n  %s | %s | %s\n", p1v.desc, p2v.desc, lev.desc);
                        auto resp = conn.transmit(selectRaw(p1v.p1, p2v.p2, {fidH, fidL}, lev.le, lev.hasLe));
                        printf("    ");
                        printSW(resp.sw1, resp.sw2);

                        if (!resp.data.empty()) {
                            printf("    Response (%zu bytes): ", resp.data.size());
                            hexDump(resp.data);
                            printf("    First byte: 0x%02X", resp.data[0]);
                            if (resp.data[0] == 0x6F) {
                                printf(" == FCI TEMPLATE (0x6F) *** TLV WRAPPED! ***");
                                foundTLV = true;
                            } else if (resp.data[0] == 0x62) {
                                printf(" == FCP TEMPLATE (0x62) *** TLV WRAPPED! ***");
                                foundTLV = true;
                            } else {
                                printf(" (raw proprietary, not TLV)");
                            }
                            printf("\n");
                        } else {
                            printf("    (no response data)\n");
                        }
                    }
                }
            }
        }

        printf("\n========================================\n");
        printf("CONCLUSION: ");
        if (foundTLV) {
            printf("CardEdge DOES return TLV-wrapped FCI in at least one variant.\n");
            printf("A process_fci() override could work with the right P2.\n");
        } else {
            printf("CardEdge NEVER returns TLV-wrapped FCI (0x6F/0x62).\n");
            printf("iso7816_select_file() rejects the response before process_fci()\n");
            printf("is called. A custom select_file() override is required.\n");
        }
        printf("========================================\n");

    } catch (const std::exception& ex) {
        fprintf(stderr, "\nError: %s\n", ex.what());
        return 1;
    }
    return 0;
}

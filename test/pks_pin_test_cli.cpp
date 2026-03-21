// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me
//
// CLI tool to test PIN operations on a PKS Chamber of Commerce card.
// Also dumps discovered key references and certificate count.
// Uses CardEdge directly for PKI operations; PKSCard is only used for probing.
// Usage: ./pks_pin_test_cli [reader_name]
// If no reader_name is given, lists available readers.

#include <cardedge/cardedge.h>
#include <cardedge/pki_applet_guard.h>
#include <pkscard/pkscard.h>
#include <smartcard/pcsc_connection.h>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

static std::string listReaders()
{
    SCARDCONTEXT ctx;
    LONG rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &ctx);
    if (rv != SCARD_S_SUCCESS) {
        std::cerr << "SCardEstablishContext failed: 0x" << std::hex << rv << std::endl;
        return {};
    }

    DWORD len = 0;
    rv = SCardListReaders(ctx, nullptr, nullptr, &len);
    if (rv != SCARD_S_SUCCESS || len == 0) {
        std::cerr << "No readers found." << std::endl;
        SCardReleaseContext(ctx);
        return {};
    }

    std::string buf(len, '\0');
    rv = SCardListReaders(ctx, nullptr, buf.data(), &len);
    SCardReleaseContext(ctx);

    if (rv != SCARD_S_SUCCESS)
        return {};

    // Multi-string: null-separated, double-null terminated
    std::string first;
    const char* p = buf.c_str();
    int idx = 0;
    while (*p) {
        std::cout << "  [" << idx << "] " << p << std::endl;
        if (idx == 0)
            first = p;
        p += strlen(p) + 1;
        idx++;
    }
    return first;
}

int main(int argc, char* argv[])
{
    std::string readerName;

    if (argc > 1) {
        readerName = argv[1];
    } else {
        std::cout << "Available readers:" << std::endl;
        readerName = listReaders();
        if (readerName.empty()) {
            std::cerr << "No readers available." << std::endl;
            return 1;
        }
        std::cout << "\nUsing first reader: " << readerName << std::endl;
    }

    try {
        // Step 0: probe
        std::cout << "\n--- Probing for PKS card ---" << std::endl;
        if (!pkscard::PKSCard::probe(readerName)) {
            std::cerr << "PKS card not detected on reader: " << readerName << std::endl;
            return 1;
        }
        std::cout << "PKS card detected." << std::endl;

        std::cout << "\n--- Connecting to card ---" << std::endl;
        smartcard::PCSCConnection conn(readerName);

        // Step 1: discoverKeyReferences
        std::cout << "\n--- Step 1: discoverKeyReferences ---" << std::endl;
        {
            cardedge::PkiAppletGuard guard(conn);
            auto keys = cardedge::discoverKeyReferences(conn);
            std::cout << "Found " << keys.size() << " key reference(s):" << std::endl;
            for (const auto& [label, fid] : keys)
                std::cout << "  \"" << label << "\" FID=0x" << std::hex << std::setfill('0') << std::setw(4) << fid
                          << std::dec << std::endl;
        }

        // Step 2: readCertificates
        std::cout << "\n--- Step 2: readCertificates ---" << std::endl;
        {
            cardedge::PkiAppletGuard guard(conn);
            auto certs = cardedge::readCertificates(conn);
            std::cout << "Found " << certs.size() << " certificate(s):" << std::endl;
            for (const auto& c : certs)
                std::cout << "  \"" << c.label << "\" DER size=" << c.derBytes.size() << " keyFID=0x" << std::hex
                          << std::setfill('0') << std::setw(4) << c.keyFID << std::dec << std::endl;
        }

        // Step 3: getPINTriesLeft (safe, no retry decrement)
        std::cout << "\n--- Step 3: getPINTriesLeft ---" << std::endl;
        cardedge::PINResult tries;
        {
            cardedge::PkiAppletGuard guard(conn);
            tries = cardedge::getPINTriesLeft(conn);
        }
        std::cout << "Result: retriesLeft=" << tries.retriesLeft << ", blocked=" << tries.blocked
                  << ", success=" << tries.success << std::endl;

        if (tries.blocked) {
            std::cerr << "PIN is BLOCKED. Cannot proceed." << std::endl;
            return 1;
        }

        if (tries.retriesLeft >= 0)
            std::cout << "Retries remaining: " << tries.retriesLeft << std::endl;

        // Step 4: verifyPIN
        std::cout << "\n--- Step 4: verifyPIN ---" << std::endl;
        std::cout << "WARNING: A wrong PIN will decrement retries (currently " << tries.retriesLeft << ")!"
                  << std::endl;
        std::cout << "Enter PIN to verify (or 'q' to quit): ";
        std::string pin;
        std::getline(std::cin, pin);

        if (pin == "q" || pin.empty()) {
            std::cout << "Aborted." << std::endl;
            return 0;
        }

        cardedge::PINResult verifyResult;
        {
            cardedge::PkiAppletGuard guard(conn);
            verifyResult = cardedge::verifyPIN(conn, pin);
        }
        std::cout << "Result: success=" << verifyResult.success << ", retriesLeft=" << verifyResult.retriesLeft
                  << ", blocked=" << verifyResult.blocked << std::endl;

        if (verifyResult.success) {
            std::cout << "PIN verified successfully!" << std::endl;
        } else if (verifyResult.blocked) {
            std::cerr << "PIN is now BLOCKED!" << std::endl;
            return 1;
        } else {
            std::cerr << "Wrong PIN. Retries remaining: " << verifyResult.retriesLeft << std::endl;
            return 1;
        }

        // Step 5: changePIN (optional)
        std::cout << "\n--- Step 5: changePIN ---" << std::endl;
        std::cout << "Enter NEW PIN (or 'q' to skip): ";
        std::string newPin;
        std::getline(std::cin, newPin);

        if (newPin == "q" || newPin.empty()) {
            std::cout << "Skipped changePIN." << std::endl;
            return 0;
        }

        std::cout << "Confirm NEW PIN: ";
        std::string confirmPin;
        std::getline(std::cin, confirmPin);

        if (newPin != confirmPin) {
            std::cerr << "PINs do not match. Aborted." << std::endl;
            return 1;
        }

        cardedge::PINResult changeResult;
        {
            cardedge::PkiAppletGuard guard(conn);
            changeResult = cardedge::changePIN(conn, pin, newPin);
        }
        std::cout << "Result: success=" << changeResult.success << ", retriesLeft=" << changeResult.retriesLeft
                  << ", blocked=" << changeResult.blocked << std::endl;

        if (changeResult.success) {
            std::cout << "PIN changed successfully!" << std::endl;

            std::cout << "\n--- Verifying new PIN ---" << std::endl;
            cardedge::PINResult recheck;
            {
                cardedge::PkiAppletGuard guard(conn);
                recheck = cardedge::verifyPIN(conn, newPin);
            }
            std::cout << "Verify new PIN: success=" << recheck.success << std::endl;

            std::cout << "\n--- Changing PIN back to original ---" << std::endl;
            cardedge::PINResult revert;
            {
                cardedge::PkiAppletGuard guard(conn);
                revert = cardedge::changePIN(conn, newPin, pin);
            }
            std::cout << "Revert: success=" << revert.success << std::endl;
            if (revert.success)
                std::cout << "PIN restored to original." << std::endl;
        } else {
            std::cerr << "changePIN failed. Retries remaining: " << changeResult.retriesLeft << std::endl;
        }

    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}

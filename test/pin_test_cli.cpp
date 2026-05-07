// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Quick CLI tool to test PIN operations on an inserted card.
// Usage: ./pin_test_cli [reader_name]
// If no reader_name is given, lists available readers.
//
// Security note: PIN material is read into LibreSCRS::Secure::String
// (cleansing allocator) and the terminal
// echo is suppressed during PIN entry on POSIX hosts. Windows console
// echo suppression is not implemented — the tool is currently
// POSIX-only-built per its CMake gate, but a SetConsoleMode-based
// equivalent should land if it ever ports to Windows.

#include <LibreSCRS/Secure/String.h>

#include <cardedge.h>
#include <pki_applet_guard.h>
#include <smartcard/pcsc_connection.h>

#include <cstring>
#include <iostream>
#include <string>
#include <string_view>

#if defined(__unix__) || defined(__APPLE__)
#include <termios.h>
#include <unistd.h>
#endif

#ifdef __APPLE__
#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#else
#include <winscard.h>
#endif

// Read a PIN with terminal echo suppressed on POSIX hosts. Returns a
// LibreSCRS::Secure::String so the bytes are cleansed from heap on
// destruction. The trailing newline that getline strips is fine —
// std::getline consumes the newline without including it.
static LibreSCRS::Secure::String readPinNoEcho(const char* prompt)
{
    std::cout << prompt;
    std::cout.flush();

#if defined(__unix__) || defined(__APPLE__)
    termios oldt{};
    termios newt{};
    bool isTty = ::isatty(STDIN_FILENO) != 0;
    if (isTty && ::tcgetattr(STDIN_FILENO, &oldt) == 0) {
        newt = oldt;
        newt.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        ::tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    } else {
        isTty = false; // tcgetattr failed — don't try to restore
    }
#endif

    std::string raw;
    std::getline(std::cin, raw);

#if defined(__unix__) || defined(__APPLE__)
    if (isTty) {
        ::tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
        std::cout << std::endl; // echo a newline since we suppressed it
    }
#endif

    // Adopt-and-cleanse: the std::string&& ctor zeroises the temporary's
    // storage before raw goes out of scope. raw itself is local and
    // reaches end-of-scope here, but the rvalue ctor handles the
    // cleansing explicitly so the path is correct even if a future
    // refactor reorders things.
    return LibreSCRS::Secure::String{std::move(raw)};
}

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
        std::cout << "\n--- Connecting to card ---" << std::endl;
        smartcard::PCSCConnection conn(readerName);

        // Step 1: getPINTriesLeft (safe, no retry decrement)
        std::cout << "\n--- Step 1: getPINTriesLeft ---" << std::endl;
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

        if (tries.retriesLeft >= 0) {
            std::cout << "Retries remaining: " << tries.retriesLeft << std::endl;
        }

        // Step 2: Ask user whether to proceed with verifyPIN
        std::cout << "\n--- Step 2: verifyPIN ---" << std::endl;
        std::cout << "WARNING: A wrong PIN will decrement retries (currently " << tries.retriesLeft << ")!"
                  << std::endl;
        auto pin = readPinNoEcho("Enter PIN to verify (or 'q' to quit): ");

        if (pin.view() == "q" || pin.empty()) {
            std::cout << "Aborted." << std::endl;
            return 0;
        }

        cardedge::PINResult verifyResult;
        {
            cardedge::PkiAppletGuard guard(conn);
            verifyResult = cardedge::verifyPIN(conn, pin.view());
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

        // Step 3: Ask user whether to test changePIN
        std::cout << "\n--- Step 3: changePIN ---" << std::endl;
        auto newPin = readPinNoEcho("Enter NEW PIN (or 'q' to skip): ");

        if (newPin.view() == "q" || newPin.empty()) {
            std::cout << "Skipped changePIN." << std::endl;
            return 0;
        }

        auto confirmPin = readPinNoEcho("Confirm NEW PIN: ");

        if (newPin != confirmPin) {
            std::cerr << "PINs do not match. Aborted." << std::endl;
            return 1;
        }

        cardedge::PINResult changeResult;
        {
            cardedge::PkiAppletGuard guard(conn);
            changeResult = cardedge::changePIN(conn, pin.view(), newPin.view());
        }
        std::cout << "Result: success=" << changeResult.success << ", retriesLeft=" << changeResult.retriesLeft
                  << ", blocked=" << changeResult.blocked << std::endl;

        if (changeResult.success) {
            std::cout << "PIN changed successfully!" << std::endl;

            // Verify the new PIN works
            std::cout << "\n--- Verifying new PIN ---" << std::endl;
            cardedge::PINResult recheck;
            {
                cardedge::PkiAppletGuard guard(conn);
                recheck = cardedge::verifyPIN(conn, newPin.view());
            }
            std::cout << "Verify new PIN: success=" << recheck.success << std::endl;

            // Change back to original
            std::cout << "\n--- Changing PIN back to original ---" << std::endl;
            cardedge::PINResult revert;
            {
                cardedge::PkiAppletGuard guard(conn);
                revert = cardedge::changePIN(conn, newPin.view(), pin.view());
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

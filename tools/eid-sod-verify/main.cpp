// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
/// @file
/// @brief eid-sod-verify — read a Serbian eID card's Security Object (SOD) and
///        verify it end-to-end, printing the signer identity and a
///        VALID / UNKNOWN / INVALID verdict.
///
/// Three verification layers (a card SOD needs all of them; chain-only is not
/// enough — an attacker could embed a genuine public MUP signer certificate in a
/// forged, unsigned SOD):
///   1. CMS SIGNATURE over the SOD content (PKCS7_verify).
///   2. certificate CHAIN to the bundled MUP masterlist (X509_verify_cert).
///   3. document-signer DOMAIN pin: the signer's issuer must be a MUP "Resursi"
///      (resources) CA — the MUP PKI issues citizen/officials certs from sibling
///      CAs under the same roots, so chain-to-a-MUP-root is not sufficient.
///
/// Deliberately independent of the in-tree rs-eid verification code, so it can act
/// as an oracle when diagnosing a card — including future MUP certificate
/// generations, where the signer's certificate changes but the read path does not.
/// The card itself is opened through CardSession like everything else, so the
/// tool holds the reader the same way the library does and never past it.

#include <LibreSCRS/SmartCard/CardSession.h>

#include <apdu.h>
#include <pcsc_connection.h>

#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#ifndef LIBREMIDDLEWARE_CERTIFICATES_DIR
#define LIBREMIDDLEWARE_CERTIFICATES_DIR ""
#endif

#ifndef LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR
#define LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR ""
#endif

namespace {

namespace fs = std::filesystem;

// Serbian eID application identifiers (citizen SERID, foreigner SERIF).
const std::vector<std::uint8_t> kAidCitizen{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x44, 0x01};
const std::vector<std::uint8_t> kAidForeigner{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x46, 0x01};

// SOD file identifiers: fixed-data (FX) and variable-data (VX).
constexpr std::uint8_t kSodFxH = 0x0F, kSodFxL = 0x1C;
constexpr std::uint8_t kSodVxH = 0x0F, kSodVxL = 0x1D;

using LibreSCRS::SmartCard::CardSession;
namespace Apdu = LibreSCRS::SmartCard::Internal;

// Send one APDU; returns the response data, empty unless the card answered 9000.
std::vector<std::uint8_t> transmitOk(CardSession& session, const Apdu::APDUCommand& cmd)
{
    const auto r = session.transmitInternal(cmd);
    if (!r.isSuccess())
        return {};
    return r.data;
}

bool selectAid(CardSession& session, const std::vector<std::uint8_t>& aid)
{
    return session.transmitInternal(Apdu::selectByAID(aid)).isSuccess();
}

// Read the full contents of an EF (SELECT by path, then READ BINARY to the length
// reported in the SELECT FCI, falling back to reading until a short/failed response).
std::vector<std::uint8_t> readEf(CardSession& session, std::uint8_t fidH, std::uint8_t fidL)
{
    const auto select = session.transmitInternal(Apdu::selectByPath(fidH, fidL, 4));
    if (!select.isSuccess())
        return {};
    // FCI layout on these cards: FID(2) length(2) ... — take the length when present.
    const auto& fci = select.data;
    const int total = (fci.size() >= 4) ? ((fci[2] << 8) | fci[3]) : 0;

    std::vector<std::uint8_t> out;
    // READ BINARY with this INS addresses 15 bits; a SOD is a few kilobytes.
    for (int off = 0; off <= 0x7FFF; off += 256) {
        const int want = total > 0 ? std::min(256, total - off) : 256;
        if (want <= 0)
            break;
        const auto r = transmitOk(session, Apdu::readBinary(static_cast<std::uint16_t>(off),
                                                            static_cast<std::uint8_t>(want == 256 ? 0x00 : want)));
        if (r.empty())
            break;
        out.insert(out.end(), r.begin(), r.end());
        if (static_cast<int>(r.size()) < want)
            break;
    }
    return out;
}

// The SOD file wraps the PKCS#7 in card-specific TLV headers. Skip to the DER
// SEQUENCE that starts the PKCS#7 (0x30 followed by a length octet).
long pkcs7Offset(const std::vector<std::uint8_t>& buf)
{
    for (std::size_t i = 0; i + 1 < buf.size() && i < 32; ++i)
        if (buf[i] == 0x30 && (buf[i + 1] == 0x80 || (buf[i + 1] & 0x80)))
            return static_cast<long>(i);
    return 0;
}

std::string lower(std::string s)
{
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string oneline(X509_NAME* n)
{
    char buf[512];
    X509_NAME_oneline(n, buf, sizeof buf);
    return buf;
}

std::string issuerCn(X509* c)
{
    X509_NAME* n = X509_get_issuer_name(c);
    const int idx = X509_NAME_get_index_by_NID(n, NID_commonName, -1);
    if (idx < 0)
        return {};
    unsigned char* u = nullptr;
    const int len = ASN1_STRING_to_UTF8(&u, X509_NAME_ENTRY_get_data(X509_NAME_get_entry(n, idx)));
    if (len < 0 || !u)
        return {};
    std::string cn(reinterpret_cast<char*>(u), static_cast<std::size_t>(len));
    OPENSSL_free(u);
    return cn;
}

// Same domain rule as the production rs-eid pin.
bool issuerIsResourcesDomain(X509* signer)
{
    const std::string cn = lower(issuerCn(signer));
    if (cn.empty() || cn.find("gradjani") != std::string::npos || cn.find("sluzbenici") != std::string::npos)
        return false;
    return cn.find("resursi") != std::string::npos;
}

int loadCertsInto(X509_STORE* store, const fs::path& dir)
{
    int n = 0;
    std::error_code ec;
    if (!fs::is_directory(dir, ec))
        return 0;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        const auto ext = e.path().extension().string();
        if (ext != ".cer" && ext != ".crt" && ext != ".pem")
            continue;
        std::ifstream f(e.path(), std::ios::binary);
        std::vector<std::uint8_t> b((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
        const unsigned char* p = b.data();
        if (X509* c = d2i_X509(nullptr, &p, static_cast<long>(b.size()))) { // malformed legacy certs simply fail here
            X509_STORE_add_cert(store, c);
            X509_free(c);
            ++n;
        }
    }
    return n;
}

void printUsage()
{
    std::puts("Usage: eid-sod-verify [--reader <name>] [--certs <dir>] [--var]\n"
              "  --reader <name>  PC/SC reader (default: first reader with a card)\n"
              "  --certs  <dir>   MUP masterlist root holding rs-mup/ and rs-mup-format/\n"
              "  --var            verify the variable-data SOD (default: fixed-data)\n"
              "Exit code 0 only on VALID.");
}

} // namespace

int main(int argc, char** argv)
{
    // Prefer the source tree when this was built from one; an installed copy
    // has that define empty and falls back to where the bundle was installed.
    std::string reader, certsDir = LIBREMIDDLEWARE_CERTIFICATES_DIR[0] != '\0'
                                       ? LIBREMIDDLEWARE_CERTIFICATES_DIR
                                       : LIBREMIDDLEWARE_INSTALLED_CERTIFICATES_DIR;
    bool variable = false;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--reader" && i + 1 < argc)
            reader = argv[++i];
        else if (a == "--certs" && i + 1 < argc)
            certsDir = argv[++i];
        else if (a == "--var")
            variable = true;
        else if (a == "--help" || a == "-h") {
            printUsage();
            return 0;
        } else {
            printUsage();
            return 2;
        }
    }

    // Resolve the reader: use --reader, else the first reader that opens.
    std::optional<CardSession> session;
    std::string lastError;
    auto tryOpen = [&](const std::string& name) {
        auto opened = CardSession::open(name);
        if (opened) {
            session.emplace(std::move(*opened));
            reader = name;
            return true;
        }
        const auto& error = opened.error();
        lastError = error.diagnosticDetail.value_or(error.userMessage.defaultText);
        return false;
    };
    if (!reader.empty()) {
        if (!tryOpen(reader)) {
            std::fprintf(stderr, "cannot open the card in %s: %s\n", reader.c_str(), lastError.c_str());
            return 3;
        }
    } else {
        for (const auto& name : Apdu::PCSCConnection::listReaders())
            if (tryOpen(name))
                break;
        if (!session) {
            std::fputs("no reader with a card found (is pcscd running? use --reader)\n", stderr);
            return 3;
        }
    }
    std::printf("reader: %s\n", reader.c_str());

    if (!selectAid(*session, kAidCitizen) && !selectAid(*session, kAidForeigner)) {
        std::fputs("not a Serbian eID card (SELECT AID failed)\n", stderr);
        return 4;
    }

    auto sod = variable ? readEf(*session, kSodVxH, kSodVxL) : readEf(*session, kSodFxH, kSodFxL);
    if (sod.size() < 32) {
        std::fputs("could not read the SOD\n", stderr);
        return 4;
    }
    std::printf("SOD bytes: %zu\n", sod.size());

    const long off = pkcs7Offset(sod);
    const unsigned char* pp = sod.data() + off;
    PKCS7* p7 = d2i_PKCS7(nullptr, &pp, static_cast<long>(sod.size()) - off);
    if (!p7) {
        std::fputs("failed to parse the PKCS#7 SOD\n", stderr);
        return 4;
    }

    const int sig = PKCS7_verify(p7, nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY); // signature only here
    STACK_OF(X509)* signers = PKCS7_get0_signers(p7, nullptr, 0);
    if (!signers || sk_X509_num(signers) != 1) {
        std::fprintf(stderr, "expected exactly one signer, got %d\n", signers ? sk_X509_num(signers) : 0);
        PKCS7_free(p7);
        return 4;
    }
    X509* signer = sk_X509_value(signers, 0);

    std::printf("signer subject : %s\n", oneline(X509_get_subject_name(signer)).c_str());
    std::printf("signer issuer  : %s\n", oneline(X509_get_issuer_name(signer)).c_str());

    X509_STORE* store = X509_STORE_new();
    const int loaded = loadCertsInto(store, fs::path(certsDir) / "rs-mup") +
                       loadCertsInto(store, fs::path(certsDir) / "rs-mup-format");
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, signer, nullptr);
    const int chain = X509_verify_cert(ctx);
    const int chainErr = chain ? 0 : X509_STORE_CTX_get_error(ctx);
    const bool pin = issuerIsResourcesDomain(signer);

    std::printf("signature      : %s\n", sig ? "OK" : "FAIL");
    std::printf("chain (%2d certs): %s%s\n", loaded, chain ? "OK" : "FAIL",
                chain ? "" : (std::string(" — ") + X509_verify_cert_error_string(chainErr)).c_str());
    std::printf("domain pin     : %s\n", pin ? "OK (MUP resources)" : "FAIL (not a document-signer domain)");

    const char* verdict = (sig && chain && pin) ? "VALID" : (sig && chain) ? "UNKNOWN (pin)" : "INVALID";
    std::printf(">>> VERDICT: %s\n", verdict);

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_free(signers);
    PKCS7_free(p7);
    return (sig && chain && pin) ? 0 : 1;
}

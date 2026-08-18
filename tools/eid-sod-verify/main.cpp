// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
/// @file
/// @brief eid-sod-verify — read a Serbian eID card's Security Object (SOD) over
///        PC/SC and verify it end-to-end, printing the signer identity and a
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

#include <pcsclite.h>
#include <winscard.h>
#include <wintypes.h>

#include <openssl/err.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
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

struct Pcsc
{
    SCARDCONTEXT ctx = 0;
    SCARDHANDLE card = 0;
    DWORD proto = 0;
    ~Pcsc()
    {
        if (card)
            SCardDisconnect(card, SCARD_LEAVE_CARD);
        if (ctx)
            SCardReleaseContext(ctx);
    }
};

// Send one APDU; returns response bytes (including SW1 SW2), empty on transmit error.
std::vector<std::uint8_t> transmit(Pcsc& p, const std::vector<std::uint8_t>& cmd)
{
    SCARD_IO_REQUEST pci{p.proto, sizeof(SCARD_IO_REQUEST)};
    std::array<std::uint8_t, 512> resp{};
    DWORD rl = static_cast<DWORD>(resp.size());
    if (SCardTransmit(p.card, &pci, cmd.data(), static_cast<DWORD>(cmd.size()), nullptr, resp.data(), &rl) !=
        SCARD_S_SUCCESS)
        return {};
    return {resp.begin(), resp.begin() + rl};
}

bool sw9000(const std::vector<std::uint8_t>& r)
{
    return r.size() >= 2 && r[r.size() - 2] == 0x90 && r[r.size() - 1] == 0x00;
}

std::vector<std::uint8_t> selectAid(Pcsc& p, const std::vector<std::uint8_t>& aid)
{
    std::vector<std::uint8_t> cmd{0x00, 0xA4, 0x04, 0x00, static_cast<std::uint8_t>(aid.size())};
    cmd.insert(cmd.end(), aid.begin(), aid.end());
    return transmit(p, cmd);
}

// Read the full contents of an EF (SELECT by path, then READ BINARY to the length
// reported in the SELECT FCI, falling back to reading until a short/failed response).
std::vector<std::uint8_t> readEf(Pcsc& p, std::uint8_t fidH, std::uint8_t fidL)
{
    auto fci = transmit(p, {0x00, 0xA4, 0x08, 0x00, 0x02, fidH, fidL, 0x04});
    if (!sw9000(fci))
        return {};
    // FCI layout on these cards: FID(2) length(2) ... — take the length when present.
    int total = (fci.size() >= 4) ? ((fci[2] << 8) | fci[3]) : 0;

    std::vector<std::uint8_t> out;
    for (int off = 0; off < 0x10000; off += 256) {
        int want = total > 0 ? std::min(256, total - off) : 256;
        if (want <= 0)
            break;
        auto r = transmit(p, {0x00, 0xB0, static_cast<std::uint8_t>(off >> 8), static_cast<std::uint8_t>(off & 0xFF),
                              static_cast<std::uint8_t>(want == 256 ? 0x00 : want)});
        if (!sw9000(r) || r.size() <= 2)
            break;
        out.insert(out.end(), r.begin(), r.end() - 2);
        if (static_cast<int>(r.size()) - 2 < want)
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

    Pcsc p;
    if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &p.ctx) != SCARD_S_SUCCESS) {
        std::fputs("cannot establish PC/SC context (is pcscd running?)\n", stderr);
        return 3;
    }

    // Resolve the reader: use --reader, else the first reader that has a card.
    if (reader.empty()) {
        DWORD len = 0;
        if (SCardListReaders(p.ctx, nullptr, nullptr, &len) == SCARD_S_SUCCESS && len > 0) {
            std::vector<char> names(len);
            SCardListReaders(p.ctx, nullptr, names.data(), &len);
            for (const char* n = names.data(); *n; n += std::strlen(n) + 1) {
                SCARDHANDLE h;
                DWORD pr;
                if (SCardConnect(p.ctx, n, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &h, &pr) ==
                    SCARD_S_SUCCESS) {
                    reader = n;
                    SCardDisconnect(h, SCARD_LEAVE_CARD);
                    break;
                }
            }
        }
    }
    if (reader.empty()) {
        std::fputs("no reader with a card found (use --reader)\n", stderr);
        return 3;
    }

    if (SCardConnect(p.ctx, reader.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &p.card,
                     &p.proto) != SCARD_S_SUCCESS) {
        std::fprintf(stderr, "cannot connect to reader: %s\n", reader.c_str());
        return 3;
    }
    std::printf("reader: %s\n", reader.c_str());

    if (!sw9000(selectAid(p, kAidCitizen)) && !sw9000(selectAid(p, kAidForeigner))) {
        std::fputs("not a Serbian eID card (SELECT AID failed)\n", stderr);
        return 4;
    }

    auto sod = variable ? readEf(p, kSodVxH, kSodVxL) : readEf(p, kSodFxH, kSodFxL);
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

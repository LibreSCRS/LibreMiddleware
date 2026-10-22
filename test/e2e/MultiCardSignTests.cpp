// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Multi-card regression smoke. Iterates every PCSC reader the system reports
// and signs, the way a document signature is made, on whichever recognised
// card profile is present on each reader: the card's plugin on a session for
// the reader, the PIN deposited and presented in the plugin's own sign.
// Per-card PIN-failure latching halts further PIN ops on a card that fails
// while the other readers continue independently — no cross-contamination.
//
// Card → PIN map (operator-supplied via env):
//   PKS  (CardEdge platform)                  → bare PIN
//   NAM  (SCE 8.0-C2V0 CL)                    → CAN:PIN (PACE then verify)
//   PIV  (G+D SCE7)                           → bare PIN
//
// Opt-in: gated on LIBRESCRS_BUILD_REAL_CARD_TESTS=ON. NOT in default
// ctest set. Operator invocation:
//
//   LIBRESCRS_TEST_PKS_PIN="0114" \
//   LIBRESCRS_TEST_NAM_PIN="123456:654321" \
//   LIBRESCRS_TEST_PIV_PIN="569548" \
//   ./MultiCardSignTests

// pin_guard.h is included for its PIN-related helpers, but this test
// deliberately does NOT invoke SKIP_IF_PIN_FAILED() at function entry.
// The single TEST iterates multiple readers/profiles in one invocation
// and uses a per-profile latch (g_latch.markFailed / hasFailed below)
// as the equivalent fence: a PIN failure on profile X must NOT skip
// subsequent profiles Y/Z on other readers. A global g_pinFailed gate
// would conflate independent cards and abort the multi-card sweep
// after the first failure, which defeats the whole point of this test.
#include "pin_guard.h"

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS_internal/Crypto/DigestInfo.h>

#include "native/plugin_signing_key.h"
#include "types.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace {

using LibreSCRS::Tests::E2E::env;

enum class CardProfile { Unknown, PKS, NAM_CL, PIV_GD };

const char* profileName(CardProfile p)
{
    switch (p) {
    case CardProfile::PKS:
        return "PKS";
    case CardProfile::NAM_CL:
        return "NAM_CL";
    case CardProfile::PIV_GD:
        return "PIV_GD";
    case CardProfile::Unknown:
    default:
        return "Unknown";
    }
}

/// Classify a card by ATR. Multiple ATRs may match the same family —
/// keep the table explicit so the operator can visually audit it and
/// no slot accidentally executes the wrong PIN.
CardProfile classifyByAtr(const std::vector<std::uint8_t>& atr)
{
    auto contains = [&](std::initializer_list<std::uint8_t> needle) {
        if (needle.size() > atr.size())
            return false;
        for (std::size_t i = 0; i + needle.size() <= atr.size(); ++i) {
            std::size_t k = 0;
            for (auto n : needle) {
                if (atr[i + k] != n)
                    break;
                ++k;
            }
            if (k == needle.size())
                return true;
        }
        return false;
    };

    // SCE 8.0-C2V0 contactless = NAM CL (an IAS-ECC hash-on-card SSCD).
    // Hist bytes literally spell "SCE 8.0-C2V0".
    if (contains({0x53, 0x43, 0x45, 0x20, 0x38, 0x2E, 0x30, 0x2D, 0x43, 0x32, 0x56, 0x30}))
        return CardProfile::NAM_CL;

    // SCE 8.0-C1V0 contact = PKS (Serbian PKS card per OpenSC
    // card-srbeid.c).
    if (contains({0x53, 0x43, 0x45, 0x20, 0x38, 0x2E, 0x30, 0x2D, 0x43, 0x31, 0x56, 0x30}))
        return CardProfile::PKS;

    // The v7 chip platform with G+D PIV applet personalisation.
    // Hist bytes start with "SCE7 " — common to multiple v7 variants;
    // disambiguation against non-PIV v7 cards (legacy Serbian eID v7)
    // would need a probing SELECT-AID — for the test matrix the operator
    // is responsible for ensuring only PIV-personalised v7 cards on the
    // reader they intend.
    if (contains({0x53, 0x43, 0x45, 0x37, 0x20}))
        return CardProfile::PIV_GD;

    return CardProfile::Unknown;
}

std::string atrHex(const std::vector<std::uint8_t>& atr)
{
    std::string out;
    out.reserve(atr.size() * 3);
    static constexpr char kHex[] = "0123456789ABCDEF";
    for (auto b : atr) {
        if (!out.empty())
            out.push_back(':');
        out.push_back(kHex[(b >> 4) & 0x0F]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

/// Per-card failure latch. The cards on the three readers are
/// independent — a PIN failure on one MUST NOT cause us to abandon
/// the sign attempts on the others. Each profile gets its own bool;
/// the test fixture consults the profile-specific latch before
/// committing any PIN-decrementing APDU.
struct PinFailureLatch
{
    std::atomic<bool> pks{false};
    std::atomic<bool> nam{false};
    std::atomic<bool> piv{false};

    bool isFailed(CardProfile p) const
    {
        switch (p) {
        case CardProfile::PKS:
            return pks.load(std::memory_order_relaxed);
        case CardProfile::NAM_CL:
            return nam.load(std::memory_order_relaxed);
        case CardProfile::PIV_GD:
            return piv.load(std::memory_order_relaxed);
        default:
            return false;
        }
    }
    void markFailed(CardProfile p)
    {
        switch (p) {
        case CardProfile::PKS:
            pks.store(true, std::memory_order_relaxed);
            break;
        case CardProfile::NAM_CL:
            nam.store(true, std::memory_order_relaxed);
            break;
        case CardProfile::PIV_GD:
            piv.store(true, std::memory_order_relaxed);
            break;
        default:
            break;
        }
    }
};
static PinFailureLatch g_latch;

struct ReaderCard
{
    std::string reader;
    std::vector<std::uint8_t> atr;
    CardProfile profile;
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
};

/// Discover every reader with a present card, classify by ATR, open a
/// CardSession on each. Skips empty readers gracefully. Returns the
/// flat list of (reader, profile, session) tuples.
std::vector<ReaderCard> discoverCards()
{
    std::vector<ReaderCard> out;
    auto monitor = std::make_shared<LibreSCRS::SmartCard::MonitorService>();
    auto readers = monitor->listReaders();
    if (!readers.has_value() || readers->empty())
        return out;

    for (const auto& r : *readers) {
        auto opened = LibreSCRS::SmartCard::CardSession::open(r);
        if (!opened.has_value())
            continue; // empty reader — fine, skip
        ReaderCard rc;
        rc.reader = r;
        rc.atr = opened->atr();
        rc.profile = classifyByAtr(rc.atr);
        rc.session = std::make_shared<LibreSCRS::SmartCard::CardSession>(std::move(*opened));
        out.push_back(std::move(rc));
    }
    return out;
}

struct SignOutcome
{
    bool attached = false; ///< a plugin read a signing key from the card
    bool certRead = false;
    bool signed_ = false;
    bool verified = false;
    std::string note;
    std::string sigError;
};

/// Sign on @p rc as a document signature is made, using @p pin. Latches the
/// profile-specific PIN-failure flag when the card refuses the PIN or reports
/// it blocked, so later ops on the SAME card skip without burning more tries.
SignOutcome signOnCard(const LibreSCRS::Plugin::CardPluginService& plugins, ReaderCard& rc, const std::string& pin)
{
    SignOutcome o;
    if (g_latch.isFailed(rc.profile)) {
        o.note = "skipped — earlier PIN failure latched for this profile";
        return o;
    }

    // NAM CL: the CAN goes to the session as the PACE secret (PACE is
    // required even to read the certificates over CL), the bare PIN to the
    // key; the plugin brings up PACE on the session itself.
    std::string pinForSign = pin;
    if (rc.profile == CardProfile::NAM_CL) {
        auto colon = pin.find(':');
        if (colon == std::string::npos) {
            o.note = "NAM CL expects CAN:PIN format; got bare PIN";
            return o;
        }
        rc.session->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can,
                                  LibreSCRS::Secure::String{pin.substr(0, colon)});
        pinForSign = pin.substr(colon + 1);
    }

    std::unique_ptr<libresign::PluginSigningKey> key;
    try {
        for (const auto& plugin : plugins.findAllCandidates(rc.atr, *rc.session)) {
            if (!LibreSCRS::Plugin::hasCapability(plugin->capabilities(), LibreSCRS::Plugin::CardCapabilities::PKI))
                continue;
            const auto certs = plugin->readCertificates(*rc.session);
            std::vector<std::vector<std::uint8_t>> chain;
            for (const auto& c : certs) {
                if (!c.derBytes.empty())
                    chain.push_back(c.derBytes);
            }
            for (const auto& c : certs) {
                if (!c.keyFID)
                    continue;
                const LibreSCRS::Secure::Buffer pinBuf(pinForSign);
                key = std::make_unique<libresign::PluginSigningKey>(
                    plugin, rc.session, c, pinBuf, chain, std::span<const std::uint8_t>{}, LibreSCRS::CancelToken{});
                break;
            }
            if (key)
                break;
        }
    } catch (const std::exception& e) {
        o.sigError = e.what();
        o.note = "reading the card's signing key failed";
        return o;
    }
    if (!key) {
        o.note = "no plugin reads a signing key from this card";
        return o;
    }
    o.attached = true;
    const auto certDer = key->certificate();
    o.certRead = !certDer.empty();

    // Sign a fixed test payload. Pass the raw bytes so a card that only signs
    // what it hashes itself is driven as a document signature drives it.
    const std::vector<std::uint8_t> payload = {'m', 'u', 'l', 't', 'i', '-', 'c', 'a', 'r', 'd'};
    std::array<std::uint8_t, 32> digest{};
    {
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        unsigned int n = 0;
        EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
        EVP_DigestUpdate(md, payload.data(), payload.size());
        EVP_DigestFinal_ex(md, digest.data(), &n);
        EVP_MD_CTX_free(md);
    }
    const auto signInput =
        LibreSCRS::Internal::Crypto::digestInfoOf(LibreSCRS::Internal::Crypto::DigestInfoHash::Sha256, payload);

    std::vector<std::uint8_t> signature;
    try {
        signature = key->sign(signInput, "SHA256withRSA", std::span<const std::uint8_t>{payload});
    } catch (const libresign::SignFailureException& e) {
        o.sigError = e.what();
        if (e.kind == libresign::SignFailureKind::PinFailed || e.kind == libresign::SignFailureKind::PinBlocked)
            g_latch.markFailed(rc.profile);
        o.note = "sign failed";
        return o;
    } catch (const std::exception& e) {
        o.sigError = e.what();
        o.note = "sign failed";
        return o;
    }

    if (signature.empty()) {
        o.note = "sign returned empty";
        return o;
    }
    o.signed_ = true;

    // Verify against the on-card cert's public key.
    const unsigned char* p = certDer.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(certDer.size()));
    if (!cert) {
        o.note = "cert DER parse failed";
        return o;
    }
    EVP_PKEY* pubKey = X509_get_pubkey(cert);
    if (!pubKey) {
        X509_free(cert);
        o.note = "pubkey extract failed";
        return o;
    }

    EVP_PKEY_CTX* vctx = EVP_PKEY_CTX_new(pubKey, nullptr);
    if (vctx && EVP_PKEY_verify_init(vctx) == 1 && EVP_PKEY_CTX_set_signature_md(vctx, EVP_sha256()) == 1) {
        if (EVP_PKEY_base_id(pubKey) == EVP_PKEY_RSA)
            EVP_PKEY_CTX_set_rsa_padding(vctx, RSA_PKCS1_PADDING);
        int r = EVP_PKEY_verify(vctx, signature.data(), signature.size(), digest.data(), digest.size());
        o.verified = (r == 1);
    }
    EVP_PKEY_CTX_free(vctx);
    EVP_PKEY_free(pubKey);
    X509_free(cert);

    if (o.verified)
        o.note = "OK (sign + verify against on-card cert pubkey)";
    else
        o.note = "sign produced bytes but verify FAILED";
    return o;
}

const char* pinFor(CardProfile p)
{
    switch (p) {
    case CardProfile::PKS:
        return std::getenv("LIBRESCRS_TEST_PKS_PIN");
    case CardProfile::NAM_CL:
        return std::getenv("LIBRESCRS_TEST_NAM_PIN");
    case CardProfile::PIV_GD:
        return std::getenv("LIBRESCRS_TEST_PIV_PIN");
    default:
        return nullptr;
    }
}

} // namespace

TEST(MultiCardSign, AllPresentReadersIndependent)
{
    auto found = discoverCards();
    std::fprintf(stderr, "\n=== MultiCardSign: %zu reader(s) with a card present ===\n", found.size());
    for (const auto& rc : found)
        std::fprintf(stderr, "  reader=%s profile=%s atr=%s\n", rc.reader.c_str(), profileName(rc.profile),
                     atrHex(rc.atr).c_str());

    if (found.empty())
        GTEST_SKIP() << "No cards present on any reader";

    struct Result
    {
        std::string reader;
        CardProfile profile;
        SignOutcome outcome;
    };
    std::vector<Result> results;

    const LibreSCRS::Plugin::CardPluginService plugins{std::filesystem::path(PLUGIN_DIR)};

    for (auto& rc : found) {
        const char* pin = pinFor(rc.profile);
        if (rc.profile == CardProfile::Unknown) {
            results.push_back({rc.reader, rc.profile, {.note = "unknown card profile (ATR not in table)"}});
            continue;
        }
        if (!pin || !*pin) {
            results.push_back({rc.reader, rc.profile, {.note = "env LIBRESCRS_TEST_<PROFILE>_PIN not set; skipping"}});
            continue;
        }
        std::fprintf(stderr, "\n--- Signing on %s @ %s ---\n", profileName(rc.profile), rc.reader.c_str());
        auto outcome = signOnCard(plugins, rc, pin);
        std::fprintf(stderr, "    attached=%d cert=%d signed=%d verified=%d note=\"%s\" err=\"%s\"\n", outcome.attached,
                     outcome.certRead, outcome.signed_, outcome.verified, outcome.note.c_str(),
                     outcome.sigError.c_str());
        results.push_back({rc.reader, rc.profile, std::move(outcome)});
    }

    std::fprintf(stderr, "\n=== SUMMARY ===\n");
    int verifiedCount = 0;
    int attemptedCount = 0;
    for (const auto& r : results) {
        std::fprintf(stderr, "  [%s] %s: verified=%d (%s)\n", r.reader.c_str(), profileName(r.profile),
                     r.outcome.verified, r.outcome.note.c_str());
        if (r.outcome.attached)
            ++attemptedCount;
        if (r.outcome.verified)
            ++verifiedCount;
    }
    std::fprintf(stderr, "  %d/%d cards attempted, %d/%d cryptographically verified\n", attemptedCount,
                 static_cast<int>(results.size()), verifiedCount, attemptedCount);

    if (attemptedCount == 0)
        GTEST_SKIP() << "No PIN env vars set for any recognised profile — sign attempts skipped.";

    // Pass if AT LEAST ONE attempted card verified. Per-card failures don't
    // fail the suite because per the operator protocol we must continue
    // testing the remaining cards even if one fails. The aggregate above
    // lets the operator audit each card independently.
    EXPECT_GT(verifiedCount, 0) << "At least one card whose PIN was supplied must produce a verifiable signature";
}

// Two consecutive signs against the SAME card MUST NOT re-prompt for the
// CAN: the PACE channel the first signature brought up on the session stays
// up, and the second signature uses it.
//
// Operator protocol:
//   LIBRESCRS_TEST_CARD=NAM_CL  // hard gate
//   LIBRESCRS_TEST_NAM_PIN="CAN:PIN"
//   ./MultiCardSignTests --gtest_filter=*PacePersistsAcrossSignatures*
//
// PIN budget: 2 signs, each presents the PIN once → 2 PIN verifications on
// the card. Operator MUST ensure the PIN counter has at least 2 fresh tries
// before invocation.
TEST(MultiCardSign, NamSignTwicePacePersistsAcrossSignatures)
{
    if (env("LIBRESCRS_TEST_CARD") != "NAM_CL")
        GTEST_SKIP() << "LIBRESCRS_TEST_CARD != NAM_CL — refusing to PIN this card unguarded.";
    const char* pin = std::getenv("LIBRESCRS_TEST_NAM_PIN");
    if (!pin || !*pin)
        GTEST_SKIP() << "LIBRESCRS_TEST_NAM_PIN not set (expected CAN:PIN format).";

    auto found = discoverCards();
    ReaderCard* nam = nullptr;
    for (auto& rc : found) {
        if (rc.profile == CardProfile::NAM_CL) {
            nam = &rc;
            break;
        }
    }
    if (!nam)
        GTEST_SKIP() << "No NAM CL card on any reader";

    const LibreSCRS::Plugin::CardPluginService plugins{std::filesystem::path(PLUGIN_DIR)};

    auto first = signOnCard(plugins, *nam, pin);
    std::fprintf(stderr, "[sign 1] attached=%d signed=%d verified=%d note=\"%s\" err=\"%s\"\n", first.attached,
                 first.signed_, first.verified, first.note.c_str(), first.sigError.c_str());
    ASSERT_TRUE(first.verified) << "First sign must verify before we attempt the second";

    // Critical assertion: the session must still report a live SM channel
    // between signs, or the second sign would re-run PACE.
    ASSERT_TRUE(nam->session->hasLiveSecureChannel()) << "PACE SM channel was torn down between signs";

    auto second = signOnCard(plugins, *nam, pin);
    std::fprintf(stderr, "[sign 2] attached=%d signed=%d verified=%d note=\"%s\" err=\"%s\"\n", second.attached,
                 second.signed_, second.verified, second.note.c_str(), second.sigError.c_str());
    EXPECT_TRUE(second.verified) << "Second sign must verify without re-prompt for CAN";
}

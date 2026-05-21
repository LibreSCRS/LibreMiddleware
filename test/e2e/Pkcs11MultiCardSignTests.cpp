// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Multi-card 4.1.0 regression smoke. Iterates every PCSC reader the
// system reports and attempts the full inject-path sign cycle against
// whichever recognised card profile is present on each reader. Per-card
// PIN-failure latching halts further PIN ops on a card that fails while
// the other readers continue independently — no cross-contamination.
//
// Card → PIN map (operator-supplied via env or compiled-in fallback):
//   PKS  (CardEdge, SmartCafe Expert v8.0 B)  → bare PIN
//   NAM  (Cryptovision SCE 8.0-C2V0 CL)       → CAN:PIN (PACE then verify)
//   PIV  (G+D SCE7)                           → bare PIN (PIV-aware path)
//
// Opt-in: gated on LIBRESCRS_BUILD_REAL_CARD_TESTS=ON. NOT in default
// ctest set. Operator invocation:
//
//   LIBRESCRS_TEST_PKS_PIN="0114" \
//   LIBRESCRS_TEST_NAM_PIN="123456:654321" \
//   LIBRESCRS_TEST_PIV_PIN="569548" \
//   ./Pkcs11MultiCardSignTests

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
#include <LibreSCRS/Pkcs11/SessionInjection.h>
#include <LibreSCRS/Secure/Buffer.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>

#include <dlfcn.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11/pkcs11.h"

#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"

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

    // SCE 8.0-C2V0 contactless = NAM CL (Cryptovision Veridos Suite SSCD).
    // Hist bytes literally spell "SCE 8.0-C2V0".
    if (contains({0x53, 0x43, 0x45, 0x20, 0x38, 0x2E, 0x30, 0x2D, 0x43, 0x32, 0x56, 0x30}))
        return CardProfile::NAM_CL;

    // SCE 8.0-C1V0 contact = PKS (Serbian PKS, SmartCafe Expert v8.0 B
    // per OpenSC card-srbeid.c).
    if (contains({0x53, 0x43, 0x45, 0x20, 0x38, 0x2E, 0x30, 0x2D, 0x43, 0x31, 0x56, 0x30}))
        return CardProfile::PKS;

    // SmartCafe Expert v7 platform with G+D PIV applet personalisation.
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

std::filesystem::path modulePath()
{
    if (const char* o = std::getenv("LIBRESCRS_PKCS11_MODULE_PATH"))
        return o;
    return std::filesystem::path{LIBRESCRS_PKCS11_MODULE_PATH};
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

bool looksLikePinError(const std::string& what)
{
    static constexpr std::array<const char*, 5> kNeedles = {
        "PIN", "0x000000a0", "0x000000A0", "0x000000a1", "0x000000a4",
    };
    for (const auto* needle : kNeedles)
        if (what.find(needle) != std::string::npos)
            return true;
    return false;
}

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
    bool attached = false;
    bool loggedIn = false;
    bool certRead = false;
    bool signed_ = false;
    bool verified = false;
    std::string note;
    std::string sigError;
};

/// Run the full inject-path sign cycle on @p rc using @p pin. Latches
/// the profile-specific PIN-failure flag on any PIN-related error so
/// subsequent ops on the SAME card skip without burning more retries.
/// @param moduleManager Shared loaded-module cache; passed by the test
///                      so each per-card sign acquires a fresh handle
///                      against the same C_Initialize-ed module —
///                      mirrors the production NativeSigningService
///                      composition.
SignOutcome signOnCard(libresign::Pkcs11ModuleManager& moduleManager, ReaderCard& rc, const std::string& pin)
{
    SignOutcome o;
    if (g_latch.isFailed(rc.profile)) {
        o.note = "skipped — earlier PIN failure latched for this profile";
        return o;
    }

    // NAM CL eager-bind flow: pre-deposit the CAN portion via
    // setPaceSecret (PACE is required even to read the AODF over CL),
    // then pass the BARE PIN to C_Login. Real-AODF slot publishes
    // maxPinLen=12; the 6-byte PIN fits. Passing the full 13-byte
    // "CAN:PIN" here would hit the dispatcher's length gate
    // (CKR_PIN_LEN_RANGE) before slot.login() runs.
    std::string pinForLogin = pin;
    if (rc.profile == CardProfile::NAM_CL) {
        auto colon = pin.find(':');
        if (colon == std::string::npos) {
            o.note = "NAM CL expects CAN:PIN format; got bare PIN";
            return o;
        }
        std::string can = pin.substr(0, colon);
        rc.session->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can, LibreSCRS::Secure::String{can});
        pinForLogin = pin.substr(colon + 1);
    }

    std::unique_ptr<libresign::Pkcs11Token> token;
    try {
        LibreSCRS::Secure::Buffer pinBuf(pinForLogin);
        token = std::make_unique<libresign::Pkcs11Token>(moduleManager.acquire(modulePath()), pinBuf,
                                                         /*keyAlias=*/std::string{}, rc.reader, rc.session);
        o.loggedIn = true;
        o.attached = true; // attachment is performed inside Pkcs11Token::Impl
    } catch (const std::exception& e) {
        o.sigError = e.what();
        if (looksLikePinError(o.sigError)) {
            g_latch.markFailed(rc.profile);
            o.note = "PIN error during attach/login; profile latched";
        } else {
            o.note = "attach/login failure (non-PIN)";
        }
        return o;
    }

    try {
        auto cert = token->certificate();
        o.certRead = !cert.empty();
    } catch (const std::exception& e) {
        o.sigError = e.what();
        o.note = "certificate read failed";
        return o;
    }

    // Sign a fixed test payload. Pass raw bytes so the libresign 4.1
    // combined-mechanism path can drive hash-on-card SSCDs correctly.
    const std::vector<std::uint8_t> payload = {'r', 'c', '-', '4', '.', '1', '.', '0', '-',
                                               'm', 'u', 'l', 't', 'i', 'c', 'a', 'r', 'd'};
    std::array<std::uint8_t, 32> digest{};
    {
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        unsigned int n = 0;
        EVP_DigestInit_ex(md, EVP_sha256(), nullptr);
        EVP_DigestUpdate(md, payload.data(), payload.size());
        EVP_DigestFinal_ex(md, digest.data(), &n);
        EVP_MD_CTX_free(md);
    }
    static constexpr std::array<std::uint8_t, 19> kSha256DigestInfoPrefix = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                             0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                             0x01, 0x05, 0x00, 0x04, 0x20};
    std::vector<std::uint8_t> signInput;
    signInput.reserve(kSha256DigestInfoPrefix.size() + digest.size());
    signInput.insert(signInput.end(), kSha256DigestInfoPrefix.begin(), kSha256DigestInfoPrefix.end());
    signInput.insert(signInput.end(), digest.begin(), digest.end());

    std::vector<std::uint8_t> signature;
    try {
        signature = token->sign(signInput, "SHA256withRSA", std::span<const std::uint8_t>{payload});
    } catch (const std::exception& e) {
        o.sigError = e.what();
        if (looksLikePinError(o.sigError))
            g_latch.markFailed(rc.profile);
        o.note = "sign failed";
        return o;
    }

    if (signature.empty()) {
        o.note = "sign returned empty";
        return o;
    }
    o.signed_ = true;

    // Verify against the on-card cert's public key.
    auto certDer = token->certificate();
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

TEST(Pkcs11MultiCardSign, AllPresentReadersIndependent)
{
    auto found = discoverCards();
    std::fprintf(stderr, "\n=== Pkcs11MultiCardSign: %zu reader(s) with a card present ===\n", found.size());
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

    // Shared loaded-module cache for the whole multi-card sweep.
    // Mirrors the production NativeSigningService composition so the
    // module stays mapped across all per-card signs — critical for
    // test #1 (two consecutive signs against the same module without
    // a C_Finalize between them).
    libresign::Pkcs11ModuleManager moduleManager;

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
        auto outcome = signOnCard(moduleManager, rc, pin);
        std::fprintf(stderr, "    attached=%d login=%d cert=%d signed=%d verified=%d note=\"%s\" err=\"%s\"\n",
                     outcome.attached, outcome.loggedIn, outcome.certRead, outcome.signed_, outcome.verified,
                     outcome.note.c_str(), outcome.sigError.c_str());
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

// Two consecutive signs against the SAME card MUST NOT re-prompt for
// the CAN. Regression test for the per-Token dlopen+dlclose cycle that
// previously tore down the loaded module's SessionRegistry between
// signs and forced a fresh PACE handshake (with CAN re-prompt) on the
// second sign. The shared loaded-module cache owned by the
// Pkcs11ModuleManager is what keeps the module mapped across both
// signs; if that invariant breaks, the second sign throws because the
// SessionAttachment placed before sign 1 is gone by the time sign 2
// constructs its Token.
//
// Operator protocol:
//   LIBRESCRS_TEST_CARD=NAM_CL  // hard gate
//   LIBRESCRS_TEST_NAM_PIN="CAN:PIN"
//   ./Pkcs11MultiCardSignTests --gtest_filter=*PacePersistsAcrossTokens*
//
// PIN budget: 2 signs; both go through C_Login → 2 PIN counter
// decrements on the card. Operator MUST ensure the PIN counter has
// at least 2 fresh tries before invocation.
TEST(Pkcs11MultiCardSign, NamSignTwicePacePersistsAcrossTokens)
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

    libresign::Pkcs11ModuleManager moduleManager;

    auto first = signOnCard(moduleManager, *nam, pin);
    std::fprintf(stderr, "[sign 1] attached=%d login=%d signed=%d verified=%d note=\"%s\" err=\"%s\"\n", first.attached,
                 first.loggedIn, first.signed_, first.verified, first.note.c_str(), first.sigError.c_str());
    ASSERT_TRUE(first.verified) << "First sign must verify before we attempt the second";

    // Critical assertion: the session must still report a live SM
    // channel between signs. If the previous Token destructor had
    // dlclose-d the module (and the SessionAttachment destructor had
    // followed the old clearActiveChannel path), this would now be
    // false and the second sign would re-prompt for CAN.
    ASSERT_TRUE(nam->session->hasLiveSecureChannel())
        << "PACE SM channel was torn down between signs — Pkcs11ModuleManager invariant broken";

    auto second = signOnCard(moduleManager, *nam, pin);
    std::fprintf(stderr, "[sign 2] attached=%d login=%d signed=%d verified=%d note=\"%s\" err=\"%s\"\n",
                 second.attached, second.loggedIn, second.signed_, second.verified, second.note.c_str(),
                 second.sigError.c_str());
    EXPECT_TRUE(second.verified) << "Second sign must verify without re-prompt for CAN";
}

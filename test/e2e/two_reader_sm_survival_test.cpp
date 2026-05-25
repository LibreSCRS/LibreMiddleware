// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Two-reader SM-survival confirmation (CAN-only, NO PIN).
//
// Confirms that a live PACE Secure-Messaging channel on reader A (NAM
// contactless) SURVIVES the opensc-pkcs11 provider binding reader B
// (cardedge / PKS contact). The provider's bind runs
// sc_establish_context — which ENUMERATES ALL readers — followed by a
// per-reader sc_connect_card(B). This test proves that enumeration +
// the connect to B does NOT disturb A's live SM.
//
// If A's SM survives, the dormant scoped_reader_name OpenSC patch
// (thirdparty/patches/0002, the reader-whitelist half) is confirmed
// superseded by SessionPresence + per-reader bind and is safe to remove.
//
// CARD-SAFETY: this is a CAN-ONLY test. NO PIN VERIFY / C_Login is ever
// issued to either card. The NAM CAN has no retry counter and PACE
// failures don't touch any PIN counter, so there is zero block risk.
// Reader B's bind needs no PIN (just sc_connect_card + sc_pkcs15_bind).
//
// Opt-in: gated on LIBRESCRS_BUILD_REAL_CARD_TESTS=ON. NOT in the
// default ctest set. Operator invocation:
//
//   LIBRESCRS_TEST_CAN="123456"
//   LIBRESCRS_PCSC_TRACE=1
//   ./TwoReaderSmSurvivalTest
//
// Required hardware: BOTH a NAM contactless card (reader name contains
// "OMNIKEY 5422CL", ATR hist bytes "SCE 8.0-C2V0") AND a cardedge / PKS
// contact card (reader name contains "Gemalto PC Twin Reader", ATR hist
// bytes "SCE 8.0-C1V0"). If either is missing the test GTEST_SKIPs.

#include "pin_guard.h"

#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/ActiveChannelHolder.h>
#include <LibreSCRS/SmartCard/AppletAid.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/MonitorService.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <internal/OpenScPKCS11Provider.h>

#include <gtest/gtest.h>

#include <cstdint>
#include <cstdio>
#include <initializer_list>
#include <memory>
#include <string>
#include <vector>

namespace {

using LibreSCRS::Tests::E2E::env;

enum class CardProfile { Unknown, PKS, NAM_CL };

const char* profileName(CardProfile p)
{
    switch (p) {
    case CardProfile::PKS:
        return "PKS";
    case CardProfile::NAM_CL:
        return "NAM_CL";
    case CardProfile::Unknown:
    default:
        return "Unknown";
    }
}

// Classify a card by ATR. Mirrors Pkcs11MultiCardSignTests::classifyByAtr;
// only the two profiles this test needs are distinguished. Reader A is
// the NAM contactless card (hist bytes "SCE 8.0-C2V0"); reader B is the
// PKS / cardedge contact card (hist bytes "SCE 8.0-C1V0").
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

    // SCE 8.0-C2V0 contactless = NAM CL (reader A).
    if (contains({0x53, 0x43, 0x45, 0x20, 0x38, 0x2E, 0x30, 0x2D, 0x43, 0x32, 0x56, 0x30}))
        return CardProfile::NAM_CL;
    // SCE 8.0-C1V0 contact = PKS / cardedge (reader B).
    if (contains({0x53, 0x43, 0x45, 0x20, 0x38, 0x2E, 0x30, 0x2D, 0x43, 0x31, 0x56, 0x30}))
        return CardProfile::PKS;
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

struct ReaderCard
{
    std::string reader;
    std::vector<std::uint8_t> atr;
    CardProfile profile;
    std::shared_ptr<LibreSCRS::SmartCard::CardSession> session;
};

// Discover every reader with a present card, classify by ATR, open a
// CardSession on each (kept alive for the SessionPresence registration
// and the live SM that persists on the session Impl after we release the
// ActiveChannelHolder).
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

// NAM PKCS#15 applet AID: A0 00 00 00 63 50 4B 43 53 2D 31 35 ("PKCS-15").
const LibreSCRS::SmartCard::AppletAid kPkcs15Aid{
    std::vector<std::uint8_t>{0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35}};

} // namespace

// Confirm that binding reader B through the opensc-pkcs11 provider does
// NOT disturb reader A's live PACE SM channel.
//
// PASS  => A's SM survived => scoped_reader_name whitelist superseded.
// FAIL  => A's SM disturbed => the whitelist patch is still needed.
TEST(TwoReaderSmSurvival, ProviderBindOnReaderBDoesNotDisturbLiveSmOnReaderA)
{
    // CAN-only gate. NO PIN env is consulted or required.
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");
    const std::string can = env("LIBRESCRS_TEST_CAN");

    auto found = discoverCards();
    std::fprintf(stderr, "\n=== TwoReaderSmSurvival: %zu reader(s) with a card present ===\n", found.size());
    for (const auto& rc : found)
        std::fprintf(stderr, "  reader=%s profile=%s atr=%s\n", rc.reader.c_str(), profileName(rc.profile),
                     atrHex(rc.atr).c_str());

    ReaderCard* a = nullptr; // NAM_CL  (live PACE SM)
    ReaderCard* b = nullptr; // PKS     (provider bind target)
    for (auto& rc : found) {
        if (rc.profile == CardProfile::NAM_CL && !a)
            a = &rc;
        else if (rc.profile == CardProfile::PKS && !b)
            b = &rc;
    }
    if (!a)
        GTEST_SKIP() << "No NAM_CL (reader A) card present — cannot establish a live PACE SM channel.";
    if (!b)
        GTEST_SKIP() << "No PKS / cardedge (reader B) card present — cannot exercise the provider bind.";

    std::fprintf(stderr, "\n  A (NAM_CL) reader = %s\n  B (PKS)    reader = %s\n", a->reader.c_str(),
                 b->reader.c_str());

    // --- Step 3: bring up A's live PACE SM (CAN only), then release the
    // holder so the live SM + SessionPresence registration persist on the
    // session Impl (the holder borrows the session mutex / PC/SC
    // transaction; releasing it leaves the SM keys live for fast-path
    // reuse). NO PIN is submitted.
    a->session->setPaceSecret(LibreSCRS::Auth::PaceSecretKind::Can, LibreSCRS::Secure::String{can});
    {
        auto holder = a->session->activateChannelWithSm(
            kPkcs15Aid, LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can},
            LibreSCRS::CancelToken{});
        ASSERT_TRUE(holder.has_value())
            << "Failed to establish PACE SM on reader A (CAN). This is not a PIN failure — CAN has no "
               "retry counter — but without a live SM the survival question is moot.";
    } // holder released here; live SM + SessionPresence entry persist on the session.

    ASSERT_TRUE(a->session->hasLiveSecureChannel())
        << "Reader A reported no live SM after releasing the holder — SessionPresence/SM did not persist; "
           "the survival test cannot proceed.";
    std::fprintf(stderr, "  [A] live PACE SM established and persists after holder release.\n");

    // --- Step 4: bind reader B through the EXACT product path:
    // OpenScPKCS11Provider::probe(B) runs the SessionPresence guard for B
    // (B has no live SM, so the probe proceeds) then OpenScCard::bind(B),
    // which does sc_establish_context (ALL-reader enumeration) +
    // sc_ctx_get_reader_by_name(B) + sc_connect_card(B) + sc_pkcs15_bind.
    // NO PIN, NO sign.
    std::fprintf(stderr, "  [B] binding via OpenScPKCS11Provider::probe (sc_establish_context enumerates ALL "
                         "readers, then sc_connect_card(B)) ...\n");
    LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider provider;
    auto boundB = provider.probe(b->reader);
    ASSERT_NE(boundB, nullptr)
        << "Provider bind on reader B returned nullptr — either SessionPresence wrongly reported a live SM "
           "on B, or sc_pkcs15_bind failed. Without a successful B bind the enumeration+connect that this "
           "test interrogates did not run.";
    std::fprintf(stderr, "  [B] provider bind succeeded (sc_establish_context enumeration + sc_connect_card(B) "
                         "completed).\n");

    // --- Step 5: re-verify A's SM SURVIVED B's bind.
    // First the cheap predicate, then a real SM-protected operation: a
    // same-applet activateChannelWithSm fast-path. If A's SM tunnel were
    // reset/corrupted by B's bind, either hasLiveSecureChannel() flips
    // false or the re-activation fails (the SM no longer encrypts/MACs).
    const bool stillLive = a->session->hasLiveSecureChannel();
    std::fprintf(stderr, "  [A] hasLiveSecureChannel() after B bind = %d\n", stillLive);
    EXPECT_TRUE(stillLive) << "VERDICT FAIL: reader A's live SM flag flipped FALSE after the reader-B "
                              "provider bind — B's bind DISTURBED A. scoped_reader_name whitelist still needed.";

    bool smOpSurvived = false;
    {
        auto reactivate = a->session->activateChannelWithSm(
            kPkcs15Aid, LibreSCRS::SmartCard::PaceRequest{LibreSCRS::Auth::PaceSecretKind::Can},
            LibreSCRS::CancelToken{});
        smOpSurvived = reactivate.has_value();
        std::fprintf(stderr, "  [A] SM-protected re-activation (same applet, fast-path) after B bind = %d\n",
                     smOpSurvived);
    }
    EXPECT_TRUE(smOpSurvived)
        << "VERDICT FAIL: SM-protected operation on reader A FAILED after the reader-B provider bind — "
           "B's bind corrupted A's SM tunnel. scoped_reader_name whitelist still needed.";

    if (stillLive && smOpSurvived)
        std::fprintf(stderr, "\n=== VERDICT: PASS — reader A's live PACE SM SURVIVED reader B's provider bind. "
                             "scoped_reader_name whitelist confirmed superseded by SessionPresence + per-reader "
                             "bind; safe to remove. ===\n");
    else
        std::fprintf(stderr, "\n=== VERDICT: FAIL — reader A's SM was DISTURBED by reader B's bind. "
                             "scoped_reader_name whitelist still needed. ===\n");
}

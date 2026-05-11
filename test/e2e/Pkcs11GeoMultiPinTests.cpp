// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Real-card E2E tests for the GEO eID dual-PIN card. Per spec
// `2026-05-09-pkcs11-multi-pin-card-slot-design.md` §5.4.1, GEO exposes
// two PKCS#11 slots (Auth + Sign / QSCD) for one physical card. Tests
// here exercise the production `librescrs-pkcs11.so` through the C ABI
// only — they never reach into LibreSCRS::Pkcs11::Internal types (the
// dylib hides those via its symbol allowlist).
//
// Every test:
//   * Begins with SKIP_IF_PIN_FAILED() so a single PIN failure blocks
//     the rest of the suite (retry-counter protection).
//   * Calls REQUIRE_ENV(...) for the PIN/CAN env vars it needs and
//     skips cleanly when they are unset (CI / dev workstation w/o card).
//   * Uses LOGIN_OR_ABORT(...) around C_Login so any non-CKR_OK trips
//     g_pinFailed before the next test runs.

#include "pin_guard.h"

// Platform-specific PKCS#11 macros must be defined BEFORE pkcs11.h is
// included (the header is OASIS-portable and asks consumers to define
// CK_PTR / CK_DECLARE_FUNCTION / CK_DECLARE_FUNCTION_POINTER /
// CK_CALLBACK_FUNCTION / NULL_PTR themselves). We intentionally do not
// include `pkcs11_platform.h` from `lib/pkcs11/src/` because that path
// is private to the .so build; replicate the four-line preamble here.
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif

#include <pkcs11/pkcs11.h>

#include <gtest/gtest.h>

#include <array>
#include <cstring>
#include <string>
#include <vector>

using LibreSCRS::Tests::E2E::env;

namespace {

// ---------------------------------------------------------------------------
// Fixture — initialises the live `librescrs-pkcs11.so` once per test, locates
// the GEO card by enumerating slots with tokens present, and tears down via
// C_Finalize. We require exactly two slots reported by the .so for a GEO
// card; the spec guarantees this (Auth + QSCD).
// ---------------------------------------------------------------------------
class Pkcs11GeoFixture : public ::testing::Test
{
protected:
    void SetUp() override
    {
        SKIP_IF_PIN_FAILED();
        const CK_RV rv = C_Initialize(nullptr);
        ASSERT_TRUE(rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED)
            << "C_Initialize returned 0x" << std::hex << rv;
    }

    void TearDown() override
    {
        // C_Finalize is best-effort: if the test already finalised (e.g.
        // via a session-cleanup helper) the second call returns
        // CKR_CRYPTOKI_NOT_INITIALIZED, which we accept silently.
        (void)C_Finalize(nullptr);
    }

    // Returns the slot list reported with tokenPresent=true. Skips the
    // test when no slots are present (no card inserted on this dev box).
    std::vector<CK_SLOT_ID> slotsWithToken()
    {
        CK_ULONG count = 0;
        CK_RV rv = C_GetSlotList(CK_TRUE, nullptr, &count);
        if (rv != CKR_OK || count == 0)
            return {};
        std::vector<CK_SLOT_ID> slots(count);
        rv = C_GetSlotList(CK_TRUE, slots.data(), &count);
        if (rv != CKR_OK)
            return {};
        slots.resize(count);
        return slots;
    }

    // Returns true if the (utf8-padded, space-trimmed) label of the
    // token in `slot` contains any of the substrings in `needles`
    // (case-insensitive ASCII match).
    static bool labelContainsAny(CK_SLOT_ID slot, std::initializer_list<const char*> needles)
    {
        CK_TOKEN_INFO info{};
        if (C_GetTokenInfo(slot, &info) != CKR_OK)
            return false;
        std::string label(reinterpret_cast<const char*>(info.label), sizeof(info.label));
        // PKCS#11 labels are space-padded to 32 bytes; lower-case for
        // case-insensitive substring search.
        for (auto& c : label)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (const char* needle : needles) {
            std::string n{needle};
            for (auto& c : n)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (label.find(n) != std::string::npos)
                return true;
        }
        return false;
    }
};

// Helpers to build the PIN bytes that C_Login expects. PKCS#11 takes a
// CK_UTF8CHAR* — for our PACE-cards we encode CAN-in-PIN as
// `${CAN}:${PIN}`; for contact cards `pin` alone.
std::vector<CK_UTF8CHAR> makePinBytes(const std::string& s)
{
    return std::vector<CK_UTF8CHAR>(s.begin(), s.end());
}

std::string canInPin(const std::string& can, const std::string& pin)
{
    return can + ":" + pin;
}

} // namespace

// ===========================================================================
// Contact-interface tests (no PACE) — GEO inserted in a contact reader.
// ===========================================================================

TEST_F(Pkcs11GeoFixture, GeoContact_GetSlotList_ReturnsTwoSlots)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    REQUIRE_ENV("LIBRESCRS_TEST_PIN_QSCD");

    const auto slots = slotsWithToken();
    if (slots.empty())
        GTEST_SKIP() << "No PKCS#11 slots with tokens present (no GEO card inserted?)";

    // GEO is the only card in our reference matrix expected to expose
    // two slots from a single physical card. If we see exactly one slot
    // the inserted card is likely eID/NAM and this GEO-specific test
    // does not apply — skip rather than fail.
    if (slots.size() < 2)
        GTEST_SKIP() << "GEO requires 2 slots; got " << slots.size() << " (probably non-GEO card inserted).";

    EXPECT_EQ(slots.size(), 2u) << "GEO card must expose exactly 2 PKCS#11 slots (Auth + Sign).";
}

TEST_F(Pkcs11GeoFixture, GeoContact_AuthSlotPinLabel)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    REQUIRE_ENV("LIBRESCRS_TEST_PIN_QSCD"); // GEO sentinel: only set on multi-PIN GEO test setups.

    const auto slots = slotsWithToken();
    if (slots.size() < 2)
        GTEST_SKIP() << "Need GEO 2-slot card for this test.";

    EXPECT_TRUE(labelContainsAny(slots[0], {"auth", "authentication"}))
        << "Slot 0 token label should reference Auth/Authentication PIN.";
}

TEST_F(Pkcs11GeoFixture, GeoContact_SignSlotPinLabel)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN_QSCD");

    const auto slots = slotsWithToken();
    if (slots.size() < 2)
        GTEST_SKIP() << "Need GEO 2-slot card for this test.";

    EXPECT_TRUE(labelContainsAny(slots[1], {"sign", "qscd", "signing"}))
        << "Slot 1 token label should reference Sign / QSCD.";
}

TEST_F(Pkcs11GeoFixture, GeoContact_AuthSlotLogin_DoesNotAffectSignSlot)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");

    const auto slots = slotsWithToken();
    if (slots.size() < 2)
        GTEST_SKIP() << "Need GEO 2-slot card for this test.";

    CK_SESSION_HANDLE authSession = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE signSession = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(slots[0], CKF_SERIAL_SESSION, nullptr, nullptr, &authSession), CKR_OK);
    ASSERT_EQ(C_OpenSession(slots[1], CKF_SERIAL_SESSION, nullptr, nullptr, &signSession), CKR_OK);

    auto pinBytes = makePinBytes(env("LIBRESCRS_TEST_PIN"));
    const CK_RV rv = C_Login(authSession, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
    LOGIN_OR_ABORT(rv, slots[0], "C_Login(Auth)");

    CK_SESSION_INFO sinfo{};
    ASSERT_EQ(C_GetSessionInfo(signSession, &sinfo), CKR_OK);
    EXPECT_EQ(sinfo.state, CKS_RO_PUBLIC_SESSION)
        << "Sign-slot session state must remain NOT_LOGGED_IN after Auth-slot login "
           "(per spec login-isolation requirement).";

    (void)C_Logout(authSession);
    (void)C_CloseSession(authSession);
    (void)C_CloseSession(signSession);
}

TEST_F(Pkcs11GeoFixture, GeoContact_SignSlotSignsWithQscdKey)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN_QSCD");

    const auto slots = slotsWithToken();
    if (slots.size() < 2)
        GTEST_SKIP() << "Need GEO 2-slot card for this test.";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(slots[1], CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    auto pinBytes = makePinBytes(env("LIBRESCRS_TEST_PIN_QSCD"));
    const CK_RV rv = C_Login(session, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
    LOGIN_OR_ABORT(rv, slots[1], "C_Login(Sign/QSCD)");

    // Locate a private RSA key on this slot.
    CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    std::array<CK_ATTRIBUTE, 2> tmpl{{{CKA_CLASS, &klass, sizeof(klass)}, {CKA_KEY_TYPE, &keyType, sizeof(keyType)}}};
    ASSERT_EQ(C_FindObjectsInit(session, tmpl.data(), tmpl.size()), CKR_OK);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG found = 0;
    ASSERT_EQ(C_FindObjects(session, &key, 1, &found), CKR_OK);
    ASSERT_EQ(C_FindObjectsFinal(session), CKR_OK);
    ASSERT_GT(found, 0u) << "GEO Sign slot should expose at least one private RSA key.";

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(C_SignInit(session, &mech, key), CKR_OK);

    // 32-byte SHA-256 digest stand-in (test-only). Real signing flows
    // would prepend the DigestInfo structure for CKM_RSA_PKCS but for
    // an "is the key responsive" smoke test the raw 32 bytes suffice —
    // any non-empty signature of the expected length proves the QSCD
    // key was actually exercised.
    std::array<CK_BYTE, 32> data{};
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<CK_BYTE>(i);

    CK_ULONG sigLen = 0;
    ASSERT_EQ(C_Sign(session, data.data(), data.size(), nullptr, &sigLen), CKR_OK);
    EXPECT_GT(sigLen, 0u);
    std::vector<CK_BYTE> sig(sigLen);
    ASSERT_EQ(C_Sign(session, data.data(), data.size(), sig.data(), &sigLen), CKR_OK);
    EXPECT_GT(sigLen, 0u);
    EXPECT_EQ(sig.size(), sigLen);

    (void)C_Logout(session);
    (void)C_CloseSession(session);
}

// ===========================================================================
// Contactless tests — GEO on an NFC reader; PACE required.
// ===========================================================================

TEST_F(Pkcs11GeoFixture, GeoContactless_CanInPinSplits)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN_QSCD");
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    const auto slots = slotsWithToken();
    if (slots.size() < 2)
        GTEST_SKIP() << "Need GEO 2-slot card on contactless reader for this test.";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(slots[1], CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    const std::string canPin = canInPin(env("LIBRESCRS_TEST_CAN"), env("LIBRESCRS_TEST_PIN_QSCD"));
    auto pinBytes = makePinBytes(canPin);
    const CK_RV rv = C_Login(session, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
    LOGIN_OR_ABORT(rv, slots[1], "C_Login(CAN-in-PIN)");

    // Sanity: post-login session reports an authenticated state.
    CK_SESSION_INFO sinfo{};
    ASSERT_EQ(C_GetSessionInfo(session, &sinfo), CKR_OK);
    EXPECT_TRUE(sinfo.state == CKS_RO_USER_FUNCTIONS || sinfo.state == CKS_RW_USER_FUNCTIONS)
        << "After CAN-in-PIN login the session must be USER_FUNCTIONS, got " << sinfo.state;

    (void)C_Logout(session);
    (void)C_CloseSession(session);
}

TEST_F(Pkcs11GeoFixture, GeoContactless_PaceCachedAcrossSiblingLogins)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    REQUIRE_ENV("LIBRESCRS_TEST_PIN_QSCD");
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    const auto slots = slotsWithToken();
    if (slots.size() < 2)
        GTEST_SKIP() << "Need GEO 2-slot card on contactless reader for this test.";

    // Login on the Auth slot with CAN-in-PIN — this establishes PACE on
    // the parent Card. The Sign slot login should then succeed with PIN
    // alone (no CAN prefix) because PACE is cached at the Card level.
    CK_SESSION_HANDLE authSession = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE signSession = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(slots[0], CKF_SERIAL_SESSION, nullptr, nullptr, &authSession), CKR_OK);
    ASSERT_EQ(C_OpenSession(slots[1], CKF_SERIAL_SESSION, nullptr, nullptr, &signSession), CKR_OK);

    {
        const std::string canPin = canInPin(env("LIBRESCRS_TEST_CAN"), env("LIBRESCRS_TEST_PIN"));
        auto pinBytes = makePinBytes(canPin);
        const CK_RV rv = C_Login(authSession, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, slots[0], "C_Login(Auth, CAN-in-PIN)");
    }

    {
        // PIN alone — no CAN prefix. Spec promises PACE-cache reuse.
        auto pinBytes = makePinBytes(env("LIBRESCRS_TEST_PIN_QSCD"));
        const CK_RV rv = C_Login(signSession, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, slots[1], "C_Login(Sign, PIN-only post-PACE)");
    }

    (void)C_Logout(authSession);
    (void)C_Logout(signSession);
    (void)C_CloseSession(authSession);
    (void)C_CloseSession(signSession);
}

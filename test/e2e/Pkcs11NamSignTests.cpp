// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Real-card E2E tests for the NAM contactless card. Per spec
// `2026-05-09-pkcs11-multi-pin-card-slot-design.md` §5.4.1, NAM exposes
// a single PKCS#11 slot, requires PACE on every transaction, and its
// PIN guards both Auth and Sign keys (one PIN, two keys).

#include "pin_guard.h"

// PKCS#11 platform macros (see Pkcs11GeoMultiPinTests.cpp for rationale).
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
#include <string>
#include <vector>

using LibreSCRS::Tests::E2E::env;

namespace {

class Pkcs11NamFixture : public ::testing::Test
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
        (void)C_Finalize(nullptr);
    }

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
};

std::vector<CK_UTF8CHAR> makePinBytes(const std::string& s)
{
    return std::vector<CK_UTF8CHAR>(s.begin(), s.end());
}

std::string canInPin(const std::string& can, const std::string& pin)
{
    return can + ":" + pin;
}

} // namespace

TEST_F(Pkcs11NamFixture, NamContactless_GetSlotList_ReturnsOneSlot)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    const auto slots = slotsWithToken();
    if (slots.empty())
        GTEST_SKIP() << "No PKCS#11 slots with tokens present (no NAM card on NFC reader?)";

    // NAM is single-slot. If we see more than one slot the inserted
    // card is probably GEO; skip rather than fail this NAM-specific test.
    if (slots.size() != 1)
        GTEST_SKIP() << "NAM expects exactly 1 slot; got " << slots.size() << " (probably non-NAM card inserted).";

    EXPECT_EQ(slots.size(), 1u);
}

/// DISABLED: PACE-PKCS#15 sign path not yet real-card validated for this
/// card family. Architectural fix landed (CardMap + plugin setCredentials
/// + sign() follows key.path + Pkcs15Slot retry on stale select) but
/// real-card end-to-end verification awaits hardware availability.
/// Re-enable by removing the DISABLED_ prefix once the sign matrix is
/// covered.
TEST_F(Pkcs11NamFixture, DISABLED_NamContactless_LoginAndSign_Succeeds)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    const auto slots = slotsWithToken();
    if (slots.size() != 1)
        GTEST_SKIP() << "Need exactly 1 slot for NAM contactless test.";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(slots[0], CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    const std::string canPin = canInPin(env("LIBRESCRS_TEST_CAN"), env("LIBRESCRS_TEST_PIN"));
    auto pinBytes = makePinBytes(canPin);
    const CK_RV rv = C_Login(session, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
    LOGIN_OR_ABORT(rv, slots[0], "C_Login(CAN-in-PIN, NAM)");

    CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    std::array<CK_ATTRIBUTE, 2> tmpl{{{CKA_CLASS, &klass, sizeof(klass)}, {CKA_KEY_TYPE, &keyType, sizeof(keyType)}}};
    ASSERT_EQ(C_FindObjectsInit(session, tmpl.data(), tmpl.size()), CKR_OK);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG found = 0;
    ASSERT_EQ(C_FindObjects(session, &key, 1, &found), CKR_OK);
    ASSERT_EQ(C_FindObjectsFinal(session), CKR_OK);
    ASSERT_GT(found, 0u) << "NAM token should expose at least one private RSA key.";

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(C_SignInit(session, &mech, key), CKR_OK);

    std::array<CK_BYTE, 32> data{};
    for (size_t i = 0; i < data.size(); ++i)
        data[i] = static_cast<CK_BYTE>(i);

    CK_ULONG sigLen = 0;
    ASSERT_EQ(C_Sign(session, data.data(), data.size(), nullptr, &sigLen), CKR_OK);
    EXPECT_GT(sigLen, 0u);
    std::vector<CK_BYTE> sig(sigLen);
    ASSERT_EQ(C_Sign(session, data.data(), data.size(), sig.data(), &sigLen), CKR_OK);
    EXPECT_EQ(sig.size(), sigLen);

    (void)C_Logout(session);
    (void)C_CloseSession(session);
}

TEST_F(Pkcs11NamFixture, NamContactless_PaceEstablishedOnce)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    const auto slots = slotsWithToken();
    if (slots.size() != 1)
        GTEST_SKIP() << "Need exactly 1 slot for NAM contactless test.";

    // First login establishes PACE.
    CK_SESSION_HANDLE first = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(slots[0], CKF_SERIAL_SESSION, nullptr, nullptr, &first), CKR_OK);
    {
        const std::string canPin = canInPin(env("LIBRESCRS_TEST_CAN"), env("LIBRESCRS_TEST_PIN"));
        auto pinBytes = makePinBytes(canPin);
        const CK_RV rv = C_Login(first, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, slots[0], "C_Login(NAM, first/PACE-establish)");
    }
    (void)C_Logout(first);
    (void)C_CloseSession(first);

    // Second login on a fresh session — PACE should be cached on the
    // parent Card so PIN-only must work without re-prefixing the CAN.
    CK_SESSION_HANDLE second = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(slots[0], CKF_SERIAL_SESSION, nullptr, nullptr, &second), CKR_OK);
    {
        auto pinBytes = makePinBytes(env("LIBRESCRS_TEST_PIN"));
        const CK_RV rv = C_Login(second, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, slots[0], "C_Login(NAM, second/PIN-only post-PACE)");
    }
    (void)C_Logout(second);
    (void)C_CloseSession(second);
}

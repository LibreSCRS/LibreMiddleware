// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief CKA_ALWAYS_AUTHENTICATE through the PKCS#11 library: the
///        CKU_CONTEXT_SPECIFIC login, its one-shot PIN, and every place that
///        PIN must stop being usable. Driven against the configurable mock
///        card with the reader list injected, so no PC/SC is touched.

#include "MockPKCS11CardProvider.h"
#include "pkcs11_library.h"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::Pkcs11::Internal::Test {
namespace {

constexpr const char* kReader = "AlwaysAuth Reader 0";
constexpr std::string_view kPin = "1111";

class AlwaysAuthenticateLibrary : public ::testing::Test
{
protected:
    void bindCard(bool alwaysAuthenticate, std::size_t modulusLength = 0)
    {
        provider = std::make_shared<MockPKCS11CardProvider>();
        MockCardSpec spec;
        spec.slots.push_back(MockSlotSpec{
            .pinId = std::vector<std::uint8_t>{0x01},
            .pinLabel = "Sign",
            .correctPin = std::string{kPin},
            .kind = SlotKind::Sign,
            .alwaysAuthenticate = alwaysAuthenticate,
            .modulusLength = modulusLength,
        });
        provider->registerCard(kReader, std::move(spec));
        library = std::make_unique<PKCS11Library>([] { return std::vector<std::string>{kReader}; });
        library->registerProvider(provider);

        CK_ULONG count = 1;
        ASSERT_EQ(library->getSlotList(CK_TRUE, &slotId, &count), CKR_OK);
        ASSERT_EQ(count, 1U);
        slot = std::static_pointer_cast<MockConfigurableSlot>(library->findSlot(slotId));
        ASSERT_NE(slot, nullptr);
        card = std::static_pointer_cast<MockConfigurableCard>(slot->lockParentCard());
        ASSERT_NE(card, nullptr);
    }

    CK_SESSION_HANDLE openSession()
    {
        CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
        EXPECT_EQ(library->openSession(slotId, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);
        return session;
    }

    CK_RV login(CK_SESSION_HANDLE session, CK_USER_TYPE userType, std::string_view pin)
    {
        std::string bytes{pin};
        return library->login(session, userType, reinterpret_cast<CK_UTF8CHAR_PTR>(bytes.data()),
                              static_cast<CK_ULONG>(bytes.size()));
    }

    CK_OBJECT_HANDLE privateKey(CK_SESSION_HANDLE session)
    {
        CK_OBJECT_CLASS objectClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE byClass{CKA_CLASS, &objectClass, sizeof(objectClass)};
        EXPECT_EQ(library->findObjectsInit(session, &byClass, 1), CKR_OK);
        CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
        CK_ULONG count = 0;
        EXPECT_EQ(library->findObjects(session, &found, 1, &count), CKR_OK);
        EXPECT_EQ(library->findObjectsFinal(session), CKR_OK);
        EXPECT_EQ(count, 1U);
        return found;
    }

    /// Open a session (logging the USER in once per slot) and start a sign.
    CK_SESSION_HANDLE startSign(CK_MECHANISM_TYPE mechanismType = CKM_RSA_PKCS)
    {
        const auto session = openSession();
        if (!slot->isLoggedIn()) {
            EXPECT_EQ(login(session, CKU_USER, kPin), CKR_OK);
        }
        key = privateKey(session);
        CK_MECHANISM mechanism{mechanismType, nullptr, 0};
        EXPECT_EQ(library->signInit(session, &mechanism, key), CKR_OK);
        return session;
    }

    CK_RV sign(CK_SESSION_HANDLE session)
    {
        std::array<CK_BYTE, 20> data{};
        std::array<CK_BYTE, 256> signature{};
        CK_ULONG length = signature.size();
        return library->sign(session, data.data(), data.size(), signature.data(), &length);
    }

    std::shared_ptr<MockPKCS11CardProvider> provider;
    std::unique_ptr<PKCS11Library> library;
    CK_SLOT_ID slotId = 0;
    std::shared_ptr<MockConfigurableSlot> slot;
    std::shared_ptr<MockConfigurableCard> card;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
};

TEST_F(AlwaysAuthenticateLibrary, AttributeMirrorsTheCardFlag)
{
    for (const bool flagged : {true, false}) {
        bindCard(flagged);
        const auto session = openSession();
        ASSERT_EQ(login(session, CKU_USER, kPin), CKR_OK);
        const auto handle = privateKey(session);
        CK_BBOOL value = flagged ? CK_FALSE : CK_TRUE;
        CK_ATTRIBUTE attribute{CKA_ALWAYS_AUTHENTICATE, &value, sizeof(value)};
        ASSERT_EQ(library->getAttributeValue(session, handle, &attribute, 1), CKR_OK);
        EXPECT_EQ(value, flagged ? CK_TRUE : CK_FALSE);
    }
}

TEST_F(AlwaysAuthenticateLibrary, SignWithoutContextLoginIsRefusedAndEndsTheOperation)
{
    bindCard(true);
    const auto session = startSign();
    EXPECT_EQ(sign(session), CKR_USER_NOT_LOGGED_IN);
    EXPECT_EQ(sign(session), CKR_OPERATION_NOT_INITIALIZED)
        << "C_Sign ends the operation on every failure but a length query";
    EXPECT_TRUE(slot->signCalls().empty()) << "nothing may reach the card without this operation's PIN";
}

TEST_F(AlwaysAuthenticateLibrary, ContextLoginWithoutAnOperationIsOperationNotInitialized)
{
    bindCard(true);
    const auto session = openSession();
    ASSERT_EQ(login(session, CKU_USER, kPin), CKR_OK);
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OPERATION_NOT_INITIALIZED);
    EXPECT_EQ(slot->contextVerifies(), 0);
}

TEST_F(AlwaysAuthenticateLibrary, ContextLoginOnAnOrdinaryKeyIsRefusedAndLeavesTheOperation)
{
    bindCard(false);
    const auto session = startSign();
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OPERATION_NOT_INITIALIZED);
    EXPECT_EQ(slot->contextVerifies(), 0);
    ASSERT_EQ(sign(session), CKR_OK) << "the refused login must not have touched the operation";
    const auto calls = slot->signCalls();
    ASSERT_EQ(calls.size(), 1U);
    EXPECT_FALSE(calls[0].viaContextPin) << "an ordinary key keeps signing on the session login";
}

TEST_F(AlwaysAuthenticateLibrary, ArmedSignatureUsesTheContextPinNotTheCachedOne)
{
    bindCard(true);
    const auto session = startSign();
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    EXPECT_EQ(slot->contextVerifies(), 1) << "the context login VERIFYs, so a wrong PIN is reported at once";
    ASSERT_EQ(sign(session), CKR_OK);
    const auto calls = slot->signCalls();
    ASSERT_EQ(calls.size(), 1U);
    EXPECT_TRUE(calls[0].viaContextPin);
    EXPECT_EQ(calls[0].pin, kPin);
}

TEST_F(AlwaysAuthenticateLibrary, ArmingAuthorisesExactlyOneSignature)
{
    bindCard(true);
    const auto session = startSign();
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    ASSERT_EQ(sign(session), CKR_OK);
    CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(library->signInit(session, &mechanism, key), CKR_OK);
    EXPECT_EQ(sign(session), CKR_USER_NOT_LOGGED_IN);
    EXPECT_EQ(slot->signCalls().size(), 1U);
}

TEST_F(AlwaysAuthenticateLibrary, LengthQueryNeitherNeedsNorConsumesTheArming)
{
    bindCard(true);
    const auto session = startSign();
    std::array<CK_BYTE, 20> data{};
    CK_ULONG length = 0;
    EXPECT_EQ(library->sign(session, data.data(), data.size(), nullptr, &length), CKR_OK)
        << "sizing the buffer needs no PIN";
    EXPECT_EQ(length, 256U);
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    length = 0;
    EXPECT_EQ(library->sign(session, data.data(), data.size(), nullptr, &length), CKR_OK);
    EXPECT_EQ(sign(session), CKR_OK) << "the length query must not have spent the one-shot PIN";
}

TEST_F(AlwaysAuthenticateLibrary, WrongContextPinIsPinIncorrectAndKeepsTheOperation)
{
    bindCard(true);
    const auto session = startSign();
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "0000"), CKR_PIN_INCORRECT);
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    EXPECT_EQ(sign(session), CKR_OK);
}

TEST_F(AlwaysAuthenticateLibrary, LockedContextPinLogsTheUserOut)
{
    bindCard(true);
    const auto session = startSign();
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "0000"), CKR_PIN_INCORRECT);
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "0000"), CKR_PIN_INCORRECT);
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "0000"), CKR_PIN_LOCKED);
    CK_SESSION_INFO info{};
    ASSERT_EQ(library->getSessionInfo(session, &info), CKR_OK);
    EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
    EXPECT_EQ(sign(session), CKR_OPERATION_NOT_INITIALIZED) << "a blocked PIN ends the operation too";
}

TEST_F(AlwaysAuthenticateLibrary, RetryAfterResetReusesTheSameOneShotPin)
{
    bindCard(true);
    const auto session = startSign();
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    card->armSignFaultOnce();
    ASSERT_EQ(sign(session), CKR_OK);
    const auto calls = slot->signCalls();
    ASSERT_EQ(calls.size(), 2U) << "the first attempt faulted; the retry after the reset signed";
    for (const auto& call : calls) {
        EXPECT_TRUE(call.viaContextPin);
        EXPECT_EQ(call.pin, kPin);
    }
}

// The reset logs the slot out, so the sibling's sign is refused whether or not
// its PIN was erased; the erase itself is read through the test hook.
TEST_F(AlwaysAuthenticateLibrary, ResetFromASiblingSessionDisarmsEveryOperation)
{
    for (const bool multiPart : {false, true}) {
        SCOPED_TRACE(multiPart ? "reset inside C_SignFinal" : "reset inside C_Sign");
        bindCard(true);
        const auto first = startSign();
        ASSERT_EQ(login(first, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
        const auto second = startSign(multiPart ? CKM_SHA256_RSA_PKCS : CKM_RSA_PKCS);
        ASSERT_EQ(login(second, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
        ASSERT_TRUE(library->holdsContextPinForTest(first));
        card->armSignFaultOnce();
        if (multiPart) {
            std::array<CK_BYTE, 8> part{};
            ASSERT_EQ(library->signUpdate(second, part.data(), part.size()), CKR_OK);
            std::array<CK_BYTE, 256> signature{};
            CK_ULONG length = signature.size();
            ASSERT_EQ(library->signFinal(second, signature.data(), &length), CKR_OK); // faulted, reset, retried
        } else {
            ASSERT_EQ(sign(second), CKR_OK); // faulted, reset, retried
        }
        EXPECT_FALSE(library->holdsContextPinForTest(first)) << "the reset must erase every PIN armed before it";
        const auto before = slot->signCalls().size();
        EXPECT_EQ(sign(first), CKR_USER_NOT_LOGGED_IN) << "a PIN armed before the reset must not sign after it";
        EXPECT_EQ(slot->signCalls().size(), before);
    }
}

TEST_F(AlwaysAuthenticateLibrary, LogoutLeavesNoArmedPinUsable)
{
    bindCard(true);
    const auto session = startSign();
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    ASSERT_EQ(library->logout(session), CKR_OK);
    EXPECT_EQ(sign(session), CKR_OPERATION_NOT_INITIALIZED)
        << "C_Logout ends the sign operations of the token, the one-shot PIN with them";
    EXPECT_TRUE(slot->signCalls().empty());
}

TEST_F(AlwaysAuthenticateLibrary, MultiPartSignNeedsTheArmingToo)
{
    bindCard(true);
    std::array<CK_BYTE, 8> part{};
    const auto session = startSign(CKM_SHA256_RSA_PKCS);
    EXPECT_EQ(library->signUpdate(session, part.data(), part.size()), CKR_USER_NOT_LOGGED_IN);
    EXPECT_EQ(library->signUpdate(session, part.data(), part.size()), CKR_OPERATION_NOT_INITIALIZED);

    CK_MECHANISM mechanism{CKM_SHA256_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(library->signInit(session, &mechanism, key), CKR_OK);
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    ASSERT_EQ(library->signUpdate(session, part.data(), part.size()), CKR_OK);
    std::array<CK_BYTE, 256> signature{};
    CK_ULONG length = signature.size();
    ASSERT_EQ(library->signFinal(session, signature.data(), &length), CKR_OK);
    const auto calls = slot->signCalls();
    ASSERT_EQ(calls.size(), 1U);
    EXPECT_TRUE(calls[0].viaContextPin);
}

TEST_F(AlwaysAuthenticateLibrary, SignFinalWithoutArmingIsRefused)
{
    bindCard(true);
    const auto session = startSign(CKM_SHA256_RSA_PKCS);
    std::array<CK_BYTE, 256> signature{};
    CK_ULONG length = 0;
    EXPECT_EQ(library->signFinal(session, nullptr, &length), CKR_OK) << "sizing needs no PIN";
    length = signature.size();
    EXPECT_EQ(library->signFinal(session, signature.data(), &length), CKR_USER_NOT_LOGGED_IN);
    EXPECT_TRUE(slot->signCalls().empty());
}

// A malformed call reports what is malformed: the input-length check comes
// before the authorisation, so an over-long input to a per-operation key that
// was never armed is CKR_DATA_LEN_RANGE, as it is for an ordinary key.
TEST_F(AlwaysAuthenticateLibrary, OverLongInputIsDataLenRangeBeforeTheArmingIsChecked)
{
    bindCard(true, 256);
    const auto session = startSign();
    std::array<CK_BYTE, 256 - 11 + 1> data{};
    std::array<CK_BYTE, 256> signature{};
    CK_ULONG length = signature.size();
    EXPECT_EQ(library->sign(session, data.data(), data.size(), signature.data(), &length), CKR_DATA_LEN_RANGE);
    EXPECT_EQ(sign(session), CKR_OPERATION_NOT_INITIALIZED) << "the refusal ended the operation";
    EXPECT_TRUE(slot->signCalls().empty());
}

// A card that refuses the armed PIN inside the signing transaction (here its
// PIN changed after the context login) has spent one try on it. The library
// must not reset the card and present the same PIN again.
TEST_F(AlwaysAuthenticateLibrary, PinRefusedWhileSigningIsPinIncorrectAndNotPresentedAgain)
{
    bindCard(true);
    const auto session = startSign();
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    slot->changePinOnCard("2222", 0);
    EXPECT_EQ(sign(session), CKR_PIN_INCORRECT);
    EXPECT_EQ(slot->signCalls().size(), 1U) << "the refused PIN reached the card exactly once";
    EXPECT_EQ(sign(session), CKR_OPERATION_NOT_INITIALIZED);
    EXPECT_TRUE(slot->isLoggedIn()) << "a wrong PIN leaves the USER login alone";
}

TEST_F(AlwaysAuthenticateLibrary, PinBlockedWhileSigningIsPinLockedAndEndsEveryOperation)
{
    bindCard(true);
    const auto first = startSign();
    ASSERT_EQ(login(first, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    const auto sibling = startSign();
    slot->changePinOnCard("2222", 2);
    EXPECT_EQ(sign(first), CKR_PIN_LOCKED);
    EXPECT_EQ(slot->signCalls().size(), 1U);
    CK_SESSION_INFO info{};
    ASSERT_EQ(library->getSessionInfo(first, &info), CKR_OK);
    EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION) << "a blocked PIN logs the user out";
    EXPECT_EQ(sign(sibling), CKR_OPERATION_NOT_INITIALIZED) << "and ends the operations of every session";
}

TEST_F(AlwaysAuthenticateLibrary, PinRefusedInSignFinalIsNotPresentedAgain)
{
    bindCard(true);
    std::array<CK_BYTE, 8> part{};
    const auto session = startSign(CKM_SHA256_RSA_PKCS);
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK);
    ASSERT_EQ(library->signUpdate(session, part.data(), part.size()), CKR_OK);
    slot->changePinOnCard("2222", 0);
    std::array<CK_BYTE, 256> signature{};
    CK_ULONG length = signature.size();
    EXPECT_EQ(library->signFinal(session, signature.data(), &length), CKR_PIN_INCORRECT);
    EXPECT_EQ(slot->signCalls().size(), 1U);
}

TEST_F(AlwaysAuthenticateLibrary, LockedContextPinEndsASiblingSessionsOperation)
{
    bindCard(true);
    const auto session = startSign();
    const auto sibling = startSign();
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "0000"), CKR_PIN_INCORRECT);
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "0000"), CKR_PIN_INCORRECT);
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "0000"), CKR_PIN_LOCKED);
    EXPECT_EQ(sign(sibling), CKR_OPERATION_NOT_INITIALIZED);
    EXPECT_TRUE(slot->signCalls().empty());
}

// The USER login ends while the context login's VERIFY runs (a sibling
// session's C_Logout skips the busy session): the PIN is not armed, and the
// operation is ended like every other one on the token.
TEST_F(AlwaysAuthenticateLibrary, ContextLoginThatOutlivesTheUserLoginEndsTheOperation)
{
    bindCard(true);
    const auto session = startSign();
    slot->dropLoginDuringNextContextVerify();
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OPERATION_NOT_INITIALIZED);
    EXPECT_EQ(sign(session), CKR_OPERATION_NOT_INITIALIZED);
    EXPECT_TRUE(slot->signCalls().empty());
}

TEST_F(AlwaysAuthenticateLibrary, SoUserTypeIsStillInvalid)
{
    bindCard(true);
    const auto session = openSession();
    EXPECT_EQ(login(session, CKU_SO, kPin), CKR_USER_TYPE_INVALID);
}

// "CAN:PIN" is the session login's syntax, not an operation's. A value the
// token's PIN length cannot hold is refused before any VERIFY spends a try.
TEST_F(AlwaysAuthenticateLibrary, ContextPinOutsideTheTokenLengthNeverReachesTheCard)
{
    bindCard(true);
    const auto session = startSign();
    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "123456:1111111111"), CKR_PIN_LEN_RANGE);
    EXPECT_EQ(slot->contextVerifies(), 0);
}

// On a PACE card the session login takes "CAN:PIN"; a user who types that form
// into the per-operation prompt must not spend a PIN try on it.
TEST_F(AlwaysAuthenticateLibrary, PaceCardContextPinWithAColonIsPinInvalidBeforeAnyVerify)
{
    provider = std::make_shared<MockPKCS11CardProvider>();
    MockCardSpec spec;
    spec.needsPace = true;
    spec.correctCan = "123456";
    spec.slots.push_back(MockSlotSpec{
        .pinId = std::vector<std::uint8_t>{0x01},
        .pinLabel = "Sign",
        .correctPin = std::string{kPin},
        .kind = SlotKind::Sign,
        .alwaysAuthenticate = true,
    });
    provider->registerCard(kReader, std::move(spec));
    library = std::make_unique<PKCS11Library>([] { return std::vector<std::string>{kReader}; });
    library->registerProvider(provider);
    CK_ULONG count = 1;
    ASSERT_EQ(library->getSlotList(CK_TRUE, &slotId, &count), CKR_OK);
    slot = std::static_pointer_cast<MockConfigurableSlot>(library->findSlot(slotId));
    ASSERT_NE(slot, nullptr);

    const auto session = openSession();
    ASSERT_EQ(login(session, CKU_USER, "123456:1111"), CKR_OK);
    key = privateKey(session);
    CK_MECHANISM mechanism{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(library->signInit(session, &mechanism, key), CKR_OK);

    EXPECT_EQ(login(session, CKU_CONTEXT_SPECIFIC, "123456:1111"), CKR_PIN_INVALID);
    EXPECT_EQ(slot->contextVerifies(), 0);
    ASSERT_EQ(login(session, CKU_CONTEXT_SPECIFIC, kPin), CKR_OK) << "the operation survived the refusal";
    EXPECT_EQ(sign(session), CKR_OK);
}

} // namespace
} // namespace LibreSCRS::Pkcs11::Internal::Test

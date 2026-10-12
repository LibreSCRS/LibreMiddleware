// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif
#include "pkcs11/pkcs11.h"

#include <algorithm>
#include <array>
#include <iterator>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using namespace libresign;

class Pkcs11TokenTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        auto slot = libresign::test::findSoftHsmTestSlot(manager.acquire(softHsmPath));
        if (!slot)
            GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";
        testSlot = *slot;
    }
    const char* softHsmPath = nullptr;
    Pkcs11ModuleManager manager;
    unsigned long testSlot = 0;
};

TEST_F(Pkcs11TokenTest, OpenAndClose)
{
    ASSERT_NO_THROW({
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                          libresign::Pkcs11Token::TestSlotId{testSlot});
    });
}

namespace {

// A token-resident RSA pair each test owns. Its CKA_ID and label are its own,
// so the shared store's "test-key" signers never select it. The ID differs per
// test: ctest runs them in parallel processes on the one token, and a test that
// destroys "its" pair must not take a sibling's with it.
using AlwaysAuthKeyId = std::array<CK_BYTE, 2>;
constexpr AlwaysAuthKeyId kSignsPerContextLoginKeyId{0xA1, 0x1A};
constexpr AlwaysAuthKeyId kCombinedMechanismKeyId{0xA1, 0x1B};
constexpr AlwaysAuthKeyId kPinRefusedAtSignKeyId{0xA1, 0x1C};
constexpr AlwaysAuthKeyId kTransientLoginFailureKeyId{0xA1, 0x1D};
constexpr char kAlwaysAuthLabel[] = "always-auth-key";
constexpr char kSoftHsmUserPin[] = "1234";

class ProvisioningSession
{
public:
    ProvisioningSession(CK_FUNCTION_LIST* functions, CK_SLOT_ID slot, AlwaysAuthKeyId keyId)
        : funcs(functions), keyId(keyId)
    {
        rv = funcs->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &session);
        if (rv == CKR_OK)
            rv =
                funcs->C_Login(session, CKU_USER, reinterpret_cast<CK_UTF8CHAR_PTR>(const_cast<char*>(kSoftHsmUserPin)),
                               static_cast<CK_ULONG>(sizeof(kSoftHsmUserPin) - 1));
    }
    ~ProvisioningSession()
    {
        if (session != CK_INVALID_HANDLE) {
            (void)funcs->C_Logout(session);
            (void)funcs->C_CloseSession(session);
        }
    }
    ProvisioningSession(const ProvisioningSession&) = delete;
    ProvisioningSession& operator=(const ProvisioningSession&) = delete;

    void destroyAlwaysAuthObjects()
    {
        CK_ATTRIBUTE byId{CKA_ID, keyId.data(), keyId.size()};
        if (funcs->C_FindObjectsInit(session, &byId, 1) != CKR_OK)
            return;
        std::array<CK_OBJECT_HANDLE, 8> found{};
        CK_ULONG count = 0;
        (void)funcs->C_FindObjects(session, found.data(), found.size(), &count);
        (void)funcs->C_FindObjectsFinal(session);
        for (CK_ULONG i = 0; i < count; ++i)
            (void)funcs->C_DestroyObject(session, found[i]);
    }

    CK_RV generateAlwaysAuthKeyPair()
    {
        CK_MECHANISM mechanism{CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0};
        CK_BBOOL yes = CK_TRUE;
        CK_ULONG bits = 2048;
        CK_BYTE exponent[] = {0x01, 0x00, 0x01};
        auto* id = keyId.data();
        auto* label = const_cast<char*>(kAlwaysAuthLabel);
        const CK_ULONG labelLength = sizeof(kAlwaysAuthLabel) - 1;
        CK_ATTRIBUTE publicTemplate[] = {
            {CKA_TOKEN, &yes, sizeof(yes)},
            {CKA_VERIFY, &yes, sizeof(yes)},
            {CKA_MODULUS_BITS, &bits, sizeof(bits)},
            {CKA_PUBLIC_EXPONENT, exponent, sizeof(exponent)},
            {CKA_ID, id, keyId.size()},
            {CKA_LABEL, label, labelLength},
        };
        CK_ATTRIBUTE privateTemplate[] = {
            {CKA_TOKEN, &yes, sizeof(yes)},
            {CKA_PRIVATE, &yes, sizeof(yes)},
            {CKA_SENSITIVE, &yes, sizeof(yes)},
            {CKA_SIGN, &yes, sizeof(yes)},
            {CKA_ALWAYS_AUTHENTICATE, &yes, sizeof(yes)},
            {CKA_ID, id, keyId.size()},
            {CKA_LABEL, label, labelLength},
        };
        CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE privateKey = CK_INVALID_HANDLE;
        return funcs->C_GenerateKeyPair(session, &mechanism, publicTemplate, std::size(publicTemplate), privateTemplate,
                                        std::size(privateTemplate), &publicKey, &privateKey);
    }

    /// C_Verify with CKM_SHA256_RSA_PKCS under the test pair's public key:
    /// does @p signature sign @p message itself?
    CK_RV verifySha256RsaPkcs(std::span<const uint8_t> message, std::span<const uint8_t> signature)
    {
        CK_OBJECT_CLASS publicClass = CKO_PUBLIC_KEY;
        CK_ATTRIBUTE byIdAndClass[] = {
            {CKA_CLASS, &publicClass, sizeof(publicClass)},
            {CKA_ID, keyId.data(), keyId.size()},
        };
        CK_RV findRv = funcs->C_FindObjectsInit(session, byIdAndClass, std::size(byIdAndClass));
        if (findRv != CKR_OK)
            return findRv;
        CK_OBJECT_HANDLE publicKey = CK_INVALID_HANDLE;
        CK_ULONG count = 0;
        findRv = funcs->C_FindObjects(session, &publicKey, 1, &count);
        (void)funcs->C_FindObjectsFinal(session);
        if (findRv != CKR_OK)
            return findRv;
        if (count != 1)
            return CKR_KEY_HANDLE_INVALID;
        CK_MECHANISM mechanism{CKM_SHA256_RSA_PKCS, nullptr, 0};
        const CK_RV initRv = funcs->C_VerifyInit(session, &mechanism, publicKey);
        if (initRv != CKR_OK)
            return initRv;
        return funcs->C_Verify(session, const_cast<CK_BYTE*>(message.data()), static_cast<CK_ULONG>(message.size()),
                               const_cast<CK_BYTE*>(signature.data()), static_cast<CK_ULONG>(signature.size()));
    }

    CK_FUNCTION_LIST* funcs;
    AlwaysAuthKeyId keyId;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_RV rv = CKR_OK;
};

// A module that presents the context-specific PIN when C_Sign runs, as
// LibreSCRS's own module does, and refuses it there. Built over SoftHSM by
// swapping two entries of its function list for the guard's lifetime: C_Login
// counts the context logins, and C_Sign finishes SoftHSM's operation (a failed
// C_Sign ends it, PKCS#11 v2.40 section 5.2) and then answers
// CKR_PIN_INCORRECT. A length query passes through, as it needs no PIN.
class PinRefusedAtSign
{
public:
    explicit PinRefusedAtSign(CK_FUNCTION_LIST* functions)
        : funcs(functions), savedLogin(functions->C_Login), savedSign(functions->C_Sign)
    {
        realLogin = savedLogin;
        realSign = savedSign;
        contextLogins = 0;
        signCalls = 0;
        funcs->C_Login = &login;
        funcs->C_Sign = &sign;
    }
    ~PinRefusedAtSign()
    {
        funcs->C_Login = savedLogin;
        funcs->C_Sign = savedSign;
    }
    PinRefusedAtSign(const PinRefusedAtSign&) = delete;
    PinRefusedAtSign& operator=(const PinRefusedAtSign&) = delete;

    static inline int contextLogins = 0;
    static inline int signCalls = 0; ///< C_Sign calls that carried a buffer

private:
    using LoginFn = decltype(CK_FUNCTION_LIST::C_Login);
    using SignFn = decltype(CK_FUNCTION_LIST::C_Sign);

    static CK_RV login(CK_SESSION_HANDLE session, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pin, CK_ULONG pinLength)
    {
        if (userType == CKU_CONTEXT_SPECIFIC)
            ++contextLogins;
        return realLogin(session, userType, pin, pinLength);
    }
    static CK_RV sign(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLength, CK_BYTE_PTR signature,
                      CK_ULONG_PTR signatureLength)
    {
        if (signature == nullptr)
            return realSign(session, data, dataLength, signature, signatureLength);
        ++signCalls;
        (void)realSign(session, data, dataLength, signature, signatureLength);
        return CKR_PIN_INCORRECT;
    }

    static inline LoginFn realLogin = nullptr;
    static inline SignFn realSign = nullptr;
    CK_FUNCTION_LIST* funcs;
    LoginFn savedLogin;
    SignFn savedSign;
};

// A module whose context-specific C_Login fails once for a reason that is not a
// PIN verdict (a busy or failing device), then behaves.
class ContextLoginFailsOnce
{
public:
    explicit ContextLoginFailsOnce(CK_FUNCTION_LIST* functions)
        : funcs(functions), savedLogin(functions->C_Login), savedSign(functions->C_Sign),
          savedOpen(functions->C_OpenSession), savedClose(functions->C_CloseSession)
    {
        realLogin = savedLogin;
        realSign = savedSign;
        realOpen = savedOpen;
        realClose = savedClose;
        contextLogins = 0;
        signCalls = 0;
        failOpenSession = false;
        firstOpened = 0;
        closed.clear();
        funcs->C_Login = &login;
        funcs->C_Sign = &sign;
        funcs->C_OpenSession = &openSession;
        funcs->C_CloseSession = &closeSession;
    }
    ~ContextLoginFailsOnce()
    {
        funcs->C_Login = savedLogin;
        funcs->C_Sign = savedSign;
        funcs->C_OpenSession = savedOpen;
        funcs->C_CloseSession = savedClose;
    }
    ContextLoginFailsOnce(const ContextLoginFailsOnce&) = delete;
    ContextLoginFailsOnce& operator=(const ContextLoginFailsOnce&) = delete;

    static inline int contextLogins = 0;
    static inline int signCalls = 0;                     ///< every C_Sign, whichever the caller
    static inline bool failOpenSession = false;          ///< C_OpenSession answers CKR_DEVICE_ERROR while set
    static inline CK_SESSION_HANDLE firstOpened = 0;     ///< the session the token opened first
    static inline std::vector<CK_SESSION_HANDLE> closed; ///< every handle C_CloseSession received

private:
    using LoginFn = decltype(CK_FUNCTION_LIST::C_Login);
    using SignFn = decltype(CK_FUNCTION_LIST::C_Sign);
    using OpenFn = decltype(CK_FUNCTION_LIST::C_OpenSession);
    using CloseFn = decltype(CK_FUNCTION_LIST::C_CloseSession);

    static CK_RV openSession(CK_SLOT_ID slot, CK_FLAGS flags, CK_VOID_PTR application, CK_NOTIFY notify,
                             CK_SESSION_HANDLE_PTR handle)
    {
        if (failOpenSession)
            return CKR_DEVICE_ERROR;
        const CK_RV rv = realOpen(slot, flags, application, notify, handle);
        if (rv == CKR_OK && firstOpened == 0)
            firstOpened = *handle;
        return rv;
    }

    static CK_RV closeSession(CK_SESSION_HANDLE session)
    {
        closed.push_back(session);
        return realClose(session);
    }

    static CK_RV sign(CK_SESSION_HANDLE session, CK_BYTE_PTR data, CK_ULONG dataLength, CK_BYTE_PTR signature,
                      CK_ULONG_PTR signatureLength)
    {
        ++signCalls;
        return realSign(session, data, dataLength, signature, signatureLength);
    }

    static CK_RV login(CK_SESSION_HANDLE session, CK_USER_TYPE userType, CK_UTF8CHAR_PTR pin, CK_ULONG pinLength)
    {
        if (userType == CKU_CONTEXT_SPECIFIC && contextLogins++ == 0)
            return CKR_DEVICE_ERROR;
        return realLogin(session, userType, pin, pinLength);
    }

    static inline LoginFn realLogin = nullptr;
    static inline SignFn realSign = nullptr;
    static inline OpenFn realOpen = nullptr;
    static inline CloseFn realClose = nullptr;
    CK_FUNCTION_LIST* funcs;
    LoginFn savedLogin;
    SignFn savedSign;
    OpenFn savedOpen;
    CloseFn savedClose;
};

} // namespace

// A key the token publishes with CKA_ALWAYS_AUTHENTICATE wants its PIN again
// for every signature (PKCS#11 v2.40 section 4.9). The token logs in once and
// must then authorise each operation itself -- twice here, so a token that
// authorised only the first one is caught.
TEST_F(Pkcs11TokenTest, AlwaysAuthenticateKeySignsOncePerContextLogin)
{
    auto module = manager.acquire(softHsmPath);
    auto* funcs = static_cast<CK_FUNCTION_LIST*>(module.functionList());
    ASSERT_NE(funcs, nullptr);
    {
        ProvisioningSession provisioning(funcs, testSlot, kSignsPerContextLoginKeyId);
        ASSERT_EQ(provisioning.rv, CKR_OK);
        provisioning.destroyAlwaysAuthObjects(); // a crashed earlier run
        ASSERT_EQ(provisioning.generateAlwaysAuthKeyPair(), CKR_OK);
    } // logged out: the token logs in on a session of its own

    const std::vector<uint8_t> keyId(kSignsPerContextLoginKeyId.begin(), kSignsPerContextLoginKeyId.end());
    const std::vector<uint8_t> toBeSigned(51, 0x42);
    std::vector<uint8_t> first;
    std::vector<uint8_t> second;
    {
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin(kSoftHsmUserPin), "",
                          libresign::Pkcs11Token::TestSlotId{testSlot}, keyId);
        ASSERT_NO_THROW(first = token.sign(toBeSigned, "SHA256withRSA", {}));
        ASSERT_NO_THROW(second = token.sign(toBeSigned, "SHA256withRSA", {}));
    }
    EXPECT_EQ(first.size(), 256U);
    EXPECT_EQ(first, second) << "PKCS#1 v1.5 is deterministic: both signatures come from the same key";

    ProvisioningSession cleanup(funcs, testSlot, kSignsPerContextLoginKeyId);
    if (cleanup.rv == CKR_OK)
        cleanup.destroyAlwaysAuthObjects();
}

// With the raw bytes at hand the token first tries the combined
// CKM_SHA256_RSA_PKCS mechanism, and that operation needs its own context
// login too. The pre-built hash here is NOT the DigestInfo of the raw bytes,
// so a signature that verifies over the raw bytes can only come from the
// combined attempt -- never from the CKM_RSA_PKCS fallback.
TEST_F(Pkcs11TokenTest, AlwaysAuthenticateKeyAuthorisesTheCombinedMechanism)
{
    auto module = manager.acquire(softHsmPath);
    auto* funcs = static_cast<CK_FUNCTION_LIST*>(module.functionList());
    ASSERT_NE(funcs, nullptr);
    {
        ProvisioningSession provisioning(funcs, testSlot, kCombinedMechanismKeyId);
        ASSERT_EQ(provisioning.rv, CKR_OK);
        provisioning.destroyAlwaysAuthObjects(); // a crashed earlier run
        ASSERT_EQ(provisioning.generateAlwaysAuthKeyPair(), CKR_OK);
    }

    const std::vector<uint8_t> keyId(kCombinedMechanismKeyId.begin(), kCombinedMechanismKeyId.end());
    const std::vector<uint8_t> rawData{'s', 'i', 'g', 'n', ' ', 'm', 'e'};
    const std::vector<uint8_t> unrelatedHash(51, 0x42);
    std::vector<uint8_t> signature;
    {
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin(kSoftHsmUserPin), "",
                          libresign::Pkcs11Token::TestSlotId{testSlot}, keyId);
        ASSERT_NO_THROW(signature = token.sign(unrelatedHash, "SHA256withRSA", rawData));
    }

    ProvisioningSession verifier(funcs, testSlot, kCombinedMechanismKeyId);
    ASSERT_EQ(verifier.rv, CKR_OK);
    EXPECT_EQ(verifier.verifySha256RsaPkcs(rawData, signature), CKR_OK)
        << "the signature must cover the raw bytes, i.e. come from the combined mechanism";
    verifier.destroyAlwaysAuthObjects();
}

// A PIN the module refused at C_Sign is a refused per-operation PIN like one
// refused at C_Login: presenting it again -- through the CKM_RSA_PKCS fallback
// after the combined attempt, or in a later sign() -- would only spend another
// try of the card's retry counter.
TEST_F(Pkcs11TokenTest, AlwaysAuthenticatePinRefusedAtSignIsNeverPresentedAgain)
{
    auto module = manager.acquire(softHsmPath);
    auto* funcs = static_cast<CK_FUNCTION_LIST*>(module.functionList());
    ASSERT_NE(funcs, nullptr);
    {
        ProvisioningSession provisioning(funcs, testSlot, kPinRefusedAtSignKeyId);
        ASSERT_EQ(provisioning.rv, CKR_OK);
        provisioning.destroyAlwaysAuthObjects(); // a crashed earlier run
        ASSERT_EQ(provisioning.generateAlwaysAuthKeyPair(), CKR_OK);
    }

    const std::vector<uint8_t> keyId(kPinRefusedAtSignKeyId.begin(), kPinRefusedAtSignKeyId.end());
    const std::vector<uint8_t> hash(51, 0x42);
    const std::vector<uint8_t> rawData{'s', 'i', 'g', 'n', ' ', 'm', 'e'};
    for (const bool combined : {true, false}) {
        SCOPED_TRACE(combined ? "combined mechanism first" : "CKM_RSA_PKCS only");
        const std::span<const uint8_t> raw = combined ? std::span<const uint8_t>{rawData} : std::span<const uint8_t>{};
        PinRefusedAtSign refusing(funcs);
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin(kSoftHsmUserPin), "",
                          libresign::Pkcs11Token::TestSlotId{testSlot}, keyId);

        EXPECT_THROW((void)token.sign(hash, "SHA256withRSA", raw), std::exception);
        EXPECT_EQ(PinRefusedAtSign::contextLogins, 1) << "the refused PIN was presented again in the same sign()";
        EXPECT_EQ(PinRefusedAtSign::signCalls, 1);

        EXPECT_THROW((void)token.sign(hash, "SHA256withRSA", raw), std::exception);
        EXPECT_EQ(PinRefusedAtSign::contextLogins, 1) << "a later sign() presented the refused PIN again";
        EXPECT_EQ(PinRefusedAtSign::signCalls, 1);
    }

    ProvisioningSession cleanup(funcs, testSlot, kPinRefusedAtSignKeyId);
    if (cleanup.rv == CKR_OK)
        cleanup.destroyAlwaysAuthObjects();
}

// Only a PIN verdict from the context login is remembered as a refusal. A
// device error says nothing about the PIN: the next sign() must still try.
TEST_F(Pkcs11TokenTest, AlwaysAuthenticateTransientContextLoginFailureIsNotARefusedPin)
{
    auto module = manager.acquire(softHsmPath);
    auto* funcs = static_cast<CK_FUNCTION_LIST*>(module.functionList());
    ASSERT_NE(funcs, nullptr);
    {
        ProvisioningSession provisioning(funcs, testSlot, kTransientLoginFailureKeyId);
        ASSERT_EQ(provisioning.rv, CKR_OK);
        provisioning.destroyAlwaysAuthObjects(); // a crashed earlier run
        ASSERT_EQ(provisioning.generateAlwaysAuthKeyPair(), CKR_OK);
    }

    const std::vector<uint8_t> keyId(kTransientLoginFailureKeyId.begin(), kTransientLoginFailureKeyId.end());
    const std::vector<uint8_t> hash(51, 0x42);
    {
        ContextLoginFailsOnce failing(funcs);
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin(kSoftHsmUserPin), "",
                          libresign::Pkcs11Token::TestSlotId{testSlot}, keyId);

        EXPECT_THROW((void)token.sign(hash, "SHA256withRSA", {}), std::exception);
        // The cleanup must end the half-started operation without sending anything
        // to the card: no C_Sign, whatever the module would have answered.
        EXPECT_EQ(ContextLoginFailsOnce::signCalls, 0) << "the cleanup after a failed context login issued C_Sign";
        // Closing the old session is what ends its active operation.
        EXPECT_EQ(std::count(ContextLoginFailsOnce::closed.begin(), ContextLoginFailsOnce::closed.end(),
                             ContextLoginFailsOnce::firstOpened),
                  1)
            << "the session holding the half-started operation was not closed exactly once";
        std::vector<uint8_t> signature;
        EXPECT_NO_THROW(signature = token.sign(hash, "SHA256withRSA", {}))
            << "a device error at the context login was remembered as a refused PIN, or left the operation active";
        EXPECT_EQ(ContextLoginFailsOnce::signCalls, 2) << "the second sign() is one length query plus one signature";
        EXPECT_EQ(signature.size(), 256U);
        EXPECT_EQ(ContextLoginFailsOnce::contextLogins, 2);
    }

    ProvisioningSession cleanup(funcs, testSlot, kTransientLoginFailureKeyId);
    if (cleanup.rv == CKR_OK)
        cleanup.destroyAlwaysAuthObjects();
}

// If the replacement session cannot be opened, the old one still holds the
// half-started operation: the token must refuse every later sign() with its own
// error rather than let the module answer CKR_OPERATION_ACTIVE, and must send
// nothing to the card.
TEST_F(Pkcs11TokenTest, AlwaysAuthenticateRefusesSigningWhenTheSessionCannotBeReplaced)
{
    auto module = manager.acquire(softHsmPath);
    auto* funcs = static_cast<CK_FUNCTION_LIST*>(module.functionList());
    ASSERT_NE(funcs, nullptr);
    {
        ProvisioningSession provisioning(funcs, testSlot, kTransientLoginFailureKeyId);
        ASSERT_EQ(provisioning.rv, CKR_OK);
        provisioning.destroyAlwaysAuthObjects(); // a crashed earlier run
        ASSERT_EQ(provisioning.generateAlwaysAuthKeyPair(), CKR_OK);
    }

    const std::vector<uint8_t> keyId(kTransientLoginFailureKeyId.begin(), kTransientLoginFailureKeyId.end());
    const std::vector<uint8_t> hash(51, 0x42);
    {
        ContextLoginFailsOnce failing(funcs);
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin(kSoftHsmUserPin), "",
                          libresign::Pkcs11Token::TestSlotId{testSlot}, keyId);
        ContextLoginFailsOnce::failOpenSession = true;

        EXPECT_THROW((void)token.sign(hash, "SHA256withRSA", {}), std::exception);
        EXPECT_TRUE(ContextLoginFailsOnce::closed.empty()) << "the old session was closed without a replacement";
        try {
            (void)token.sign(hash, "SHA256withRSA", {});
            ADD_FAILURE() << "sign() proceeded on a token whose session could not be replaced";
        } catch (const std::exception& e) {
            EXPECT_NE(std::string(e.what()).find("could not be replaced"), std::string::npos) << e.what();
        }
        EXPECT_EQ(ContextLoginFailsOnce::signCalls, 0);
        EXPECT_EQ(ContextLoginFailsOnce::contextLogins, 1) << "the refused token tried the PIN again";
        ContextLoginFailsOnce::failOpenSession = false;
    }

    ProvisioningSession cleanup(funcs, testSlot, kTransientLoginFailureKeyId);
    if (cleanup.rv == CKR_OK)
        cleanup.destroyAlwaysAuthObjects();
}

// The session login of a PACE card takes "CAN:PIN"; the per-operation login
// takes the PIN alone -- the module's own split (at the first ':'), so a token
// built from the login credential never VERIFYs the CAN as a PIN. No SoftHSM.
TEST(Pkcs11TokenOperationPin, TakesThePinPartOfACanPinCredential)
{
    const auto bytes = [](std::string_view s) { return std::vector<uint8_t>(s.begin(), s.end()); };
    const auto asString = [](std::span<const uint8_t> s) { return std::string(s.begin(), s.end()); };

    const auto plain = bytes("1234");
    EXPECT_EQ(asString(libresign::detail::operationPinOf(plain)), "1234");
    const auto canPin = bytes("123456:1234");
    EXPECT_EQ(asString(libresign::detail::operationPinOf(canPin)), "1234");
    const auto twoColons = bytes("123456:12:34");
    EXPECT_EQ(asString(libresign::detail::operationPinOf(twoColons)), "12:34") << "split at the FIRST ':' only";
    const auto empty = bytes("");
    EXPECT_TRUE(libresign::detail::operationPinOf(empty).empty());
}

TEST(Pkcs11TokenStandalone, FailsWithInvalidModule)
{
    Pkcs11ModuleManager manager;
    ASSERT_THROW({ (void)manager.acquire("/nonexistent.so"); }, std::runtime_error);
}

#endif

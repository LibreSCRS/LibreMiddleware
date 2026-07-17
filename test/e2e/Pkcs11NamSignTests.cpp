// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Real-card E2E tests for the NAM contactless card. NAM exposes a single
// PKCS#11 slot, requires PACE on every transaction, and its PIN guards
// both Auth and Sign keys (one PIN, two keys).

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

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdio>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using LibreSCRS::Tests::E2E::env;

namespace {

// Trim a space/NUL-padded PKCS#11 fixed field (CK_TOKEN_INFO.label / .model)
// to a plain std::string.
std::string trimmedField(const CK_UTF8CHAR* field, size_t n)
{
    std::string s(reinterpret_cast<const char*>(field), n);
    const auto end = s.find_last_not_of(std::string("\0 ", 2));
    return end == std::string::npos ? std::string{} : s.substr(0, end + 1);
}

bool icontains(std::string hay, std::string needle)
{
    auto lower = [](std::string& x) {
        std::transform(x.begin(), x.end(), x.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    };
    lower(hay);
    lower(needle);
    return hay.find(needle) != std::string::npos;
}

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

    // Find the NAM contactless slot among ALL present slots. The product
    // enumerates one slot per inserted card, so a NAM test must pick the NAM
    // card's slot rather than assume it is the only card present (mirrors
    // Pkcs11PksSignTests::findPksSlot). NAM is identified pre-login by its
    // PACE-CAN placeholder token label "PACE access required"; the PKS sibling
    // slot surfaces "Serbian CardEdge". The CK_SLOT_ID is stable across the
    // post-login self-transform, so the same id is reused for login + sign.
    std::optional<CK_SLOT_ID> findNamSlot()
    {
        for (CK_SLOT_ID slot : slotsWithToken()) {
            CK_TOKEN_INFO info{};
            if (C_GetTokenInfo(slot, &info) != CKR_OK)
                continue;
            if (icontains(trimmedField(info.label, sizeof(info.label)), "pace access required"))
                return slot;
        }
        return std::nullopt;
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

// Reads an arbitrary byte-valued attribute (CKA_ID / CKA_VALUE / CKA_LABEL)
// off an object via the two-call C_GetAttributeValue size-then-fetch idiom.
// Returns empty on any failure or empty/unavailable attribute.
std::vector<uint8_t> readAttr(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj, CK_ATTRIBUTE_TYPE type)
{
    CK_ATTRIBUTE a{type, nullptr, 0};
    if (C_GetAttributeValue(session, obj, &a, 1) != CKR_OK || a.ulValueLen == 0 ||
        a.ulValueLen == static_cast<CK_ULONG>(-1))
        return {};
    std::vector<uint8_t> v(a.ulValueLen);
    a.pValue = v.data();
    if (C_GetAttributeValue(session, obj, &a, 1) != CKR_OK)
        return {};
    return v;
}

std::string hexOf(const std::vector<uint8_t>& v)
{
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(v.size() * 2);
    for (uint8_t b : v) {
        s.push_back(d[b >> 4]);
        s.push_back(d[b & 0x0F]);
    }
    return s;
}

} // namespace

// The NAM slot must be discoverable EVEN WHEN OTHER CARDS ARE PRESENT — the
// product enumerates one slot per inserted card (e.g. PKS + NAM = 2 slots), so
// this test finds the NAM slot among all of them rather than assuming NAM is
// alone. Regression guard for the prior single-card assumption that skipped
// the whole NAM suite whenever a second card was inserted.
TEST_F(Pkcs11NamFixture, NamContactless_SlotDiscoverableAmongMultipleCards)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    if (slotsWithToken().empty())
        GTEST_SKIP() << "No PKCS#11 slots with tokens present (no NAM card on NFC reader?)";

    const auto namSlot = findNamSlot();
    if (!namSlot)
        GTEST_SKIP() << "No NAM PACE-placeholder slot among the present tokens — NAM card not inserted?";

    SUCCEED() << "NAM slot discovered among " << slotsWithToken().size() << " present slot(s): " << *namSlot;
}

// Pre-login the placeholder slot must surface as CKF_LOGIN_REQUIRED so
// PKCS#11 clients (libresign, p11-kit, Kleopatra) can discover the card
// before the CAN is supplied. Regression guard for the PACE-placeholder-slot
// fix: prior behaviour returned an empty slot list and broke sign.
TEST_F(Pkcs11NamFixture, NamContactless_PlaceholderSlot_LoginRequiredFlag)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    const auto namSlot = findNamSlot();
    if (!namSlot)
        GTEST_SKIP() << "No NAM PACE-placeholder slot present (NAM card not inserted?).";

    CK_TOKEN_INFO info{};
    ASSERT_EQ(C_GetTokenInfo(*namSlot, &info), CKR_OK);

    // CKF_LOGIN_REQUIRED = 0x00000004UL per PKCS#11 v2.40.
    EXPECT_NE(info.flags & 0x00000004UL, 0u) << "Placeholder token must publish CKF_LOGIN_REQUIRED";
}

/// Real-card placeholder-slot self-transform smoke. With the
/// PACE-placeholder-slot design, the slot enumerated pre-login exposes
/// CKF_LOGIN_REQUIRED; after C_Login(CAN[:PIN]) the same slot publishes
/// the card's real keys / certs and is signable through the same
/// CK_SLOT_ID (no slot-vector swap).
TEST_F(Pkcs11NamFixture, NamContactless_LoginAndSign_Succeeds)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");

    const auto namSlot = findNamSlot();
    if (!namSlot)
        GTEST_SKIP() << "No NAM PACE-placeholder slot present (NAM card not inserted?).";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(*namSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    // NAM CL is pure-PACE: a bare CAN authenticates the slot. The
    // CAN-in-PIN form ("CAN:PIN") is supported for PACE + card-PIN
    // combos; when LIBRESCRS_TEST_PIN is set we exercise that path too.
    const std::string pinEnv = env("LIBRESCRS_TEST_PIN");
    const std::string canPin = pinEnv.empty() ? env("LIBRESCRS_TEST_CAN") : canInPin(env("LIBRESCRS_TEST_CAN"), pinEnv);
    auto pinBytes = makePinBytes(canPin);
    const CK_RV rv = C_Login(session, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
    LOGIN_OR_ABORT(rv, *namSlot, "C_Login(CAN-in-PIN, NAM)");

    // Post-login enumeration must surface at least one certificate.
    // Empty-objects guards in the slot self-transform return DeviceError
    // when the post-resume profile yields zero keys AND zero certs, so a
    // successful C_Login means at least one of each should be findable.
    {
        CK_OBJECT_CLASS certKlass = CKO_CERTIFICATE;
        std::array<CK_ATTRIBUTE, 1> certTmpl{{{CKA_CLASS, &certKlass, sizeof(certKlass)}}};
        ASSERT_EQ(C_FindObjectsInit(session, certTmpl.data(), certTmpl.size()), CKR_OK);
        CK_OBJECT_HANDLE cert = CK_INVALID_HANDLE;
        CK_ULONG certFound = 0;
        ASSERT_EQ(C_FindObjects(session, &cert, 1, &certFound), CKR_OK);
        ASSERT_EQ(C_FindObjectsFinal(session), CKR_OK);
        ASSERT_GT(certFound, 0u) << "NAM token should expose at least one certificate post-login.";
    }

    CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    std::array<CK_ATTRIBUTE, 2> tmpl{{{CKA_CLASS, &klass, sizeof(klass)}, {CKA_KEY_TYPE, &keyType, sizeof(keyType)}}};
    ASSERT_EQ(C_FindObjectsInit(session, tmpl.data(), tmpl.size()), CKR_OK);
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG found = 0;
    ASSERT_EQ(C_FindObjects(session, &key, 1, &found), CKR_OK);
    ASSERT_EQ(C_FindObjectsFinal(session), CKR_OK);
    ASSERT_GT(found, 0u) << "NAM token should expose at least one private RSA key.";

    // NAM is a hash-on-card IAS-ECC SSCD: its PSO COMPUTE machinery
    // insists on hashing the input itself and rejects a pre-built
    // DigestInfo (CKM_RSA_PKCS) with SW 6A80 / 6982. The only working
    // contract is the combined CKM_SHA256_RSA_PKCS mechanism over the
    // raw message — exactly the path LibreCelik's libresign Native
    // backend takes (lib/libresign/src/native/pkcs11_token.cpp). A
    // cryptographic round-trip check of this path lives in
    // NamContactless_LcFaithfulSign_VerifiesAgainstCert; this smoke just
    // asserts the post-login slot self-transform is signable.
    CK_MECHANISM mech{CKM_SHA256_RSA_PKCS, nullptr, 0};
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

    const auto namSlot = findNamSlot();
    if (!namSlot)
        GTEST_SKIP() << "No NAM PACE-placeholder slot present (NAM card not inserted?).";

    // First login establishes PACE.
    CK_SESSION_HANDLE first = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(*namSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &first), CKR_OK);
    {
        const std::string canPin = canInPin(env("LIBRESCRS_TEST_CAN"), env("LIBRESCRS_TEST_PIN"));
        auto pinBytes = makePinBytes(canPin);
        const CK_RV rv = C_Login(first, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, *namSlot, "C_Login(NAM, first/PACE-establish)");
    }
    (void)C_Logout(first);
    (void)C_CloseSession(first);

    // Second login on a fresh session — PACE should be cached on the
    // parent Card so PIN-only must work without re-prefixing the CAN.
    CK_SESSION_HANDLE second = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(*namSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &second), CKR_OK);
    {
        auto pinBytes = makePinBytes(env("LIBRESCRS_TEST_PIN"));
        const CK_RV rv = C_Login(second, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, *namSlot, "C_Login(NAM, second/PIN-only post-PACE)");
    }
    (void)C_Logout(second);
    (void)C_CloseSession(second);
}

// Ground-truth NAM sign that mirrors how LibreCelik actually signs AND
// cryptographically verifies the result.
//
// The legacy LoginAndSign_Succeeds test signs 32 raw bytes through
// CKM_RSA_PKCS and never checks the signature — both unfaithful to
// LibreCelik and blind to a silently-wrong (re-hashed) signature.
// LibreCelik's libresign Native backend
// (lib/libresign/src/native/pkcs11_token.cpp::Pkcs11Token::sign) signs
// through the combined CKM_SHA256_RSA_PKCS mechanism over the raw
// document bytes; the PKCS#11 library turns that into
// buildDigestInfo()+signWithDigestInfo() and the pkcs15 card layer maps
// it to SignScheme::RsaSha256Pkcs1, reaching the IAS-ECC 0x42 / 0x28
// attempts that the RsaPkcs1 path never tries.
//
// This test reproduces that exact boundary for EVERY RSA key on the
// card and verifies each signature against the matching certificate's
// public key with EVP_PKEY_verify (RSA PKCS#1 v1.5 / SHA-256). A card
// SW 9000 whose signature does not validate (the IAS-ECC re-hash trap)
// fails loudly here instead of passing as the legacy test would.
TEST_F(Pkcs11NamFixture, NamContactless_LcFaithfulSign_VerifiesAgainstCert)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_CAN");
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");

    const auto namSlot = findNamSlot();
    if (!namSlot)
        GTEST_SKIP() << "No NAM PACE-placeholder slot present (NAM card not inserted?).";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(*namSlot, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    {
        const std::string canPin = canInPin(env("LIBRESCRS_TEST_CAN"), env("LIBRESCRS_TEST_PIN"));
        auto pinBytes = makePinBytes(canPin);
        const CK_RV rv = C_Login(session, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, *namSlot, "C_Login(CAN-in-PIN, NAM faithful sign)");
    }

    // Map every certificate by its CKA_ID (id, DER).
    std::vector<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> certs;
    {
        CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
        std::array<CK_ATTRIBUTE, 1> tmpl{{{CKA_CLASS, &klass, sizeof(klass)}}};
        ASSERT_EQ(C_FindObjectsInit(session, tmpl.data(), tmpl.size()), CKR_OK);
        while (true) {
            CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
            CK_ULONG n = 0;
            ASSERT_EQ(C_FindObjects(session, &h, 1, &n), CKR_OK);
            if (n == 0)
                break;
            certs.emplace_back(readAttr(session, h, CKA_ID), readAttr(session, h, CKA_VALUE));
        }
        ASSERT_EQ(C_FindObjectsFinal(session), CKR_OK);
    }
    ASSERT_FALSE(certs.empty()) << "NAM exposed no certificates post-login.";

    // Collect every RSA private key with its id, label and CKA_SIGN flag.
    struct KeyEntry
    {
        CK_OBJECT_HANDLE handle;
        std::vector<uint8_t> id;
        std::string label;
        bool canSign;
    };
    std::vector<KeyEntry> keys;
    {
        CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE kt = CKK_RSA;
        std::array<CK_ATTRIBUTE, 2> tmpl{{{CKA_CLASS, &klass, sizeof(klass)}, {CKA_KEY_TYPE, &kt, sizeof(kt)}}};
        ASSERT_EQ(C_FindObjectsInit(session, tmpl.data(), tmpl.size()), CKR_OK);
        while (true) {
            CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
            CK_ULONG n = 0;
            ASSERT_EQ(C_FindObjects(session, &h, 1, &n), CKR_OK);
            if (n == 0)
                break;
            auto id = readAttr(session, h, CKA_ID);
            auto lbl = readAttr(session, h, CKA_LABEL);
            CK_BBOOL sign = CK_FALSE;
            CK_ATTRIBUTE sa{CKA_SIGN, &sign, sizeof(sign)};
            (void)C_GetAttributeValue(session, h, &sa, 1);
            keys.push_back({h, std::move(id), std::string(lbl.begin(), lbl.end()), sign == CK_TRUE});
        }
        ASSERT_EQ(C_FindObjectsFinal(session), CKR_OK);
    }
    ASSERT_FALSE(keys.empty()) << "NAM exposed no RSA private keys post-login.";

    const std::vector<uint8_t> payload = {'l', 'i', 'b', 'r', 'e', 's', 'c', 'r',
                                          's', '-', 'n', 'a', 'm', '-', 'g', 't'};
    unsigned char digest[32];
    {
        unsigned int n = 0;
        ASSERT_EQ(EVP_Digest(payload.data(), payload.size(), digest, &n, EVP_sha256(), nullptr), 1);
        ASSERT_EQ(n, 32u);
    }

    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    int verifiedCount = 0;
    for (const auto& k : keys) {
        // Faithful LibreCelik path: combined hash+sign over the raw payload.
        CK_MECHANISM mech{CKM_SHA256_RSA_PKCS, nullptr, 0};
        CK_RV signRv = C_SignInit(session, &mech, k.handle);
        CK_ULONG sigLen = 0;
        std::vector<CK_BYTE> sig;
        if (signRv == CKR_OK)
            signRv = C_Sign(session, const_cast<CK_BYTE*>(payload.data()), static_cast<CK_ULONG>(payload.size()),
                            nullptr, &sigLen);
        if (signRv == CKR_OK && sigLen > 0) {
            sig.resize(sigLen);
            signRv = C_Sign(session, const_cast<CK_BYTE*>(payload.data()), static_cast<CK_ULONG>(payload.size()),
                            sig.data(), &sigLen);
            if (signRv == CKR_OK)
                sig.resize(sigLen);
        }

        // Find the certificate sharing this key's CKA_ID.
        const std::vector<uint8_t>* certDer = nullptr;
        for (const auto& c : certs) {
            if (!k.id.empty() && c.first == k.id) {
                certDer = &c.second;
                break;
            }
        }

        bool verified = false;
        if (signRv == CKR_OK && !sig.empty() && certDer != nullptr && !certDer->empty()) {
            const unsigned char* p = certDer->data();
            X509Ptr x{d2i_X509(nullptr, &p, static_cast<long>(certDer->size())), &X509_free};
            if (x) {
                EvpPkeyPtr pkey{X509_get_pubkey(x.get()), &EVP_PKEY_free};
                if (pkey) {
                    EvpPkeyCtxPtr vctx{EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free};
                    if (vctx && EVP_PKEY_verify_init(vctx.get()) == 1 &&
                        EVP_PKEY_CTX_set_rsa_padding(vctx.get(), RSA_PKCS1_PADDING) == 1 &&
                        EVP_PKEY_CTX_set_signature_md(vctx.get(), EVP_sha256()) == 1) {
                        verified = EVP_PKEY_verify(vctx.get(), sig.data(), sig.size(), digest, 32) == 1;
                    }
                }
            }
        }
        if (verified)
            ++verifiedCount;

        std::fprintf(stderr, "[NAM-GT] key='%s' id=%s CKA_SIGN=%d cert=%s signRv=0x%lX sigLen=%zu verified=%s\n",
                     k.label.c_str(), hexOf(k.id).c_str(), k.canSign ? 1 : 0, certDer ? "yes" : "no",
                     static_cast<unsigned long>(signRv), sig.size(), verified ? "YES" : "NO");
    }

    (void)C_Logout(session);
    (void)C_CloseSession(session);

    EXPECT_GE(verifiedCount, 1)
        << "No NAM RSA key produced a cryptographically valid SHA256-RSA-PKCS signature via the "
           "LibreCelik-faithful path. Either the sign key is unreachable through PKCS15Card::sign, or "
           "the card's SW 9000 is a silently-wrong (re-hashed) signature.";
}

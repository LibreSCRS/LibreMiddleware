// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Real-card E2E tests for the Privredna komora Srbije (PKS) Serbian
// Chamber of Commerce card. PKS is a single-PIN contact card driven
// through upstream OpenSC (card-srbeid + pkcs15-srbeid) — there is no
// PACE/CAN involved, just plain AID select + VERIFY + COMPUTE_SIGNATURE.
//
// Detection is by token-label match rather than ATR whitelist, because
// the synthesized PKCS#11 token label ("Serbian CardEdge") is stable
// across ATR variants in the srbeid driver.
//
// Every test follows the project-wide PIN-guard discipline:
//   * SKIP_IF_PIN_FAILED() at the top so a single PIN miss latches the
//     suite into skip-mode and we cannot exhaust the 3-attempt counter.
//   * REQUIRE_ENV("LIBRESCRS_TEST_PIN") so the suite is safe to run on
//     CI / dev workstations without a card present.
//   * LOGIN_OR_ABORT(...) around C_Login so any non-CKR_OK trips
//     g_pinFailed before the next PIN-using test runs.

#include "pin_guard.h"

// Platform-specific PKCS#11 macros must be defined BEFORE pkcs11.h is
// included (the header is OASIS-portable and asks consumers to define
// CK_PTR / CK_DECLARE_FUNCTION / CK_DECLARE_FUNCTION_POINTER /
// CK_CALLBACK_FUNCTION / NULL_PTR themselves). Mirrors the preamble
// in Pkcs11NamSignTests.cpp / Pkcs11Suite1MultiPinTests.cpp.
#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR nullptr
#endif

#include <pkcs11/pkcs11.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

using LibreSCRS::Tests::E2E::env;

namespace {

// ---------------------------------------------------------------------------
// Fixture — initialises librescrs-pkcs11.so once per test, hunts a PKS
// token by label, and tears down via C_Finalize. All tests skip cleanly
// when no PKS is present so the suite is safe to run on CI / a dev box
// with an unrelated card inserted.
// ---------------------------------------------------------------------------
class Pkcs11PksFixture : public ::testing::Test
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
        // Best-effort: a test that already finalised explicitly will
        // get CKR_CRYPTOKI_NOT_INITIALIZED here, which we accept.
        (void)C_Finalize(nullptr);
    }

    static std::vector<CK_SLOT_ID> slotsWithToken()
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

    static std::string trimmedField(const CK_UTF8CHAR* field, size_t len)
    {
        std::string s(reinterpret_cast<const char*>(field), len);
        // PKCS#11 string fields are space-padded; trim trailing spaces.
        while (!s.empty() && s.back() == ' ')
            s.pop_back();
        return s;
    }

    // Lowercase, ASCII-only substring check.
    static bool icontains(const std::string& hay, const std::string& needle)
    {
        std::string h = hay;
        std::string n = needle;
        for (auto& c : h)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (auto& c : n)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        return h.find(n) != std::string::npos;
    }

    // Returns the first slot whose token surfaces as a PKS card per the
    // synthesized label/model the OpenSC srbeid driver emits. Looks for
    // "Serbian CardEdge" in the token label AND "OpenSC" in the model
    // string (the upstream driver advertises model "PKCS#15 emulated"
    // prefixed with "OpenSC" by the framework — we match conservatively
    // on the "OpenSC" substring to ride out minor wording drift).
    static std::optional<CK_SLOT_ID> findPksSlot()
    {
        const auto slots = slotsWithToken();
        for (CK_SLOT_ID slot : slots) {
            CK_TOKEN_INFO info{};
            if (C_GetTokenInfo(slot, &info) != CKR_OK)
                continue;
            const std::string label = trimmedField(info.label, sizeof(info.label));
            const std::string model = trimmedField(info.model, sizeof(info.model));
            if (icontains(label, "serbian cardedge") && icontains(model, "opensc"))
                return slot;
        }
        return std::nullopt;
    }
};

std::vector<CK_UTF8CHAR> makePinBytes(const std::string& s)
{
    return std::vector<CK_UTF8CHAR>(s.begin(), s.end());
}

// Locates the first certificate object on `session` whose label contains
// any of the supplied needles (case-insensitive). Returns CK_INVALID_HANDLE
// when none match. No PIN required — certs are public objects.
CK_OBJECT_HANDLE findCertByLabelSubstring(CK_SESSION_HANDLE session, std::initializer_list<const char*> needles)
{
    CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
    std::array<CK_ATTRIBUTE, 1> tmpl{{{CKA_CLASS, &klass, sizeof(klass)}}};
    if (C_FindObjectsInit(session, tmpl.data(), tmpl.size()) != CKR_OK)
        return CK_INVALID_HANDLE;

    CK_OBJECT_HANDLE match = CK_INVALID_HANDLE;
    while (true) {
        CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;
        CK_ULONG found = 0;
        if (C_FindObjects(session, &handle, 1, &found) != CKR_OK || found == 0)
            break;

        CK_ATTRIBUTE labelAttr{CKA_LABEL, nullptr, 0};
        if (C_GetAttributeValue(session, handle, &labelAttr, 1) != CKR_OK || labelAttr.ulValueLen == 0)
            continue;
        std::vector<char> buf(labelAttr.ulValueLen);
        labelAttr.pValue = buf.data();
        if (C_GetAttributeValue(session, handle, &labelAttr, 1) != CKR_OK)
            continue;
        std::string label(buf.data(), buf.size());
        std::string lower = label;
        for (auto& c : lower)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        for (const char* needle : needles) {
            std::string n = needle;
            for (auto& c : n)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lower.find(n) != std::string::npos) {
                match = handle;
                break;
            }
        }
        if (match != CK_INVALID_HANDLE)
            break;
    }
    (void)C_FindObjectsFinal(session);
    return match;
}

// Reads CKA_VALUE off a certificate object (DER bytes).
std::vector<uint8_t> readCertDer(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE cert)
{
    CK_ATTRIBUTE attr{CKA_VALUE, nullptr, 0};
    if (C_GetAttributeValue(session, cert, &attr, 1) != CKR_OK || attr.ulValueLen == 0)
        return {};
    std::vector<uint8_t> der(attr.ulValueLen);
    attr.pValue = der.data();
    if (C_GetAttributeValue(session, cert, &attr, 1) != CKR_OK)
        return {};
    return der;
}

// Reads CKA_ID off a private-key or certificate object.
std::vector<uint8_t> readCkaId(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE obj)
{
    CK_ATTRIBUTE attr{CKA_ID, nullptr, 0};
    if (C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK || attr.ulValueLen == 0)
        return {};
    std::vector<uint8_t> id(attr.ulValueLen);
    attr.pValue = id.data();
    if (C_GetAttributeValue(session, obj, &attr, 1) != CKR_OK)
        return {};
    return id;
}

// Locates the private RSA key whose CKA_ID matches `id`. Returns
// CK_INVALID_HANDLE when no such key is reachable (e.g. session not
// logged in for a CKA_PRIVATE=true key).
CK_OBJECT_HANDLE findPrivateKeyById(CK_SESSION_HANDLE session, const std::vector<uint8_t>& id)
{
    CK_OBJECT_CLASS klass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    std::array<CK_ATTRIBUTE, 3> tmpl{{
        {CKA_CLASS, &klass, sizeof(klass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ID, const_cast<uint8_t*>(id.data()), static_cast<CK_ULONG>(id.size())},
    }};
    if (C_FindObjectsInit(session, tmpl.data(), tmpl.size()) != CKR_OK)
        return CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE key = CK_INVALID_HANDLE;
    CK_ULONG found = 0;
    (void)C_FindObjects(session, &key, 1, &found);
    (void)C_FindObjectsFinal(session);
    return found > 0 ? key : CK_INVALID_HANDLE;
}

} // namespace

// ===========================================================================
// Tests
// ===========================================================================

TEST_F(Pkcs11PksFixture, PksContact_GetSlotList_ReturnsOneSlot)
{
    SKIP_IF_PIN_FAILED();

    const auto pks = findPksSlot();
    if (!pks)
        GTEST_SKIP() << "No PKS card detected (no token whose label contains 'Serbian CardEdge').";

    // PKS is single-PIN → exactly one PKCS#11 slot for the card.
    // Multiple non-PKS readers may bring the total slot count higher;
    // assert there is at least one and that the one we found is reachable.
    const auto slots = slotsWithToken();
    EXPECT_GE(slots.size(), 1u);
    EXPECT_NE(std::find(slots.begin(), slots.end(), *pks), slots.end());
}

TEST_F(Pkcs11PksFixture, PksContact_TokenLabel)
{
    SKIP_IF_PIN_FAILED();

    const auto pks = findPksSlot();
    if (!pks)
        GTEST_SKIP() << "No PKS card detected.";

    CK_TOKEN_INFO info{};
    ASSERT_EQ(C_GetTokenInfo(*pks, &info), CKR_OK);
    const std::string label = trimmedField(info.label, sizeof(info.label));
    EXPECT_NE(label.find("Serbian CardEdge"), std::string::npos)
        << "PKS token label expected to contain 'Serbian CardEdge'; got: '" << label << "'";
}

TEST_F(Pkcs11PksFixture, PksContact_BothCerts_Enumerate)
{
    SKIP_IF_PIN_FAILED();

    const auto pks = findPksSlot();
    if (!pks)
        GTEST_SKIP() << "No PKS card detected.";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(*pks, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    // Certificate objects are CKA_PRIVATE=false → enumerable without login.
    CK_OBJECT_CLASS klass = CKO_CERTIFICATE;
    std::array<CK_ATTRIBUTE, 1> tmpl{{{CKA_CLASS, &klass, sizeof(klass)}}};
    ASSERT_EQ(C_FindObjectsInit(session, tmpl.data(), tmpl.size()), CKR_OK);
    std::vector<CK_OBJECT_HANDLE> certs;
    while (true) {
        CK_OBJECT_HANDLE h = CK_INVALID_HANDLE;
        CK_ULONG found = 0;
        ASSERT_EQ(C_FindObjects(session, &h, 1, &found), CKR_OK);
        if (found == 0)
            break;
        certs.push_back(h);
    }
    ASSERT_EQ(C_FindObjectsFinal(session), CKR_OK);

    EXPECT_GE(certs.size(), 2u) << "PKS card is expected to expose at least two certificates "
                                   "(Key Exchange + Digital Signature); found "
                                << certs.size();

    (void)C_CloseSession(session);
}

TEST_F(Pkcs11PksFixture, PksContact_LoginAndSign_Succeeds)
{
    SKIP_IF_PIN_FAILED();
    REQUIRE_ENV("LIBRESCRS_TEST_PIN");

    const auto pks = findPksSlot();
    if (!pks)
        GTEST_SKIP() << "No PKS card detected.";

    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    ASSERT_EQ(C_OpenSession(*pks, CKF_SERIAL_SESSION, nullptr, nullptr, &session), CKR_OK);

    // Locate the Digital Signature certificate by label substring.
    // PKS labels typically read "Digital Signature" / "Key Exchange".
    CK_OBJECT_HANDLE dsCert = findCertByLabelSubstring(session, {"digital signature", "sign"});
    if (dsCert == CK_INVALID_HANDLE) {
        (void)C_CloseSession(session);
        GTEST_SKIP() << "PKS card has no Digital Signature certificate (label match) — unexpected; skipping.";
    }

    const auto dsCertDer = readCertDer(session, dsCert);
    ASSERT_FALSE(dsCertDer.empty()) << "Digital Signature certificate CKA_VALUE empty.";
    const auto dsId = readCkaId(session, dsCert);
    ASSERT_FALSE(dsId.empty()) << "Digital Signature certificate CKA_ID empty.";

    // Login as user (single-PIN card; no CAN prefix).
    {
        auto pinBytes = makePinBytes(env("LIBRESCRS_TEST_PIN"));
        const CK_RV rv = C_Login(session, CKU_USER, pinBytes.data(), static_cast<CK_ULONG>(pinBytes.size()));
        LOGIN_OR_ABORT(rv, *pks, "C_Login(PKS, single-PIN)");
    }

    // Find the private RSA key sharing CKA_ID with the chosen cert.
    CK_OBJECT_HANDLE key = findPrivateKeyById(session, dsId);
    ASSERT_NE(key, CK_INVALID_HANDLE) << "Could not locate private RSA key matching Digital Signature cert CKA_ID.";

    // Build SHA-256 DigestInfo over a known payload, sign via raw
    // CKM_RSA_PKCS, then verify the signature against the cert's pubkey
    // using EVP_PKEY_verify (RSA_PKCS1_PADDING + SHA-256 md). This is
    // the exact contract pkcs11-tool's `--sign -m SHA256-RSA-PKCS` flow
    // exercises end-to-end.
    const std::vector<uint8_t> payload = {'l', 'i', 'b', 'r', 'e', 's', 'c', 'r', 's', '-', 'e', '2', 'e'};

    unsigned char digest[32];
    {
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        ASSERT_NE(md, nullptr);
        ASSERT_EQ(EVP_DigestInit_ex(md, EVP_sha256(), nullptr), 1);
        ASSERT_EQ(EVP_DigestUpdate(md, payload.data(), payload.size()), 1);
        unsigned int n = 0;
        ASSERT_EQ(EVP_DigestFinal_ex(md, digest, &n), 1);
        ASSERT_EQ(n, 32u);
        EVP_MD_CTX_free(md);
    }

    // RFC 3447 §9.2 DigestInfo DER prefix for id-sha256.
    static constexpr std::array<uint8_t, 19> kSha256DigestInfoPrefix = {0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60,
                                                                        0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02,
                                                                        0x01, 0x05, 0x00, 0x04, 0x20};
    std::vector<CK_BYTE> signInput;
    signInput.reserve(kSha256DigestInfoPrefix.size() + 32);
    signInput.insert(signInput.end(), kSha256DigestInfoPrefix.begin(), kSha256DigestInfoPrefix.end());
    signInput.insert(signInput.end(), digest, digest + 32);

    CK_MECHANISM mech{CKM_RSA_PKCS, nullptr, 0};
    ASSERT_EQ(C_SignInit(session, &mech, key), CKR_OK);

    CK_ULONG sigLen = 0;
    ASSERT_EQ(C_Sign(session, signInput.data(), static_cast<CK_ULONG>(signInput.size()), nullptr, &sigLen), CKR_OK);
    ASSERT_GT(sigLen, 0u);
    std::vector<CK_BYTE> sig(sigLen);
    ASSERT_EQ(C_Sign(session, signInput.data(), static_cast<CK_ULONG>(signInput.size()), sig.data(), &sigLen), CKR_OK);
    ASSERT_EQ(sig.size(), sigLen);

    // Decode cert + extract public key; RAII keeps OpenSSL handles
    // alive across the fatal-assert escape paths.
    using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;
    using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
    using EvpPkeyCtxPtr = std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)>;

    const unsigned char* derPtr = dsCertDer.data();
    X509Ptr x{d2i_X509(nullptr, &derPtr, static_cast<long>(dsCertDer.size())), &X509_free};
    ASSERT_NE(x.get(), nullptr) << "d2i_X509 failed parsing Digital Signature cert.";
    EvpPkeyPtr pkey{X509_get_pubkey(x.get()), &EVP_PKEY_free};
    ASSERT_NE(pkey.get(), nullptr) << "X509_get_pubkey failed.";

    EvpPkeyCtxPtr vctx{EVP_PKEY_CTX_new(pkey.get(), nullptr), &EVP_PKEY_CTX_free};
    ASSERT_NE(vctx.get(), nullptr);
    ASSERT_EQ(EVP_PKEY_verify_init(vctx.get()), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_rsa_padding(vctx.get(), RSA_PKCS1_PADDING), 1);
    ASSERT_EQ(EVP_PKEY_CTX_set_signature_md(vctx.get(), EVP_sha256()), 1);

    const int vres = EVP_PKEY_verify(vctx.get(), sig.data(), sig.size(), digest, 32);
    EXPECT_EQ(vres, 1) << "Signature verify FAILED — PKS card produced a signature that does "
                          "not validate against its own cert's public key. "
                          "Sig len: "
                       << sig.size() << " bytes.";

    (void)C_Logout(session);
    (void)C_CloseSession(session);
}

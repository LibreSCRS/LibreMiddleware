// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/jades_module.h"
#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/mock_tsa_server.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

#include <json.hpp>

#include <openssl/bio.h>
#include <openssl/evp.h>

#include <string>
#include <vector>

using namespace libresign;

namespace {

nlohmann::json parseJws(const SigningResult& result)
{
    return nlohmann::json::parse(result.signedDocument.begin(), result.signedDocument.end());
}

/// The etsiU array of one `signatures[]` entry, or a null json when the entry
/// carries no unprotected header. ETSI TS 119 182-1 §5.3 places etsiU in the
/// per-signature unprotected header, so this is deliberately scoped to ONE
/// entry — a document-wide search would not notice a component landing on the
/// wrong signer.
nlohmann::json entryEtsiU(const nlohmann::json& entry)
{
    if (!entry.contains("header") || !entry["header"].contains("etsiU"))
        return nlohmann::json{};
    return entry["header"]["etsiU"];
}

/// True when @p etsiU carries at least one component named @p key
/// (`sigTst`, `rVals`, `arcTst`).
bool etsiUHasComponent(const nlohmann::json& etsiU, const char* key)
{
    if (!etsiU.is_array())
        return false;
    for (const auto& component : etsiU) {
        if (component.is_object() && component.contains(key))
            return true;
    }
    return false;
}

} // namespace

class JAdESModuleTest : public ::testing::Test
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

    /// Sign @p data with the valid signer at @p level.
    SigningResult signFirst(const std::vector<uint8_t>& data, SignatureLevel level, const TSAConfig& tsa)
    {
        JAdESModule jades;
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                          libresign::Pkcs11Token::TestSlotId{testSlot});
        return jades.sign(data, "test.txt", token, level, SignaturePackaging::Detached, tsa);
    }

    /// Append using the OTHER key pair on the token, so the new entry is
    /// distinguishable from the prior one. Module-level appendSigner applies no
    /// expiry policy (that lives in NativeSigningService), so the expired pair
    /// signs normally here.
    SigningResult appendSecond(const std::vector<uint8_t>& prior, const std::vector<uint8_t>& originalDoc,
                               SignatureLevel level, const TSAConfig& tsa)
    {
        JAdESModule jades;
        Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"),
                          libresign::test::kSoftHsmExpiredKeyLabel, libresign::Pkcs11Token::TestSlotId{testSlot});
        return jades.appendSigner(prior, originalDoc, "test.txt", token, level, tsa);
    }

    const char* softHsmPath = nullptr;
    libresign::Pkcs11ModuleManager manager;
    unsigned long testSlot = 0;
};

TEST_F(JAdESModuleTest, SignBB_ProducesValidJWS)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    JAdESModule jades;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = jades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());

    // Parse as JSON
    std::string json(result.signedDocument.begin(), result.signedDocument.end());
    auto j = nlohmann::json::parse(json);

    // JWS JSON Serialization should have "signatures" array
    ASSERT_TRUE(j.contains("signatures"));
    ASSERT_GE(j["signatures"].size(), 1u);
    ASSERT_TRUE(j["signatures"][0].contains("protected"));
    ASSERT_TRUE(j["signatures"][0].contains("signature"));
}

TEST_F(JAdESModuleTest, SignBB_DetachedOmitsPayload)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    JAdESModule jades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto result = jades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;

    std::string json(result.signedDocument.begin(), result.signedDocument.end());
    auto j = nlohmann::json::parse(json);

    // Detached: per RFC 7797 §4.2 and RFC 7515 §7.2 the "payload" member is
    // OMITTED, not present-but-empty. An empty-string payload is a distinct
    // (and valid) JWS input that strict validators reject on detached
    // signatures, so absence is the contract being pinned here.
    EXPECT_FALSE(j.contains("payload"));
}

TEST_F(JAdESModuleTest, SignBB_EnvelopedHasPayload)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    JAdESModule jades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto result = jades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Enveloped, {});

    ASSERT_TRUE(result.success) << result.errorMessage;

    std::string json(result.signedDocument.begin(), result.signedDocument.end());
    auto j = nlohmann::json::parse(json);

    // Enveloped: payload should be non-empty base64url
    ASSERT_TRUE(j.contains("payload"));
    EXPECT_FALSE(j["payload"].get<std::string>().empty());
}

TEST_F(JAdESModuleTest, SignBB_ProtectedHeaderContainsRequiredFields)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    JAdESModule jades;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = jades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;

    std::string json(result.signedDocument.begin(), result.signedDocument.end());
    auto j = nlohmann::json::parse(json);

    // Decode the protected header (base64url)
    std::string protB64 = j["signatures"][0]["protected"].get<std::string>();
    // Add padding back for standard base64 decode
    while (protB64.size() % 4 != 0)
        protB64 += '=';
    for (char& c : protB64) {
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
    }

    // Decode base64
    std::vector<uint8_t> decoded(protB64.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(protB64.data(), static_cast<int>(protB64.size()));
    mem = BIO_push(b64, mem);
    BIO_set_flags(mem, BIO_FLAGS_BASE64_NO_NL);
    int decodedLen = BIO_read(mem, decoded.data(), static_cast<int>(decoded.size()));
    BIO_free_all(mem);

    ASSERT_GT(decodedLen, 0);
    decoded.resize(static_cast<size_t>(decodedLen));

    auto headerParsed = nlohmann::json::parse(decoded.begin(), decoded.end());
    // ETSI TS 119 182-1 baseline B requires: alg, x5c or x5t#S256 (signing
    // cert ref), and a claimed-signing-time. We emit iat (RFC 7519 numeric
    // date) — sigT was deprecated in 2024 and dropped by DSS 6.4 after
    // 2025-05-15. crit lists only non-registered header members; iat and
    // x5t#S256 are JOSE-registered so they MUST NOT appear in crit.
    EXPECT_TRUE(headerParsed.contains("alg"));
    EXPECT_TRUE(headerParsed.contains("x5c"));
    EXPECT_TRUE(headerParsed.contains("x5t#S256"));
    EXPECT_TRUE(headerParsed.contains("iat"));
    EXPECT_FALSE(headerParsed.contains("sigT"));
    // crit is required for detached (b64=false); for enveloped, no
    // non-registered headers means crit MAY be omitted entirely.
    EXPECT_TRUE(headerParsed.contains("crit"));
}

TEST_F(JAdESModuleTest, SignBB_DifferentDataProducesDifferentSignature)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    JAdESModule jades;

    std::vector<uint8_t> data1 = {'A', 'B', 'C'};
    std::vector<uint8_t> data2 = {'X', 'Y', 'Z'};

    auto result1 = jades.sign(data1, "a.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});
    auto result2 = jades.sign(data2, "b.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result1.success) << result1.errorMessage;
    ASSERT_TRUE(result2.success) << result2.errorMessage;
    EXPECT_NE(result1.signedDocument, result2.signedDocument);
}

TEST_F(JAdESModuleTest, SignBB_NoEtsiUHeader)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    JAdESModule jades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto result = jades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;

    std::string json(result.signedDocument.begin(), result.signedDocument.end());
    auto j = nlohmann::json::parse(json);

    // B-B should NOT have unprotected header with etsiU
    EXPECT_FALSE(j["signatures"][0].contains("header"));
}

// ---- Per-signature etsiU (ETSI TS 119 182-1 §5.3) ----

// etsiU is a per-signature unprotected header member: the components a signer
// requested belong to that signer's entry in signatures[] and to no other.
// Assert on the NEW entry's own header, and assert the prior entry came
// through byte-identical — a validator that recomputes the prior signer's
// sigTst imprint over a mutated entry would reject a signature that was valid
// before the append.
TEST_F(JAdESModuleTest, AppendSignerAtBTAddsEtsiUToTheNewEntryOnly)
{
    libresign::test::MockTsaServer tsaServer;
    const std::vector<uint8_t> data = {'M', 'u', 'l', 't', 'i'};

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    auto prior = signFirst(data, SignatureLevel::B_T, tsa);
    ASSERT_TRUE(prior.success) << prior.errorMessage;

    auto priorJws = parseJws(prior);
    ASSERT_EQ(priorJws["signatures"].size(), 1u);
    const std::string priorEntryDump = priorJws["signatures"][0].dump();
    ASSERT_TRUE(etsiUHasComponent(entryEtsiU(priorJws["signatures"][0]), "sigTst"))
        << "fixture precondition: the first signer must already carry its own sigTst";

    auto appended = appendSecond(prior.signedDocument, data, SignatureLevel::B_T, tsa);
    ASSERT_TRUE(appended.success) << appended.errorMessage;
    EXPECT_EQ(tsaServer.servedCount(), 2) << "one RFC 3161 round-trip per signer";

    auto appendedJws = parseJws(appended);
    ASSERT_EQ(appendedJws["signatures"].size(), 2u);

    EXPECT_TRUE(etsiUHasComponent(entryEtsiU(appendedJws["signatures"][1]), "sigTst"))
        << "the appended signer must carry its OWN sigTst in its OWN header";
    EXPECT_EQ(appendedJws["signatures"][0].dump(), priorEntryDump)
        << "the prior signer's entry must survive the append byte-for-byte";
}

// B-B appends must not grow an unprotected header at all: with no upgrade
// requested there is no etsiU component to place.
TEST_F(JAdESModuleTest, AppendSignerAtBBAddsNoEtsiU)
{
    const std::vector<uint8_t> data = {'P', 'l', 'a', 'i', 'n'};

    auto prior = signFirst(data, SignatureLevel::B_B, {});
    ASSERT_TRUE(prior.success) << prior.errorMessage;

    auto appended = appendSecond(prior.signedDocument, data, SignatureLevel::B_B, {});
    ASSERT_TRUE(appended.success) << appended.errorMessage;

    auto appendedJws = parseJws(appended);
    ASSERT_EQ(appendedJws["signatures"].size(), 2u);
    EXPECT_FALSE(appendedJws["signatures"][1].contains("header"));
}

// B-LT on append now reaches the long-term revocation gate instead of being
// refused up front. The SoftHSM token's single self-signed leaf is a chain of
// length one, so the tail is unprovable and the gate must fail closed.
TEST_F(JAdESModuleTest, AppendSignerAtLongTermRejectsUnterminatedChain)
{
    libresign::test::MockTsaServer tsaServer;
    const std::vector<uint8_t> data = {'L', 'o', 'n', 'g'};

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    auto prior = signFirst(data, SignatureLevel::B_B, {});
    ASSERT_TRUE(prior.success) << prior.errorMessage;

    auto appended = appendSecond(prior.signedDocument, data, SignatureLevel::B_LT, tsa);
    EXPECT_FALSE(appended.success);
    ASSERT_TRUE(appended.failureKind.has_value()) << appended.errorMessage;
    EXPECT_EQ(*appended.failureKind, SignFailureKind::CertificateChainIncomplete) << appended.errorMessage;
}

// B-LTA stays refused on the append path, matching the CAdES ceiling: an
// archive timestamp seals a document state, and appending a signer changes
// that state for every signer already present.
TEST_F(JAdESModuleTest, AppendSignerRejectsArchiveLevel)
{
    libresign::test::MockTsaServer tsaServer;
    const std::vector<uint8_t> data = {'A', 'r', 'c', 'h'};

    TSAConfig tsa;
    tsa.url = tsaServer.url();
    auto prior = signFirst(data, SignatureLevel::B_B, {});
    ASSERT_TRUE(prior.success) << prior.errorMessage;

    auto appended = appendSecond(prior.signedDocument, data, SignatureLevel::B_LTA, tsa);
    EXPECT_FALSE(appended.success);
    ASSERT_TRUE(appended.failureKind.has_value()) << appended.errorMessage;
    EXPECT_EQ(*appended.failureKind, SignFailureKind::PolicyViolation) << appended.errorMessage;
}

// Non-SoftHSM tests

TEST(JAdESModuleStandalone, BTRequiresTSA)
{
    // Cannot actually test without SoftHSM, but verifies the interface
    JAdESModule jades;
    std::vector<uint8_t> data = {'T', 'e', 's', 't'};

    const char* hsmPath = libresign::test::findSoftHsmPath();
    if (!hsmPath)
        GTEST_SKIP() << "SoftHSM2 not found";

    libresign::Pkcs11ModuleManager localManager;
    auto slot = libresign::test::findSoftHsmTestSlot(localManager.acquire(hsmPath));
    if (!slot)
        GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";

    Pkcs11Token token(localManager.acquire(hsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{*slot});
    TSAConfig emptyTsa; // empty URL
    auto result = jades.sign(data, "test.txt", token, SignatureLevel::B_T, SignaturePackaging::Detached, emptyTsa);

    // Should fail because TSA URL is empty
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
}

// Non-SoftHSM tests

TEST(JAdESModuleStandalone, RejectsEmptyInput)
{
    JAdESModule jades;
    std::vector<uint8_t> empty;
    // Token is never touched — sign() returns early on empty input.
    alignas(Pkcs11Token) char storage[sizeof(Pkcs11Token)]{};
    auto& dummyToken = *reinterpret_cast<Pkcs11Token*>(storage);
    auto result = jades.sign(empty, "test.json", dummyToken, SignatureLevel::B_B, SignaturePackaging::Detached, {});
    ASSERT_FALSE(result.success);
    EXPECT_NE(result.errorMessage.find("empty"), std::string::npos);
}

#else
TEST(JAdESModuleTest, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif

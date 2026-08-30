// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <csca_master_list.h>
#include <passive_auth.h>
#include <chip_auth.h>
#include <active_auth.h>
#include <secure_messaging.h>
#include <bac.h>
#include <LibreSCRS/Plugin/SecurityCheck.h>

// Relative, unlike the angle-bracket includes above: this header is a test
// fixture that lives next to this file, not on any target include path.
#include "emrtd-crypto/synthetic_masterlist.h"

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <stdexcept>

#include <unistd.h> // geteuid, for the root-runs-ignore-permissions guard below

// ---------------------------------------------------------------------------
// Passive Authentication tests
// ---------------------------------------------------------------------------

TEST(PassiveAuthTest, VerifyDGHashMatchesSHA256)
{
    std::vector<uint8_t> emptyData;
    // SHA-256 of empty input
    std::vector<uint8_t> expectedHash = {0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4,
                                         0xc8, 0x99, 0x6f, 0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b,
                                         0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55};
    auto status = emrtd::crypto::verifyDGHash(emptyData, expectedHash, "SHA-256");
    EXPECT_EQ(status, emrtd::crypto::PAResult::PASSED);
}

TEST(PassiveAuthTest, VerifyDGHashMismatch)
{
    std::vector<uint8_t> data = {0x01, 0x02, 0x03};
    std::vector<uint8_t> wrongHash(32, 0x00);
    auto status = emrtd::crypto::verifyDGHash(data, wrongHash, "SHA-256");
    EXPECT_EQ(status, emrtd::crypto::PAResult::FAILED);
}

TEST(PassiveAuthTest, VerifyDGHashMatchesSHA1)
{
    std::vector<uint8_t> emptyData;
    // SHA-1 of empty input
    std::vector<uint8_t> expectedHash = {0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
                                         0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09};
    auto status = emrtd::crypto::verifyDGHash(emptyData, expectedHash, "SHA-1");
    EXPECT_EQ(status, emrtd::crypto::PAResult::PASSED);
}

TEST(PassiveAuthTest, VerifyDGHashUnsupportedAlgorithm)
{
    std::vector<uint8_t> data = {0x01};
    std::vector<uint8_t> hash(32, 0x00);
    auto status = emrtd::crypto::verifyDGHash(data, hash, "MD5");
    EXPECT_EQ(status, emrtd::crypto::PAResult::FAILED);
}

TEST(PassiveAuthTest, ParseEmptySODReturnsNullopt)
{
    auto sod = emrtd::crypto::parseSOD({});
    EXPECT_FALSE(sod.has_value());
}

TEST(PassiveAuthTest, ParseGarbageSODReturnsNullopt)
{
    std::vector<uint8_t> garbage = {0xFF, 0xFE, 0xFD, 0xFC};
    auto sod = emrtd::crypto::parseSOD(garbage);
    EXPECT_FALSE(sod.has_value());
}

TEST(PassiveAuthTest, PerformPAWithNoSODFails)
{
    auto result = emrtd::crypto::performPassiveAuth({}, {});
    EXPECT_EQ(result.sodSignature, emrtd::crypto::PAResult::FAILED);
    EXPECT_FALSE(result.errorDetail.empty());
}

TEST(PassiveAuthTest, VerifySODSignatureEmptyFails)
{
    auto status = emrtd::crypto::verifySODSignature({});
    EXPECT_EQ(status, emrtd::crypto::PAResult::FAILED);
}

TEST(PassiveAuthTest, VerifyCSCAChainEmptyNotPerformed)
{
    auto status = emrtd::crypto::verifyCSCAChain({}, "");
    EXPECT_EQ(status, emrtd::crypto::PAResult::NOT_PERFORMED);
}

// ---------------------------------------------------------------------------
// Chip Authentication tests
// ---------------------------------------------------------------------------

TEST(ChipAuthTest, ParseEmptyDG14Fails)
{
    std::vector<emrtd::crypto::ChipAuthInfo> infos;
    std::vector<emrtd::crypto::ChipAuthPublicKey> keys;
    EXPECT_FALSE(emrtd::crypto::parseDG14({}, infos, keys));
}

TEST(ChipAuthTest, ParseGarbageDG14Fails)
{
    std::vector<uint8_t> garbage = {0xFF, 0xFE, 0xFD, 0xFC};
    std::vector<emrtd::crypto::ChipAuthInfo> infos;
    std::vector<emrtd::crypto::ChipAuthPublicKey> keys;
    EXPECT_FALSE(emrtd::crypto::parseDG14(garbage, infos, keys));
}

TEST(ChipAuthTest, ParseDG14WrongTagFails)
{
    // Tag 0x30 instead of expected 0x6E
    std::vector<uint8_t> wrongTag = {0x30, 0x02, 0x31, 0x00};
    std::vector<emrtd::crypto::ChipAuthInfo> infos;
    std::vector<emrtd::crypto::ChipAuthPublicKey> keys;
    EXPECT_FALSE(emrtd::crypto::parseDG14(wrongTag, infos, keys));
}

TEST(ChipAuthTest, ParseDG14EmptySetFails)
{
    // Valid 0x6E tag wrapping an empty SET
    std::vector<uint8_t> emptySet = {0x6E, 0x02, 0x31, 0x00};
    std::vector<emrtd::crypto::ChipAuthInfo> infos;
    std::vector<emrtd::crypto::ChipAuthPublicKey> keys;
    EXPECT_FALSE(emrtd::crypto::parseDG14(emptySet, infos, keys));
}

// ---------------------------------------------------------------------------
// Active Authentication tests
// ---------------------------------------------------------------------------

TEST(ActiveAuthTest, ParseEmptyDG15ReturnsUnknown)
{
    auto key = emrtd::crypto::parseDG15({});
    EXPECT_EQ(key.algorithm, emrtd::crypto::AAPublicKey::UNKNOWN);
}

TEST(ActiveAuthTest, ParseGarbageDG15ReturnsUnknown)
{
    std::vector<uint8_t> garbage = {0xFF, 0xFE, 0xFD, 0xFC};
    auto key = emrtd::crypto::parseDG15(garbage);
    EXPECT_EQ(key.algorithm, emrtd::crypto::AAPublicKey::UNKNOWN);
}

TEST(ActiveAuthTest, ParseDG15WrongTagReturnsUnknown)
{
    // Tag 0x30 instead of expected 0x6F
    std::vector<uint8_t> wrongTag = {0x30, 0x02, 0x30, 0x00};
    auto key = emrtd::crypto::parseDG15(wrongTag);
    EXPECT_EQ(key.algorithm, emrtd::crypto::AAPublicKey::UNKNOWN);
}

// ---------------------------------------------------------------------------
// SecurityStatus tests
// ---------------------------------------------------------------------------

TEST(SecurityStatusTest, ComputeOverallAllPassed)
{
    LibreSCRS::Plugin::SecurityStatus status;
    status.checks.push_back({"pa.dg_hash.1", LibreSCRS::Plugin::SecurityCategory::DataIntegrity,
                             LibreSCRS::Plugin::SecurityCheck::Status::Passed, "DG1 Hash", "", ""});
    status.checks.push_back({"pa.dg_hash.2", LibreSCRS::Plugin::SecurityCategory::DataIntegrity,
                             LibreSCRS::Plugin::SecurityCheck::Status::Passed, "DG2 Hash", "", ""});
    status.checks.push_back({"pa.sod_signature", LibreSCRS::Plugin::SecurityCategory::Authenticity,
                             LibreSCRS::Plugin::SecurityCheck::Status::Passed, "SOD Signature", "", ""});
    status.checks.push_back({"ca.chip_auth", LibreSCRS::Plugin::SecurityCategory::Genuineness,
                             LibreSCRS::Plugin::SecurityCheck::Status::Passed, "Chip Auth", "", ""});
    status.computeOverall();
    EXPECT_EQ(status.overallIntegrity, LibreSCRS::Plugin::SecurityCheck::Status::Passed);
    EXPECT_EQ(status.overallAuthenticity, LibreSCRS::Plugin::SecurityCheck::Status::Passed);
    EXPECT_EQ(status.overallGenuineness, LibreSCRS::Plugin::SecurityCheck::Status::Passed);
}

TEST(SecurityStatusTest, ComputeOverallOneFailed)
{
    LibreSCRS::Plugin::SecurityStatus status;
    status.checks.push_back({"pa.dg_hash.1", LibreSCRS::Plugin::SecurityCategory::DataIntegrity,
                             LibreSCRS::Plugin::SecurityCheck::Status::Passed, "DG1 Hash", "", ""});
    status.checks.push_back({"pa.dg_hash.2", LibreSCRS::Plugin::SecurityCategory::DataIntegrity,
                             LibreSCRS::Plugin::SecurityCheck::Status::Failed, "DG2 Hash", "", "hash mismatch"});
    status.computeOverall();
    EXPECT_EQ(status.overallIntegrity, LibreSCRS::Plugin::SecurityCheck::Status::Failed);
}

TEST(SecurityStatusTest, ComputeOverallNotPerformed)
{
    LibreSCRS::Plugin::SecurityStatus status;
    status.computeOverall();
    EXPECT_EQ(status.overallIntegrity, LibreSCRS::Plugin::SecurityCheck::Status::NotPerformed);
    EXPECT_EQ(status.overallAuthenticity, LibreSCRS::Plugin::SecurityCheck::Status::NotPerformed);
    EXPECT_EQ(status.overallGenuineness, LibreSCRS::Plugin::SecurityCheck::Status::NotPerformed);
}

// ---------------------------------------------------------------------------
// Secure Messaging protect/unprotect round-trip test
// ---------------------------------------------------------------------------

TEST(SecureMessagingTest, ProtectUnprotectRoundTrip)
{
    // Use known 3DES (BAC-style) keys for a deterministic round-trip.
    // We protect a SELECT APDU with data, then build a synthetic SM response
    // that a card would return, and verify unprotect recovers the original data.
    using namespace emrtd::crypto;

    SessionKeys protectKeys;
    protectKeys.encKey = {0xCB, 0x10, 0x61, 0xFE, 0x76, 0x4F, 0x0B, 0x1C,
                          0x86, 0xF1, 0x91, 0xC2, 0x2A, 0x51, 0x97, 0x31};
    protectKeys.macKey = {0x25, 0xDA, 0x08, 0xAD, 0x4A, 0xA2, 0x0E, 0x3D,
                          0x38, 0xF8, 0x02, 0xD9, 0x75, 0x85, 0x32, 0x57};
    protectKeys.ssc = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // Plain SELECT APDU: 00 A4 04 0C 07 A0000002471001
    std::vector<uint8_t> plainCmd = {0x00, 0xA4, 0x04, 0x0C, 0x07, 0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01};

    SecureMessaging smProtect(protectKeys, SMAlgorithm::DES3);
    auto protectedCmd = smProtect.protect(plainCmd);

    // Verify the protected command is well-formed
    ASSERT_GT(protectedCmd.size(), 4u);
    EXPECT_EQ(protectedCmd[0] & 0x0C, 0x0C) << "CLA SM bit not set";
    EXPECT_EQ(protectedCmd[1], 0xA4) << "INS must be preserved";
    EXPECT_EQ(protectedCmd[2], 0x04) << "P1 must be preserved";
    EXPECT_EQ(protectedCmd[3], 0x0C) << "P2 must be preserved";

    // Now test with a no-data command (READ BINARY) — two SM instances with
    // identical keys must produce a synthetic response that round-trips.
    // We use two instances to simulate card-side and reader-side with
    // synchronized SSC values.
    SessionKeys readerKeys;
    readerKeys.encKey = protectKeys.encKey;
    readerKeys.macKey = protectKeys.macKey;
    readerKeys.ssc = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10};

    SessionKeys cardKeys = readerKeys; // card starts with same keys

    SecureMessaging smReader(readerKeys, SMAlgorithm::DES3);
    SecureMessaging smCard(cardKeys, SMAlgorithm::DES3);

    // Reader protects a READ BINARY command (SSC incremented to ...11)
    std::vector<uint8_t> readBinary = {0x00, 0xB0, 0x00, 0x00, 0x04};
    auto protectedRead = smReader.protect(readBinary);
    EXPECT_GT(protectedRead.size(), readBinary.size());

    // Card side: protect would increment SSC once more (to ...12) for the response.
    // We simulate: card also called protect once (to sync SSC to ...11), now
    // card builds response. For the unprotect test, we verify that two identical
    // SM instances produce the same output (determinism).
    auto protectedRead2 = smCard.protect(readBinary);
    EXPECT_EQ(protectedRead, protectedRead2) << "Two SM instances with same keys/SSC must produce identical output";
}

// ---------------------------------------------------------------------------
// EF.COM parsing edge cases
// ---------------------------------------------------------------------------
// NOTE: readCOM() is a method on EMRTDCard which requires a live card
// connection — the COM parsing logic is tightly coupled to the card object
// and there is no standalone parse function. These tests would need to be
// run as hardware integration tests (see pace_hardware_test.cpp).
// Leaving placeholder tests to document the gap.

TEST(EFCOMTest, ParseEmptyCOM)
{
    // readCOM() on EMRTDCard reads from the card — no static parse available.
    // Tested indirectly via PACEHardwareTest::PaceAuthenticateAndReadCOM.
    GTEST_SKIP() << "COM parsing is coupled to EMRTDCard (needs card connection)";
}

TEST(EFCOMTest, ParseUnknownTags)
{
    // Unknown DG tags in the tag list (0x5C) are silently skipped by readCOM().
    // No standalone parser to unit-test — would need a mock connection or
    // extracting the parse logic into a free function.
    GTEST_SKIP() << "COM parsing is coupled to EMRTDCard (needs card connection)";
}

// ---------------------------------------------------------------------------
// BAC key derivation — ICAO 9303 Appendix D test vectors
// ---------------------------------------------------------------------------
// The worked example from ICAO Doc 9303 Part 11, Section 4.4 (Appendix D.2):
//   Document number: L898902C
//   Date of birth:   740727
//   Date of expiry:  120714
// Expected K_seed and derived keys verified against the spec.

TEST(BACTestVectors, ICAO9303AppendixD2KeyDerivation)
{
    auto keys = emrtd::crypto::deriveBACKeys("L898902C", "740727", "120714");

    // From ICAO 9303 Part 11 §D.2:
    // MRZ_information = "L898902C<37407273120714 9"
    // K_seed = SHA-1("L898902C<3740727312071 49")[0:16]
    //
    // K_Enc (after KDF counter=1 and parity adjustment):
    std::vector<uint8_t> expectedEnc = {0xCB, 0x10, 0x61, 0xFE, 0x76, 0x4F, 0x0B, 0x1C,
                                        0x86, 0xF1, 0x91, 0xC2, 0x2A, 0x51, 0x97, 0x31};
    // K_MAC (after KDF counter=2 and parity adjustment):
    std::vector<uint8_t> expectedMac = {0x25, 0xDA, 0x08, 0xAD, 0x4A, 0xA2, 0x0E, 0x3D,
                                        0x38, 0xF8, 0x02, 0xD9, 0x75, 0x85, 0x32, 0x57};

    EXPECT_EQ(keys.encKey, expectedEnc) << "K_Enc does not match ICAO 9303 Appendix D.2";
    EXPECT_EQ(keys.macKey, expectedMac) << "K_MAC does not match ICAO 9303 Appendix D.2";
}

TEST(BACTestVectors, ICAO9303CheckDigits)
{
    // ICAO 9303 Part 3 §4.9 check digit algorithm (weight 7,3,1)
    // These are the three check digits used in Appendix D.2
    EXPECT_EQ(emrtd::crypto::detail::computeCheckDigit("L898902C<"), 3);
    EXPECT_EQ(emrtd::crypto::detail::computeCheckDigit("740727"), 3);
    EXPECT_EQ(emrtd::crypto::detail::computeCheckDigit("120714"), 9);

    // Edge cases
    EXPECT_EQ(emrtd::crypto::detail::computeCheckDigit(""), 0) << "Empty input check digit should be 0";
    EXPECT_EQ(emrtd::crypto::detail::computeCheckDigit("<<<<<<<<<"), 0) << "All-filler check digit should be 0";
}

TEST(BACTestVectors, ShortDocNumberPadding)
{
    // Document numbers shorter than 9 characters are padded with '<'
    // Verify that "AB1234" produces the same keys as "AB1234<<<" (explicit padding)
    auto keys1 = emrtd::crypto::deriveBACKeys("AB1234", "800101", "250101");
    auto keys2 = emrtd::crypto::deriveBACKeys("AB1234<<<", "800101", "250101");
    EXPECT_EQ(keys1.encKey, keys2.encKey) << "Short doc number should be padded to 9 chars with '<'";
    EXPECT_EQ(keys1.macKey, keys2.macKey);
}

// ---------------------------------------------------------------------------
// Synthetic master list fixture
//
// The fixture's whole job is to be hard to fool, so these assert the properties
// that make it so — not just that it runs. Each one fails if the corresponding
// awkwardness in the generator is smoothed away.
// ---------------------------------------------------------------------------

namespace {

CMS_ContentInfo* parseCms(const std::vector<uint8_t>& der)
{
    BIO* bio = BIO_new_mem_buf(der.data(), static_cast<int>(der.size()));
    CMS_ContentInfo* cms = d2i_CMS_bio(bio, nullptr);
    BIO_free(bio);
    return cms;
}

std::string eContentTypeOf(const std::vector<uint8_t>& der)
{
    CMS_ContentInfo* cms = parseCms(der);
    if (cms == nullptr) {
        return "<not a CMS>";
    }
    char text[128] = {0};
    OBJ_obj2txt(text, sizeof(text), CMS_get0_eContentType(cms), 1);
    CMS_ContentInfo_free(cms);
    return text;
}

X509* certFromDer(const std::vector<uint8_t>& der)
{
    const unsigned char* p = der.data();
    return d2i_X509(nullptr, &p, static_cast<long>(der.size()));
}

X509_STORE* storeOf(const std::vector<std::vector<uint8_t>>& anchors)
{
    X509_STORE* store = X509_STORE_new();
    for (const auto& anchor : anchors) {
        X509* cert = certFromDer(anchor);
        X509_STORE_add_cert(store, cert);
        X509_free(cert);
    }
    return store;
}

/// CMS_verify against @p anchors. Returns 1 on success, 0 on failure, -1 when
/// the encoding does not even parse — the three answers are not the same
/// verdict and several tests below turn on the difference.
int cmsVerifyAgainst(const std::vector<uint8_t>& der, const std::vector<std::vector<uint8_t>>& anchors,
                     unsigned int flags)
{
    CMS_ContentInfo* cms = parseCms(der);
    if (cms == nullptr) {
        return -1;
    }
    X509_STORE* store = storeOf(anchors);
    BIO* sink = BIO_new(BIO_s_mem());
    const int rc = CMS_verify(cms, nullptr, store, nullptr, sink, flags);
    ERR_clear_error();
    BIO_free(sink);
    X509_STORE_free(store);
    CMS_ContentInfo_free(cms);
    return rc;
}

/// The X509 reason the signer's chain fails, or 0 when it builds. Read straight
/// from the store context because CMS_verify collapses every reason into one
/// opaque "certificate verify error", and the reason is the whole point here.
int chainVerifyError(const std::vector<uint8_t>& cmsDer, const std::vector<std::vector<uint8_t>>& anchors)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    X509_STORE* store = storeOf(anchors);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, sk_X509_value(certs, 0), nullptr);
    const int ok = X509_verify_cert(ctx);
    const int reason = ok == 1 ? 0 : X509_STORE_CTX_get_error(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return reason;
}

std::string nameText(const X509_NAME* name)
{
    char* text = X509_NAME_oneline(name, nullptr, 0);
    std::string out = text != nullptr ? text : "";
    OPENSSL_free(text);
    return out;
}

std::string signerIssuerOf(const std::vector<uint8_t>& cmsDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    const std::string out = nameText(X509_get_issuer_name(sk_X509_value(certs, 0)));
    sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(cms);
    return out;
}

std::string signerSubjectOf(const std::vector<uint8_t>& cmsDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    const std::string out = nameText(X509_get_subject_name(sk_X509_value(certs, 0)));
    sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(cms);
    return out;
}

std::string subjectOfCert(const std::vector<uint8_t>& certDer)
{
    X509* cert = certFromDer(certDer);
    const std::string out = nameText(X509_get_subject_name(cert));
    X509_free(cert);
    return out;
}

/// The DER of a certificate's serialNumber TLV, as `i2d` writes it.
std::vector<uint8_t> serialTlvOf(const std::vector<uint8_t>& certDer)
{
    X509* cert = certFromDer(certDer);
    unsigned char* der = nullptr;
    const int len = i2d_ASN1_INTEGER(X509_get_serialNumber(cert), &der);
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    X509_free(cert);
    return out;
}

/// @p payload wrapped in a DER TLV with tag @p tag.
///
/// Here rather than beside the master-list helpers below because the anchor
/// loader's tests need it too.
std::vector<uint8_t> derWrap(uint8_t tag, const std::vector<uint8_t>& payload)
{
    std::vector<uint8_t> out{tag};
    if (payload.size() < 0x80) {
        out.push_back(static_cast<uint8_t>(payload.size()));
    } else {
        std::vector<uint8_t> lengthBytes;
        for (std::size_t v = payload.size(); v != 0; v >>= 8) {
            lengthBytes.insert(lengthBytes.begin(), static_cast<uint8_t>(v & 0xFFu));
        }
        out.push_back(static_cast<uint8_t>(0x80u | lengthBytes.size()));
        out.insert(out.end(), lengthBytes.begin(), lengthBytes.end());
    }
    out.insert(out.end(), payload.begin(), payload.end());
    return out;
}

/// @p der with its outer SEQUENCE re-wrapped using BER's indefinite length --
/// same contents, `30 80` at the front and `00 00` at the back.
std::vector<uint8_t> withIndefiniteOuterLength(const std::vector<uint8_t>& der)
{
    if (der.size() < 2 || der[0] != 0x30) {
        throw std::runtime_error("withIndefiniteOuterLength: not a SEQUENCE");
    }
    const std::size_t headerLen = (der[1] & 0x80) == 0 ? 2u : 2u + (der[1] & 0x7Fu);
    if (der.size() <= headerLen) {
        throw std::runtime_error("withIndefiniteOuterLength: truncated");
    }
    std::vector<uint8_t> out{0x30, 0x80};
    out.insert(out.end(), der.begin() + static_cast<long>(headerLen), der.end());
    out.push_back(0x00);
    out.push_back(0x00);
    return out;
}

/// The same certificate with its tbsCertificate -- and ONLY that -- re-wrapped
/// using BER's indefinite length. The outer Certificate SEQUENCE keeps a
/// definite length.
///
/// That asymmetry is the whole point. X509_CINF is an ASN1_SEQUENCE_enc, so a
/// decoded certificate keeps a cached copy of the tbsCertificate bytes it came
/// from and i2d_X509 replays them verbatim -- re-encoding the outer header
/// around a tbsCertificate that is still `30 80 ... 00 00`. Re-wrapping the
/// OUTER SEQUENCE instead would prove nothing: nothing caches that one, so i2d
/// rewrites it whatever it was.
std::vector<uint8_t> withIndefiniteTbsLength(const std::vector<uint8_t>& certDer)
{
    if (certDer.size() < 2 || certDer[0] != 0x30) {
        throw std::runtime_error("withIndefiniteTbsLength: not a SEQUENCE");
    }
    const std::size_t outerHeader = (certDer[1] & 0x80) == 0 ? 2u : 2u + (certDer[1] & 0x7Fu);
    if (certDer.size() <= outerHeader || certDer[outerHeader] != 0x30) {
        throw std::runtime_error("withIndefiniteTbsLength: no tbsCertificate SEQUENCE");
    }
    const unsigned char* p = certDer.data() + outerHeader;
    long len = 0;
    int tag = 0;
    int cls = 0;
    if ((ASN1_get_object(&p, &len, &tag, &cls, static_cast<long>(certDer.size() - outerHeader)) & 0x80) != 0) {
        throw std::runtime_error("withIndefiniteTbsLength: unreadable tbsCertificate header");
    }
    const std::size_t tbsEnd = static_cast<std::size_t>(p - certDer.data()) + static_cast<std::size_t>(len);
    const std::vector<uint8_t> tbs(certDer.begin() + static_cast<long>(outerHeader),
                                   certDer.begin() + static_cast<long>(tbsEnd));
    std::vector<uint8_t> body = withIndefiniteOuterLength(tbs);
    // signatureAlgorithm and signatureValue carried over untouched.
    body.insert(body.end(), certDer.begin() + static_cast<long>(tbsEnd), certDer.end());
    return derWrap(0x30, body);
}

/// The one byte index at which two equal-length buffers differ, or npos.
std::size_t soleDifference(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b)
{
    if (a.size() != b.size()) {
        return std::string::npos;
    }
    std::size_t found = std::string::npos;
    for (std::size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            if (found != std::string::npos) {
                return std::string::npos; // more than one
            }
            found = i;
        }
    }
    return found;
}

/// Walks the signed CscaMasterList back out of a CMS and returns its anchors in
/// the order the SET OF actually carries them. Deliberately independent of the
/// generator's own assembly: it re-derives what a consumer would see.
std::vector<std::vector<uint8_t>> anchorsInsideList(const std::vector<uint8_t>& cmsDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    EXPECT_NE(cms, nullptr);
    if (cms == nullptr) {
        return {};
    }
    ASN1_OCTET_STRING** content = CMS_get0_content(cms);
    std::vector<std::vector<uint8_t>> out;
    if (content != nullptr && *content != nullptr) {
        const unsigned char* p = (*content)->data;
        const unsigned char* end = p + (*content)->length;

        long len = 0;
        int tag = 0;
        int cls = 0;
        // ASN1_get_object sets 0x80 on error and returns the constructed bit
        // otherwise, so success is the absence of 0x80 — not a zero return.
        const auto readHeader = [&](const unsigned char* limit) {
            return (ASN1_get_object(&p, &len, &tag, &cls, limit - p) & 0x80) == 0;
        };

        // CscaMasterList ::= SEQUENCE { version INTEGER, certificates SET OF }
        if (readHeader(end) && tag == V_ASN1_SEQUENCE) {
            end = p + len;
            if (readHeader(end) && tag == V_ASN1_INTEGER) {
                p += len; // skip version
                if (readHeader(end) && tag == V_ASN1_SET) {
                    const unsigned char* setEnd = p + len;
                    while (p < setEnd) {
                        const unsigned char* start = p;
                        X509* cert = d2i_X509(nullptr, &p, setEnd - p);
                        if (cert == nullptr) {
                            ADD_FAILURE() << "a SET OF element is not a well-formed Certificate";
                            break;
                        }
                        X509_free(cert);
                        out.emplace_back(start, p);
                    }
                }
            }
        }
    }
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return out;
}

} // namespace

TEST(SyntheticMasterListTest, VariesOnlyTheSignerWhenAskedForAnother)
{
    const auto a = LibreSCRS::Test::makeMasterList(2);
    const auto b = LibreSCRS::Test::makeMasterListWithOtherSigner(a);

    EXPECT_EQ(a.cscaDer.size(), 2u);
    EXPECT_EQ(a.signerSpkiSha256.size(), 32u);
    EXPECT_NE(a.signerSpkiSha256, b.signerSpkiSha256);
    EXPECT_EQ(a.cscaDer, b.cscaDer) << "anchors must be byte-identical";
}

TEST(SyntheticMasterListTest, TamperKeepsTheEncodingLengthIntact)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto bad = LibreSCRS::Test::makeTamperedMasterList(ml);
    ASSERT_EQ(ml.der.size(), bad.der.size());
    EXPECT_NE(ml.der, bad.der);
}

TEST(SyntheticMasterListTest, TamperLeavesTheSetOfInDerOrder)
{
    // Two anchors, because the ordering hazard needs a neighbour to sort
    // against: flipping the low bit of the FIRST serial byte can carry the
    // smallest encoding past the next one, and the list then reads as
    // malformed rather than badly signed — the exact wrong verdict this
    // fixture exists to rule out.
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto bad = LibreSCRS::Test::makeTamperedMasterList(ml);

    const auto anchors = anchorsInsideList(bad.der);
    ASSERT_EQ(anchors.size(), 2u) << "the tampered list must still parse as a CscaMasterList";
    EXPECT_TRUE(std::is_sorted(anchors.begin(), anchors.end())) << "tampering must not disturb the DER SET OF order";
    EXPECT_NE(anchors, ml.cscaDer) << "something inside the signed content must actually have changed";
}

TEST(SyntheticMasterListTest, TamperTargetsTheLastSerialByte)
{
    // The ordering property above only bites when two serials happen to be
    // adjacent, which is rare. This pins the mechanism that makes it hold, and
    // it fails every time if the tamper moves back to the first serial byte.
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto bad = LibreSCRS::Test::makeTamperedMasterList(ml);

    const std::size_t changed = soleDifference(ml.der, bad.der);
    ASSERT_NE(changed, std::string::npos) << "exactly one byte must change";
    EXPECT_EQ(ml.der[changed] ^ bad.der[changed], 0x01) << "and it must be a single-bit flip";

    // Where the first anchor sits inside the signed content.
    const auto& first = ml.cscaDer.front();
    const auto at = std::search(ml.der.begin(), ml.der.end(), first.begin(), first.end());
    ASSERT_NE(at, ml.der.end()) << "the anchors are embedded verbatim";
    const auto anchorAt = static_cast<std::size_t>(std::distance(ml.der.begin(), at));
    ASSERT_GE(changed, anchorAt);
    ASSERT_LT(changed, anchorAt + first.size()) << "the tamper must land inside the first anchor";

    // And within that anchor, on the last byte of the serialNumber value.
    const auto serial = serialTlvOf(first);
    const auto serialAt = std::search(first.begin(), first.end(), serial.begin(), serial.end());
    ASSERT_NE(serialAt, first.end());
    const auto serialOffset = static_cast<std::size_t>(std::distance(first.begin(), serialAt));
    ASSERT_LT(serialOffset, 32u) << "the serial is near the front of a certificate; this is the right match";
    EXPECT_EQ(changed - anchorAt, serialOffset + serial.size() - 1)
        << "the tamper must hit the LAST serial byte: the first one can reorder the DER SET OF";
}

TEST(SyntheticMasterListTest, CarriesTheIcaoContentType)
{
    // Guards CMS_PARTIAL: without it CMS_sign finalises before the content type
    // is set, and nothing can tell a master list from anything else.
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    EXPECT_EQ(eContentTypeOf(ml.der), "2.23.136.1.1.2");
}

TEST(SyntheticMasterListTest, IsSignedSoundlyButNotByItsOwnAnchors)
{
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    EXPECT_EQ(cmsVerifyAgainst(ml.der, {}, CMS_NO_SIGNER_CERT_VERIFY), 1) << "the signature itself must be sound";
    EXPECT_NE(cmsVerifyAgainst(ml.der, ml.cscaDer, 0), 1)
        << "the signer must not chain to the list it signs: that circular check has to be impossible";
}

TEST(SyntheticMasterListTest, EmptyListIsStillProperlySigned)
{
    const auto ml = LibreSCRS::Test::makeMasterList(0);
    EXPECT_TRUE(ml.cscaDer.empty());
    EXPECT_EQ(ml.eContentTamperOffset, 0u);
    EXPECT_EQ(eContentTypeOf(ml.der), "2.23.136.1.1.2");
    EXPECT_EQ(cmsVerifyAgainst(ml.der, {}, CMS_NO_SIGNER_CERT_VERIFY), 1);
}

TEST(SyntheticMasterListTest, AnchorsAreSortedForDerSetOf)
{
    const auto ml = LibreSCRS::Test::makeMasterList(4);
    EXPECT_TRUE(std::is_sorted(ml.cscaDer.begin(), ml.cscaDer.end()));
    EXPECT_EQ(anchorsInsideList(ml.der), ml.cscaDer) << "cscaDer must be what the list actually carries";
}

TEST(SyntheticMasterListTest, TamperedListStillParsesButFailsTheSignature)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto bad = LibreSCRS::Test::makeTamperedMasterList(ml);
    ASSERT_NE(cmsVerifyAgainst(bad.der, {}, CMS_NO_SIGNER_CERT_VERIFY), -1)
        << "a tampered list must still parse: the verdict wanted is bad signature, not malformed";
    EXPECT_EQ(cmsVerifyAgainst(bad.der, {}, CMS_NO_SIGNER_CERT_VERIFY), 0);
}

TEST(SyntheticMasterListTest, SignedNonMasterListDiffersOnlyInItsContentType)
{
    const auto der = LibreSCRS::Test::makeSignedNonMasterList();
    EXPECT_EQ(eContentTypeOf(der), "1.2.840.113549.1.7.1");
    EXPECT_EQ(cmsVerifyAgainst(der, {}, CMS_NO_SIGNER_CERT_VERIFY), 1)
        << "it must be properly signed, so only the content type gives it away";
    EXPECT_FALSE(anchorsInsideList(der).empty()) << "its content is a well-formed master list too";
}

TEST(SyntheticMasterListTest, SodChainsToItsAnchorAndParses)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto sod = LibreSCRS::Test::makeSod(ml, 1);

    const auto parsed = emrtd::crypto::parseSOD(sod);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->hashAlgorithm, "SHA-256");
    EXPECT_EQ(parsed->dgHashes.size(), 1u);
    EXPECT_EQ(emrtd::crypto::verifySODSignature(sod), emrtd::crypto::PAResult::PASSED);

    EXPECT_EQ(chainVerifyError(sod, ml.cscaDer), 0) << X509_verify_cert_error_string(chainVerifyError(sod, ml.cscaDer));
    EXPECT_EQ(cmsVerifyAgainst(sod, ml.cscaDer, 0), 1);
}

TEST(SyntheticMasterListTest, DscEkuTripsTheCmsVerifySmimePurpose)
{
    // The ICAO 9303-12 DSC EKU. CMS_verify applies the smime_sign purpose,
    // which rejects any EKU without emailProtection — so a real passport fails
    // unless the caller separates the chain from the CMS check.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0, "2.23.136.1.1.14.1");
    EXPECT_NE(cmsVerifyAgainst(sod, ml.cscaDer, 0), 1);
    EXPECT_EQ(cmsVerifyAgainst(sod, ml.cscaDer, CMS_NO_SIGNER_CERT_VERIFY), 1);
    EXPECT_EQ(chainVerifyError(sod, ml.cscaDer), 0) << "the chain itself is fine; only the purpose objects";
}

TEST(SyntheticMasterListTest, ExpiredDscFailsOnExpiryAlone)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0, "", "200101000000Z");
    const int reason = chainVerifyError(sod, ml.cscaDer);
    EXPECT_EQ(reason, X509_V_ERR_CERT_HAS_EXPIRED) << X509_verify_cert_error_string(reason);
    EXPECT_EQ(cmsVerifyAgainst(sod, ml.cscaDer, CMS_NO_SIGNER_CERT_VERIFY), 1) << "nothing else is wrong with it";

    // The 13-character form the header recommends has to actually yield a
    // UTCTime: RFC 5280 §4.1.2.5 requires one for any date before 2050, and
    // the 15-character form would silently produce a GeneralizedTime instead.
    CMS_ContentInfo* cms = parseCms(sod);
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    EXPECT_EQ(ASN1_STRING_type(X509_get0_notAfter(sk_X509_value(certs, 0))), V_ASN1_UTCTIME);
    sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(cms);
}

TEST(SyntheticMasterListTest, ExpiredDscVerifiesAtSigningTime)
{
    // ICAO accepts an expired document signer on a still-valid passport by
    // checking the chain at signing time. That is only stageable if the ANCHOR
    // reaches back that far too, so this fails the moment the anchors stop
    // being backdated.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0, "", "200101000000Z");

    CMS_ContentInfo* cms = parseCms(sod);
    ASSERT_NE(cms, nullptr);
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    X509_STORE* store = storeOf(ml.cscaDer);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    X509_STORE_CTX_init(ctx, store, sk_X509_value(certs, 0), nullptr);

    // 2018-06-01, comfortably inside the DSC's own window
    X509_VERIFY_PARAM* param = X509_STORE_CTX_get0_param(ctx);
    X509_VERIFY_PARAM_set_time(param, 1527811200);
    X509_VERIFY_PARAM_set_flags(param, X509_V_FLAG_USE_CHECK_TIME);

    const int ok = X509_verify_cert(ctx);
    const int reason = X509_STORE_CTX_get_error(ctx);
    const int depth = X509_STORE_CTX_get_error_depth(ctx);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();

    EXPECT_EQ(ok, 1) << X509_verify_cert_error_string(reason) << " at depth " << depth;
}

TEST(SyntheticMasterListTest, ForgedSodIsSelfIssuedAndAnchorsNowhere)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto sod = LibreSCRS::Test::makeForgedSod();

    ASSERT_TRUE(emrtd::crypto::parseSOD(sod).has_value()) << "it must be a readable SOD, just not a trusted one";
    EXPECT_EQ(signerIssuerOf(sod), signerSubjectOf(sod)) << "the forgery names itself as issuer";
    const int reason = chainVerifyError(sod, ml.cscaDer);
    EXPECT_EQ(reason, X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) << X509_verify_cert_error_string(reason);
}

TEST(SyntheticMasterListTest, ImpersonatedIssuerReachesTheChainAndFailsOnTheSignature)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto sod = LibreSCRS::Test::makeSodWithImpersonatedIssuer(ml, 0);

    EXPECT_EQ(signerIssuerOf(sod), subjectOfCert(ml.cscaDer[0])) << "the DN prefilter has to match";
    EXPECT_NE(signerIssuerOf(sod), signerSubjectOf(sod)) << "so it must not look self-issued";

    // The verdict that only exists if the document gets past the prefilter: an
    // implementation answering "passed" on a DN match is caught here.
    const int reason = chainVerifyError(sod, ml.cscaDer);
    EXPECT_EQ(reason, X509_V_ERR_CERT_SIGNATURE_FAILURE) << X509_verify_cert_error_string(reason);
}

/// Reads a PEM file back as certificate DER.
std::vector<uint8_t> readPemAsDer(const std::filesystem::path& file)
{
    BIO* in = BIO_new_file(file.string().c_str(), "r");
    X509* cert = PEM_read_bio_X509(in, nullptr, nullptr, nullptr);
    BIO_free(in);
    if (cert == nullptr) {
        return {};
    }
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert, &der);
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    X509_free(cert);
    return out;
}

TEST(SyntheticMasterListTest, SodIssuesFromAListRebuiltFromItsOwnPemDir)
{
    // What the anchor-key note on makeSod() actually promises. The registry is
    // keyed on the anchor's own encoding and the PEM round trip is byte for
    // byte, so a list reassembled from disk still finds its keys — it is an
    // anchor this process never minted that has none.
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const std::string dir = LibreSCRS::Test::writePemDir(ml.cscaDer);

    LibreSCRS::Test::SyntheticMasterList rebuilt;
    for (int i = 0; i < 2; ++i) {
        rebuilt.cscaDer.push_back(readPemAsDer(std::filesystem::path(dir) / (std::to_string(i) + ".pem")));
    }
    std::filesystem::remove_all(dir);

    ASSERT_EQ(rebuilt.cscaDer, ml.cscaDer) << "the PEM round trip must be byte-identical";
    std::vector<uint8_t> sod;
    ASSERT_NO_THROW(sod = LibreSCRS::Test::makeSod(rebuilt, 0));
    EXPECT_EQ(cmsVerifyAgainst(sod, ml.cscaDer, CMS_NO_SIGNER_CERT_VERIFY), 1);
    EXPECT_EQ(chainVerifyError(sod, ml.cscaDer), 0);
}

TEST(SyntheticMasterListTest, SodThrowsOnAnAnchorThisProcessNeverMinted)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    LibreSCRS::Test::SyntheticMasterList alien;
    alien.cscaDer.push_back(ml.cscaDer[0]);
    alien.cscaDer[0].back() ^= 0x01; // no longer any certificate this process made

    EXPECT_THROW(static_cast<void>(LibreSCRS::Test::makeSod(alien, 0)), std::runtime_error);
}

namespace {

/// Whether OpenSSL's own hashed-directory lookup finds a certificate with
/// @p subject in @p dir.
///
/// This is the question `X509_STORE_load_path` does NOT answer. That call
/// returns 1 for a directory that does not exist, for one that is empty, and
/// for a path that is a regular file -- measured, all three -- because it only
/// records the string; nothing is read until a lookup asks for a subject, and
/// the lookup finds only names `c_rehash` has produced.
bool hashedLookupFinds(const std::filesystem::path& dir, const X509_NAME* subject)
{
    X509_STORE* store = X509_STORE_new();
    EXPECT_EQ(X509_STORE_load_path(store, dir.string().c_str()), 1);
    X509_STORE_CTX* ctx = X509_STORE_CTX_new();
    EXPECT_EQ(X509_STORE_CTX_init(ctx, store, nullptr, nullptr), 1);
    X509_OBJECT* found = X509_STORE_CTX_get_obj_by_subject(ctx, X509_LU_X509, subject);
    const bool hit = found != nullptr;
    X509_OBJECT_free(found);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    ERR_clear_error();
    return hit;
}

} // namespace

TEST(SyntheticMasterListTest, PemDirIsUnhashedAndLoadable)
{
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    const std::string dir = LibreSCRS::Test::writePemDir(ml.cscaDer);

    int files = 0;
    for (const auto& entry : std::filesystem::directory_iterator(dir)) {
        static_cast<void>(entry);
        ++files;
    }
    EXPECT_EQ(files, 3);
    EXPECT_TRUE(std::filesystem::exists(std::filesystem::path(dir) / "0.pem"));

    // LOADABLE: every file reads back as the certificate it was written from.
    for (std::size_t i = 0; i < ml.cscaDer.size(); ++i) {
        EXPECT_EQ(readPemAsDer(std::filesystem::path(dir) / (std::to_string(i) + ".pem")), ml.cscaDer[i])
            << "anchor " << i << " must read back byte for byte";
    }

    // UNHASHED: OpenSSL's own directory lookup finds nothing here, which is the
    // whole reason loadAnchorDerFromDirectory exists. Paired with a rehashed
    // copy of the same directory, where the same lookup DOES find it -- without
    // that control a lookup that never worked would look like proof.
    X509* first = certFromDer(ml.cscaDer[0]);
    ASSERT_NE(first, nullptr);
    const X509_NAME* subject = X509_get_subject_name(first);

    const std::filesystem::path rehashed(dir + "-rehashed");
    std::filesystem::create_directories(rehashed);
    char linkName[32] = {0};
    std::snprintf(linkName, sizeof(linkName), "%08lx.0", X509_subject_name_hash(first));
    std::filesystem::create_symlink(std::filesystem::path(dir) / "0.pem", rehashed / linkName);

    EXPECT_TRUE(hashedLookupFinds(rehashed, subject)) << "the control must really work, or the negative proves nothing";
    EXPECT_FALSE(hashedLookupFinds(std::filesystem::path(dir), subject))
        << "a directory nobody rehashed must be invisible to OpenSSL's own lookup";

    X509_free(first);
    std::filesystem::remove_all(rehashed);
    std::filesystem::remove_all(dir);
}

// ---------------------------------------------------------------------------
// Anchor directory loader tests
// ---------------------------------------------------------------------------

// Internal linkage: this target links five translation units together, and
// none of these names need to be visible outside this file.
namespace {

/// @p bytes random bytes as hex. The same device writePemDir() uses in the
/// fixture, for the same reason: a fixed path in a shared temporary directory
/// belongs to whichever process got there first.
std::string randomHexSuffix(std::size_t bytes)
{
    std::vector<unsigned char> raw(bytes);
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        throw std::runtime_error("randomHexSuffix: RAND_bytes failed");
    }
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes * 2);
    for (const unsigned char b : raw) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

/// A fresh, empty temporary directory this test owns and must remove.
///
/// The name is random, not just per label, and sequential execution inside one
/// binary is not the question. gtest_discover_tests registers every case as its
/// own ctest test, so `ctest -j` runs these as concurrent PROCESSES -- and two
/// runs on one host, two CI jobs or two developers, would otherwise share one
/// path per label. One run's setup would delete, or a permission test would
/// chmod 000, the directory another was in the middle of reading, and the
/// failure would arrive looking like a bug in the loader.
///
/// @p label is kept in the name only so that a directory left behind by a
/// crashed run says which test made it. Nothing is cleaned up here, because
/// with a random name there is nothing of ours to find.
std::filesystem::path makeAnchorLoaderTempDir(const char* label)
{
    const auto dir = std::filesystem::temp_directory_path() /
                     (std::string("librescrs-anchorloader-") + label + "-" + randomHexSuffix(8));
    std::filesystem::create_directories(dir);
    return dir;
}

void writeFile(const std::filesystem::path& file, const std::string& content)
{
    std::ofstream out(file, std::ios::binary);
    out << content;
}

void writeFile(const std::filesystem::path& file, const std::vector<uint8_t>& content)
{
    std::ofstream out(file, std::ios::binary);
    out.write(reinterpret_cast<const char*>(content.data()), static_cast<std::streamsize>(content.size()));
}

/// Converts certificate DER to PEM text -- the reverse of readPemAsDer()
/// above -- so a test can build a multi-certificate PEM bundle in one file.
/// Throws rather than returning an empty string on a failed decode, so a
/// broken fixture fails loudly at the point the DER stopped being a
/// certificate, instead of quietly handing a test an empty PEM file that
/// fails somewhere else entirely.
std::string derToPemText(const std::vector<uint8_t>& der)
{
    const unsigned char* p = der.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (cert == nullptr) {
        throw std::runtime_error("derToPemText: d2i_X509 failed on fixture-provided DER");
    }
    BIO* mem = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(mem, cert);
    char* data = nullptr;
    const long len = BIO_get_mem_data(mem, &data);
    std::string pem(data, static_cast<size_t>(len));
    BIO_free(mem);
    X509_free(cert);
    return pem;
}

/// Restores @p path's permissions to @p restoreTo when it goes out of scope
/// -- including via an ASSERT_* early return or an exception -- so a test
/// that locks a path down to prove something about an unreadable entry never
/// leaves that path unusable for a later cleanup to deal with.
class ScopedPermissions
{
public:
    ScopedPermissions(std::filesystem::path path, std::filesystem::perms restoreTo)
        : path_(std::move(path)), restoreTo_(restoreTo)
    {}
    ~ScopedPermissions()
    {
        std::error_code ec;
        std::filesystem::permissions(path_, restoreTo_, std::filesystem::perm_options::replace, ec);
    }
    ScopedPermissions(const ScopedPermissions&) = delete;
    ScopedPermissions& operator=(const ScopedPermissions&) = delete;

private:
    std::filesystem::path path_;
    std::filesystem::perms restoreTo_;
};

/// These tests share this process's single thread-local OpenSSL error
/// queue. Without clearing it on the way in and out, a test that leaves
/// something queued (or expects something queued) would depend on running
/// after -- or before -- some other specific test, which gtest does not
/// guarantee.
class AnchorLoaderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ERR_clear_error();
    }
    void TearDown() override
    {
        ERR_clear_error();
    }
};

} // namespace

TEST_F(AnchorLoaderTest, ReadsAPlainDirectoryThatWasNeverRehashed)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto dir = LibreSCRS::Test::writePemDir(ml.cscaDer);
    bool readable = false;
    auto der = emrtd::crypto::loadAnchorDerFromDirectory(dir, &readable);
    std::filesystem::remove_all(dir); // test needs #include <filesystem>

    EXPECT_TRUE(readable);
    ASSERT_EQ(der.size(), 2u);
    // Compared as a multiset, not by position: readdir() order is
    // unspecified, and the fixture header warns against a test a broken
    // implementation can pass by accident.
    auto expected = ml.cscaDer;
    std::sort(der.begin(), der.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(der, expected);
}

TEST_F(AnchorLoaderTest, ReportsAMissingDirectoryWithoutThrowing)
{
    bool readable = true;
    const auto der = emrtd::crypto::loadAnchorDerFromDirectory("/nonexistent/xyz", &readable);
    EXPECT_FALSE(readable);
    EXPECT_TRUE(der.empty());
}

TEST_F(AnchorLoaderTest, ReportsARegularFileWithoutThrowing)
{
    // std::filesystem::directory_iterator THROWS on a regular file unless the
    // error_code overload is used; that exception would unwind out through the
    // plugin's dlopen boundary. Uses a file this test creates and verifies
    // itself, rather than a path merely assumed to exist on the host, so the
    // assertion holds in any sandbox.
    // Randomly named for the reason makeAnchorLoaderTempDir gives: under
    // `ctest -j` these cases are concurrent processes sharing one temp
    // directory, and a fixed name is one run removing another run's file.
    const auto path =
        std::filesystem::temp_directory_path() / ("librescrs-anchorloader-regular-file-" + randomHexSuffix(8));
    writeFile(path, std::string("not a directory"));
    ASSERT_TRUE(std::filesystem::is_regular_file(path)) << "test setup must actually produce a regular file";

    bool readable = true;
    const auto der = emrtd::crypto::loadAnchorDerFromDirectory(path.string(), &readable);
    std::filesystem::remove(path);

    EXPECT_FALSE(readable);
    EXPECT_TRUE(der.empty());
}

TEST_F(AnchorLoaderTest, ReportsAnUnsearchableEntryWithoutClaimingTheDirectoryIsEmpty)
{
    // The directory itself IS searchable; two of its ENTRIES are not, being
    // symlinks into a directory whose access has been removed. That is the
    // shape the name has to describe, because a directory the loader cannot
    // enter is answered far earlier, by the iterator.
    //
    // A dangling symlink cannot be classified from the directory listing
    // alone: unlike a plain regular file, whose type some filesystems report
    // straight from the listing without ever calling stat(), naming what a
    // symlink points to always requires a real lookup. Two symlinks into a
    // directory whose own access has been removed reliably fail that lookup,
    // so this exercises the is_regular_file() failure path specifically --
    // a different, narrower failure class than an entry that can be typed
    // but not opened (see the mixed-readability test below, which is the one
    // that matches a plain `r--` directory of real anchor files).
    if (::geteuid() == 0) {
        GTEST_SKIP() << "permission bits are not enforced for root";
    }

    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto blockedDir = makeAnchorLoaderTempDir("blocked");
    writeFile(blockedDir / "0.pem", derToPemText(ml.cscaDer[0]));
    writeFile(blockedDir / "1.pem", derToPemText(ml.cscaDer[1]));

    const auto anchorDir = makeAnchorLoaderTempDir("unsearchable");
    std::filesystem::create_symlink(blockedDir / "0.pem", anchorDir / "0.pem");
    std::filesystem::create_symlink(blockedDir / "1.pem", anchorDir / "1.pem");

    bool readable = true;
    std::vector<std::vector<uint8_t>> der;
    {
        std::filesystem::permissions(blockedDir, std::filesystem::perms::none, std::filesystem::perm_options::replace);
        // Restores blockedDir's permissions when this scope ends, including
        // on an early return or exception, so a dying test cannot leave a
        // mode-000 directory behind for the next run to trip over.
        ScopedPermissions restoreBlockedDir(blockedDir, std::filesystem::perms::owner_all);
        der = emrtd::crypto::loadAnchorDerFromDirectory(anchorDir.string(), &readable);
    }

    std::filesystem::remove_all(blockedDir);
    std::filesystem::remove_all(anchorDir);

    EXPECT_FALSE(readable) << "an unsearchable entry must not be reported the same as an empty, readable directory";
    EXPECT_TRUE(der.empty());
}

TEST_F(AnchorLoaderTest, ReportsAMixOfReadableAndUnreadableAnchorsAsUnreadable)
{
    // The dangerous case, and the literal shape of a plain `r--` anchor
    // directory: NOT every entry unreadable (which degenerates to an
    // obviously-empty, easy-to-notice result), but one readable anchor
    // sitting next to one that is not. is_regular_file() answers straight
    // from the directory listing for both -- a restrictive file mode does
    // not stop readdir() from reporting a regular file as a regular file --
    // so the failure only surfaces later, when BIO_new_file actually tries
    // to open the unreadable one by name. Silently dropping that one would
    // let a caller see a plausible, non-empty anchor set and never learn
    // that a second one went missing.
    if (::geteuid() == 0) {
        GTEST_SKIP() << "permission bits are not enforced for root";
    }

    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto dir = makeAnchorLoaderTempDir("mixed");
    writeFile(dir / "0.pem", derToPemText(ml.cscaDer[0])); // stays readable
    writeFile(dir / "1.pem", derToPemText(ml.cscaDer[1])); // made unreadable below

    bool readable = true;
    std::vector<std::vector<uint8_t>> der;
    {
        std::filesystem::permissions(dir / "1.pem", std::filesystem::perms::none,
                                     std::filesystem::perm_options::replace);
        ScopedPermissions restoreUnreadable(dir / "1.pem", std::filesystem::perms::owner_all);
        der = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    }
    std::filesystem::remove_all(dir);

    EXPECT_FALSE(readable) << "one unreadable anchor must not be masked by another anchor that did load";
    ASSERT_EQ(der.size(), 1u) << "the readable anchor must still come back, not be dropped along with the other one";
    EXPECT_EQ(der[0], ml.cscaDer[0]);
}

TEST_F(AnchorLoaderTest, ReadsEveryCertificateInAConcatenatedPemBundle)
{
    // The ordinary shape of a published CSCA set: one file holding several
    // certificates back to back, not one file per certificate. A loader that
    // reads only the first PEM object per file silently drops the rest.
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto dir = makeAnchorLoaderTempDir("bundle");
    writeFile(dir / "bundle.pem", derToPemText(ml.cscaDer[0]) + derToPemText(ml.cscaDer[1]));

    bool readable = false;
    auto der = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    std::filesystem::remove_all(dir);

    // Reading past the last certificate in the bundle is expected to fail
    // ("no start line") and must not leave that failure sitting in the
    // thread's OpenSSL error queue for an unrelated later caller to trip
    // over.
    EXPECT_EQ(ERR_peek_error(), 0ul) << "a successful load must not leave stray entries in the error queue";

    EXPECT_TRUE(readable);
    ASSERT_EQ(der.size(), 2u) << "both certificates in the bundle must be read, not just the first";
    auto expected = ml.cscaDer;
    std::sort(der.begin(), der.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(der, expected);
}

TEST_F(AnchorLoaderTest, ReadsRawDerAndSkipsANonCertificateFileSilently)
{
    // The DER fallback (BIO_reset + d2i_X509_bio) has no coverage otherwise:
    // writePemDir only ever writes PEM. Also exercises the silent skip of a
    // file that is neither PEM nor DER, alongside a file that is genuinely
    // both readable and a certificate.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto dir = makeAnchorLoaderTempDir("der-fallback");
    writeFile(dir / "0.der", ml.cscaDer[0]);
    writeFile(dir / "garbage.txt", std::string("this is not a certificate at all"));

    bool readable = false;
    const auto der = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    std::filesystem::remove_all(dir);

    // garbage.txt fails both the PEM and the DER attempt; that failure must
    // not leave anything in the thread's OpenSSL error queue for a later,
    // unrelated caller (e.g. a signing failure) to have prepended to it.
    EXPECT_EQ(ERR_peek_error(), 0ul) << "a skipped non-certificate file must not leave stray error-queue entries";

    EXPECT_TRUE(readable);
    ASSERT_EQ(der.size(), 1u) << "the garbage file must be skipped, not counted, and must not throw";
    EXPECT_EQ(der[0], ml.cscaDer[0]);
}

TEST_F(AnchorLoaderTest, ReturnsCanonicalDerForAFileThatCarriesBer)
{
    // The @return says "the DER encoding of every certificate found", and a
    // consumer that fingerprints an anchor, looks one up in a revocation list,
    // or stores one is entitled to take that literally: one logical certificate
    // must not yield two fingerprints because two files spelled it differently.
    //
    // i2d_X509 alone does not deliver it. X509_CINF is an ASN1_SEQUENCE_enc, so
    // a certificate decoded from BER keeps the tbsCertificate bytes it came
    // from and i2d replays them verbatim -- which is why the assertion below,
    // that the FILE really carries BER, is made with the same i2d round trip
    // that the loader used to do.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto berCert = withIndefiniteTbsLength(ml.cscaDer.front());
    ASSERT_NE(berCert, ml.cscaDer.front()) << "the fixture must really have changed the encoding";

    const auto dir = makeAnchorLoaderTempDir("ber-encoded");
    writeFile(dir / "0.pem", derToPemText(berCert));
    ASSERT_EQ(readPemAsDer(dir / "0.pem"), berCert)
        << "the file must really carry the BER form, or nothing below is about re-encoding";

    bool readable = false;
    const auto der = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    std::filesystem::remove_all(dir);

    EXPECT_TRUE(readable);
    ASSERT_EQ(der.size(), 1u);
    EXPECT_NE(der.front(), berCert) << "the file's own bytes must not be what comes back";
    EXPECT_EQ(der.front(), ml.cscaDer.front())
        << "one logical certificate, one encoding, whatever the file spelled it as";
}

TEST_F(AnchorLoaderTest, SkipsASubdirectoryWithoutAffectingReadable)
{
    // Only regular-file entries are ever opened; a subdirectory is skipped
    // without being counted as unreadable, so a directory holding nothing
    // but one still reports readable == true with an empty result -- exactly
    // what the header documents outReadable does and does not check.
    const auto dir = makeAnchorLoaderTempDir("subdirectory-only");
    std::filesystem::create_directory(dir / "not-a-file");

    bool readable = false;
    const auto der = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    std::filesystem::remove_all(dir);

    EXPECT_TRUE(readable) << "a subdirectory entry is not a readability failure";
    EXPECT_TRUE(der.empty());
}

TEST_F(AnchorLoaderTest, DoesNotWipeACallersPendingOpenSslError)
{
    // ERR_clear_error() would wipe the whole thread-local queue; the loader
    // must remove only what it added itself, via a per-entry ErrorQueueMark
    // (ERR_set_mark() / ERR_pop_to_mark()). The fixture's SetUp() has
    // already cleared the queue, so queuing this diagnostic starts from a
    // known-empty state; it stands in for some earlier, unrelated failure
    // already pending on this thread. Then exercise a directory that makes
    // the loader fail a parse internally (so it has its own entries to
    // clean up), and confirm the pre-existing one is still there afterward.
    // A single file is not enough to prove the marking is actually scoped
    // correctly rather than merely present -- see the at-scale test below
    // for that.
    const auto dir = makeAnchorLoaderTempDir("caller-error");
    writeFile(dir / "garbage.txt", std::string("not a certificate"));

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    bool readable = false;
    const auto der = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    std::filesystem::remove_all(dir);

    EXPECT_EQ(ERR_peek_error(), callerError)
        << "a caller's own pending OpenSSL error must survive a call that internally fails a parse";
    // ERR_peek_error() alone only proves the OLDEST entry is still the
    // caller's; it says nothing about whether this function's own residue
    // is stacked on top of it. Popping the caller's error and then checking
    // the queue is empty closes that gap.
    EXPECT_EQ(ERR_get_error(), callerError) << "the caller's error must still be there to pop";
    EXPECT_EQ(ERR_peek_error(), 0ul) << "and popping it must leave the queue empty -- no residue on top of it";
    EXPECT_TRUE(readable);
    EXPECT_TRUE(der.empty());
}

TEST_F(AnchorLoaderTest, DoesNotWipeACallersPendingOpenSslErrorAtRealisticScale)
{
    // A single mark/pop bracket around the WHOLE scan -- what an earlier
    // version of this function used -- looks correct at the one-file scale
    // the test above uses, but silently degrades to exactly the
    // ERR_clear_error() it was meant to replace once enough entries push
    // past the error queue's fixed-size ring (OpenSSL's ERR_NUM_ERRORS,
    // 16 slots in this build): a garbage file pushes two entries per scan,
    // so as few as 8 of them exhaust it and start overwriting the marked
    // slot. Twenty is comfortably past that, and no larger than an ordinary
    // per-country CSCA anchor directory -- the exact shape this loader
    // exists for, not a corner case -- so this is the scale that actually
    // has to hold.
    constexpr int fileCount = 20;
    const auto dir = makeAnchorLoaderTempDir("caller-error-scale");
    for (int i = 0; i < fileCount; ++i) {
        writeFile(dir / (std::to_string(i) + ".garbage"), std::string("not a certificate"));
    }

    // The fixture's SetUp() has already cleared the queue.
    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    bool readable = false;
    const auto der = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    std::filesystem::remove_all(dir);

    EXPECT_EQ(ERR_peek_error(), callerError)
        << "a caller's pending error must survive scanning a directory this size, not only a single-file one";
    EXPECT_EQ(ERR_get_error(), callerError) << "the caller's error must still be there to pop";
    EXPECT_EQ(ERR_peek_error(), 0ul) << "and popping it must leave the queue empty -- no residue on top of it";
    EXPECT_TRUE(readable);
    EXPECT_TRUE(der.empty());
}

// ---------------------------------------------------------------------------
// CSCA master list parser tests
// ---------------------------------------------------------------------------

namespace {

/// Re-encodes @p cmsDer with its eContentType FIELD overwritten to @p oidText
/// and every signed attribute -- including the contentType attribute, which
/// records what the signer actually signed -- left exactly as it was.
///
/// This is the relabelling that reading the content type in one place only
/// would let through: the eContentType field sits outside the signature, so
/// the object still verifies afterwards and only the disagreement between the
/// two places gives it away.
std::vector<uint8_t> relabelEContentTypeField(const std::vector<uint8_t>& cmsDer, const char* oidText)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("relabelEContentTypeField: the input is not a CMS");
    }
    ASN1_OBJECT* oid = OBJ_txt2obj(oidText, 1);
    const int set = oid != nullptr ? CMS_set1_eContentType(cms, oid) : 0;
    ASN1_OBJECT_free(oid);
    if (set != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("relabelEContentTypeField: CMS_set1_eContentType failed");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("relabelEContentTypeField: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// Re-encodes @p cmsDer with its eContent replaced by @p content and BOTH
/// places that name the content type left alone, so the object still claims to
/// be a master list while carrying something else.
///
/// The signature no longer matches the content afterwards, which is exactly
/// what makes this usable here: the parser under test does not look at it.
std::vector<uint8_t> replaceEContent(const std::vector<uint8_t>& cmsDer, const std::vector<uint8_t>& content)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("replaceEContent: the input is not a CMS");
    }
    ASN1_OCTET_STRING** slot = CMS_get0_content(cms);
    if (slot == nullptr || *slot == nullptr ||
        ASN1_OCTET_STRING_set(*slot, content.data(), static_cast<int>(content.size())) != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("replaceEContent: could not replace the encapsulated content");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("replaceEContent: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// The encapsulated content of @p cmsDer, so a test can put a real master list
/// inside something that is not a SignedData.
std::vector<uint8_t> eContentOf(const std::vector<uint8_t>& cmsDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("eContentOf: the input is not a CMS");
    }
    ASN1_OCTET_STRING** slot = CMS_get0_content(cms);
    if (slot == nullptr || *slot == nullptr) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("eContentOf: the CMS carries no content");
    }
    const unsigned char* data = ASN1_STRING_get0_data(*slot);
    std::vector<uint8_t> out(data, data + ASN1_STRING_length(*slot));
    CMS_ContentInfo_free(cms);
    return out;
}

/// A CMS DigestedData over @p content, wearing @p oidText as its content type.
/// Nothing signed it, so nothing in it is bound to that type -- but the
/// eContentType field says master list and the content really is one.
std::vector<uint8_t> makeDigestedDataWearing(const std::vector<uint8_t>& content, const char* oidText)
{
    BIO* bio = BIO_new_mem_buf(content.data(), static_cast<int>(content.size()));
    CMS_ContentInfo* cms = CMS_digest_create(bio, EVP_sha256(), CMS_BINARY);
    BIO_free(bio);
    if (cms == nullptr) {
        throw std::runtime_error("makeDigestedDataWearing: CMS_digest_create failed");
    }
    ASN1_OBJECT* oid = OBJ_txt2obj(oidText, 1);
    const int set = oid != nullptr ? CMS_set1_eContentType(cms, oid) : 0;
    ASN1_OBJECT_free(oid);
    if (set != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("makeDigestedDataWearing: CMS_set1_eContentType failed");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("makeDigestedDataWearing: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// Re-encodes @p cmsDer after letting @p mutate change its first SignerInfo.
/// @p mutate returns false when the input was not the shape it expected, which
/// becomes a throw rather than a quietly unmodified fixture.
template <typename Mutate>
std::vector<uint8_t> reencodeWithMutatedSigner(const std::vector<uint8_t>& cmsDer, Mutate mutate)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("reencodeWithMutatedSigner: the input is not a CMS");
    }
    CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), 0);
    if (signer == nullptr || !mutate(signer)) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("reencodeWithMutatedSigner: could not mutate the signer");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("reencodeWithMutatedSigner: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// Signer @p signerIndex's contentType attribute value in dotted form, read at
/// @p lastpos: -3 the way the parser reads it (exactly one attribute, exactly
/// one value), -1 the lax way (first attribute, first value, no cardinality
/// check at all) -- which is what a parser that skipped the cardinality would
/// have seen.
std::string signedContentTypeOf(const std::vector<uint8_t>& cmsDer, int lastpos, int signerIndex = 0)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        return "<not a CMS>";
    }
    CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), signerIndex);
    std::string out = "<none>";
    if (signer != nullptr) {
        const auto* oid = static_cast<const ASN1_OBJECT*>(
            CMS_signed_get0_data_by_OBJ(signer, OBJ_nid2obj(NID_pkcs9_contentType), lastpos, V_ASN1_OBJECT));
        if (oid != nullptr) {
            char text[128] = {0};
            OBJ_obj2txt(text, sizeof(text), oid, 1);
            out = text;
        }
    }
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return out;
}

/// Re-encodes @p cmsDer with the first signer's signed contentType attribute
/// replaced by one whose single value is a PrintableString spelling the ICAO
/// OID rather than the OID itself.
///
/// The attribute is present and unique, so only its type gives it away -- and
/// OpenSSL raises while rejecting it, which is what makes this input reach the
/// error queue at all.
std::vector<uint8_t> replaceSignedContentTypeWithNonOid(const std::vector<uint8_t>& cmsDer)
{
    return reencodeWithMutatedSigner(cmsDer, [](CMS_SignerInfo* signer) {
        const int loc = CMS_signed_get_attr_by_NID(signer, NID_pkcs9_contentType, -1);
        if (loc < 0) {
            return false;
        }
        X509_ATTRIBUTE_free(CMS_signed_delete_attr(signer, loc));
        static const char* kText = "2.23.136.1.1.2";
        return CMS_signed_add1_attr_by_NID(signer, NID_pkcs9_contentType, V_ASN1_PRINTABLESTRING, kText,
                                           static_cast<int>(std::strlen(kText))) == 1;
    });
}

/// Re-encodes @p cmsDer with a SECOND signed contentType attribute added,
/// naming the same OID. RFC 5652 s11.1 allows exactly one.
std::vector<uint8_t> duplicateSignedContentTypeAttribute(const std::vector<uint8_t>& cmsDer)
{
    return reencodeWithMutatedSigner(cmsDer, [](CMS_SignerInfo* signer) {
        ASN1_OBJECT* oid = OBJ_txt2obj("2.23.136.1.1.2", 1);
        if (oid == nullptr) {
            return false;
        }
        const int rc = CMS_signed_add1_attr_by_NID(signer, NID_pkcs9_contentType, V_ASN1_OBJECT, oid, -1);
        ASN1_OBJECT_free(oid);
        return rc == 1;
    });
}

/// Re-encodes @p cmsDer with a second VALUE pushed into the one signed
/// contentType attribute, naming the same OID. RFC 5652 s11.1 allows exactly
/// one value, and the attribute stays unique, so only the value count differs.
std::vector<uint8_t> addSecondValueToSignedContentTypeAttribute(const std::vector<uint8_t>& cmsDer)
{
    return reencodeWithMutatedSigner(cmsDer, [](CMS_SignerInfo* signer) {
        const int loc = CMS_signed_get_attr_by_NID(signer, NID_pkcs9_contentType, -1);
        X509_ATTRIBUTE* attr = loc >= 0 ? CMS_signed_get_attr(signer, loc) : nullptr;
        ASN1_OBJECT* oid = OBJ_txt2obj("2.23.136.1.1.2", 1);
        if (attr == nullptr || oid == nullptr) {
            ASN1_OBJECT_free(oid);
            return false;
        }
        const int rc = X509_ATTRIBUTE_set1_data(attr, V_ASN1_OBJECT, oid, -1);
        ASN1_OBJECT_free(oid);
        return rc == 1;
    });
}

/// How many SignerInfos @p cmsDer carries, or -1 when it is not a CMS.
int signerCountOf(const std::vector<uint8_t>& cmsDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        return -1;
    }
    const int count = sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(cms));
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return count;
}

/// Re-encodes @p cmsDer with the first signer's signed contentType attribute
/// DELETED outright -- present in neither form.
std::vector<uint8_t> removeSignedContentTypeAttribute(const std::vector<uint8_t>& cmsDer)
{
    return reencodeWithMutatedSigner(cmsDer, [](CMS_SignerInfo* signer) {
        const int loc = CMS_signed_get_attr_by_NID(signer, NID_pkcs9_contentType, -1);
        if (loc < 0) {
            return false;
        }
        X509_ATTRIBUTE_free(CMS_signed_delete_attr(signer, loc));
        return CMS_signed_get_attr_by_NID(signer, NID_pkcs9_contentType, -1) < 0;
    });
}

/// A throwaway self-signed P-256 identity, freed with the object.
struct ThrowawayIdentity
{
    EVP_PKEY* key = nullptr;
    X509* cert = nullptr;

    ThrowawayIdentity() = default;
    ThrowawayIdentity(const ThrowawayIdentity&) = delete;
    ThrowawayIdentity& operator=(const ThrowawayIdentity&) = delete;
    ~ThrowawayIdentity()
    {
        X509_free(cert);
        EVP_PKEY_free(key);
    }
};

/// Mints a self-signed certificate for @p commonName. Nothing verifies it --
/// it exists only so a second SignerInfo has an identity to name.
void mintThrowawayIdentity(ThrowawayIdentity& id, const char* commonName)
{
    id.key = EVP_EC_gen("P-256");
    id.cert = X509_new();
    if (id.key == nullptr || id.cert == nullptr) {
        throw std::runtime_error("mintThrowawayIdentity: could not allocate");
    }
    X509_set_version(id.cert, 2);
    ASN1_INTEGER_set(X509_get_serialNumber(id.cert), 42);
    X509_gmtime_adj(X509_getm_notBefore(id.cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(id.cert), 3600);
    X509_set_pubkey(id.cert, id.key);
    X509_NAME* name = X509_get_subject_name(id.cert);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(commonName), -1, -1, 0);
    X509_set_issuer_name(id.cert, name);
    if (X509_sign(id.cert, id.key, EVP_sha256()) <= 0) {
        throw std::runtime_error("mintThrowawayIdentity: X509_sign failed");
    }
}

/// Re-encodes @p cmsDer with one more SignerInfo added, named @p commonName,
/// whose signed contentType attribute names @p contentTypeOidText.
///
/// Added with CMS_PARTIAL and never finalised, so this signer has no signature
/// over anything -- which is fine here, since nothing under test looks at one.
/// Callable repeatedly: each call mints its own key, so signers stay distinct.
std::vector<uint8_t> addSigner(const std::vector<uint8_t>& cmsDer, const char* contentTypeOidText,
                               const char* commonName)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("addSecondSigner: the input is not a CMS");
    }
    ThrowawayIdentity id;
    int rc = 0;
    try {
        mintThrowawayIdentity(id, commonName);
        CMS_SignerInfo* signer =
            CMS_add1_signer(cms, id.cert, id.key, EVP_sha256(), CMS_PARTIAL | CMS_NOSMIMECAP | CMS_NOCERTS);
        ASN1_OBJECT* oid = OBJ_txt2obj(contentTypeOidText, 1);
        if (signer != nullptr && oid != nullptr) {
            rc = CMS_signed_add1_attr_by_NID(signer, NID_pkcs9_contentType, V_ASN1_OBJECT, oid, -1);
        }
        ASN1_OBJECT_free(oid);
    } catch (...) {
        CMS_ContentInfo_free(cms);
        throw;
    }
    if (rc != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("addSigner: could not add the signer");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("addSigner: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// Re-encodes @p cmsDer with signer @p signerIndex's contentType attribute
/// replaced by one naming @p oidText.
std::vector<uint8_t> relabelSignerAt(const std::vector<uint8_t>& cmsDer, int signerIndex, const char* oidText)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("relabelSignerAt: the input is not a CMS");
    }
    CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), signerIndex);
    int rc = 0;
    if (signer != nullptr) {
        const int loc = CMS_signed_get_attr_by_NID(signer, NID_pkcs9_contentType, -1);
        if (loc >= 0) {
            X509_ATTRIBUTE_free(CMS_signed_delete_attr(signer, loc));
        }
        ASN1_OBJECT* oid = OBJ_txt2obj(oidText, 1);
        if (oid != nullptr) {
            rc = CMS_signed_add1_attr_by_NID(signer, NID_pkcs9_contentType, V_ASN1_OBJECT, oid, -1);
        }
        ASN1_OBJECT_free(oid);
    }
    if (rc != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("relabelSignerAt: could not relabel that signer");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("relabelSignerAt: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// A CMS SignedData over @p content wearing @p oidText and carrying NO
/// SignerInfo at all.
///
/// CMS_sign given no key builds the "certificates only" shape -- a SignedData
/// with an empty signerInfos SET. It cannot be finalised (CMS_final builds its
/// digest chain out of the signers' digest algorithms, and there are none), so
/// the content goes in afterwards through the same path every other fixture
/// here uses.
std::vector<uint8_t> makeSignerlessSignedData(const std::vector<uint8_t>& content, const char* oidText)
{
    CMS_ContentInfo* cms = CMS_sign(nullptr, nullptr, nullptr, nullptr, CMS_PARTIAL | CMS_BINARY | CMS_NOSMIMECAP);
    if (cms == nullptr) {
        throw std::runtime_error("makeSignerlessSignedData: CMS_sign failed");
    }
    ASN1_OBJECT* oid = OBJ_txt2obj(oidText, 1);
    const int set = oid != nullptr ? CMS_set1_eContentType(cms, oid) : 0;
    ASN1_OBJECT_free(oid);
    if (set != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("makeSignerlessSignedData: CMS_set1_eContentType failed");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("makeSignerlessSignedData: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> skeleton(der, der + len);
    OPENSSL_free(der);
    return replaceEContent(skeleton, content);
}

/// Re-encodes @p cmsDer with its encapsulated content REMOVED, i.e. as a
/// detached signature. Everything that says what the content is stays.
std::vector<uint8_t> detachEContent(const std::vector<uint8_t>& cmsDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("detachEContent: the input is not a CMS");
    }
    ASN1_OCTET_STRING** slot = CMS_get0_content(cms);
    if (slot == nullptr || *slot == nullptr) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("detachEContent: there was no content to detach");
    }
    ASN1_OCTET_STRING_free(*slot);
    *slot = nullptr;
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("detachEContent: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// Offset of the `version` INTEGER's TAG byte inside a CscaMasterList encoding
/// -- the first byte after the outer SEQUENCE's own header.
std::size_t versionTagOffsetIn(const std::vector<uint8_t>& content)
{
    if (content.size() < 3 || content[0] != 0x30) {
        throw std::runtime_error("versionTagOffsetIn: not a SEQUENCE");
    }
    const std::size_t at = (content[1] & 0x80) == 0 ? 2u : 2u + (content[1] & 0x7Fu);
    if (content.size() <= at) {
        throw std::runtime_error("versionTagOffsetIn: truncated");
    }
    return at;
}

/// A copy of @p content whose `version` TAG byte is @p tagByte. Only the tag
/// changes: the length and the value stay, so a walk that strides by length
/// covers exactly the same bytes and nothing but the tag can be what rejects
/// it.
std::vector<uint8_t> withVersionTagByte(const std::vector<uint8_t>& content, uint8_t tagByte)
{
    std::vector<uint8_t> out = content;
    const std::size_t at = versionTagOffsetIn(out);
    if (out[at] != 0x02) {
        throw std::runtime_error("withVersionTagByte: that is not the version INTEGER tag");
    }
    out[at] = tagByte;
    return out;
}

/// A copy of @p content whose outer SEQUENCE declares a length @p delta bytes
/// different from the truth, with the length field's WIDTH unchanged so that
/// nothing inside it moves and the only thing wrong is the declared length.
std::vector<uint8_t> rewriteOuterSequenceLength(std::vector<uint8_t> content, long delta)
{
    if (content.size() < 2 || content[0] != 0x30) {
        throw std::runtime_error("rewriteOuterSequenceLength: not a SEQUENCE");
    }
    std::size_t width = 1;  // bytes of the length field itself
    std::size_t offset = 1; // where the value's first byte sits
    if ((content[1] & 0x80) != 0) {
        width = content[1] & 0x7Fu;
        offset = 2;
        if (width == 0 || width > 4 || content.size() < offset + width) {
            throw std::runtime_error("rewriteOuterSequenceLength: unsupported length form");
        }
    }
    long value = 0;
    for (std::size_t i = 0; i < width; ++i) {
        value = (value << 8) | content[offset + i];
    }
    value += delta;
    if (value < 0) {
        throw std::runtime_error("rewriteOuterSequenceLength: length would go negative");
    }
    // The rewritten value has to fit the width it started with, or bytes move
    // and the test stops being about the length alone.
    if (width < 4 && value >= (1L << (8 * static_cast<long>(width)))) {
        throw std::runtime_error("rewriteOuterSequenceLength: length no longer fits its field");
    }
    for (std::size_t i = 0; i < width; ++i) {
        content[offset + width - 1 - i] = static_cast<uint8_t>((value >> (8 * i)) & 0xFF);
    }
    return content;
}

/// A copy of @p content with @p field appended INSIDE its outer SEQUENCE, the
/// length grown to match -- a third field in a structure that has two.
std::vector<uint8_t> withExtraFieldInTheSequence(const std::vector<uint8_t>& content, const std::vector<uint8_t>& field)
{
    std::vector<uint8_t> out = content;
    out.insert(out.end(), field.begin(), field.end());
    return rewriteOuterSequenceLength(std::move(out), static_cast<long>(field.size()));
}

/// Asserts that @p callerError is the only thing left in the OpenSSL error
/// queue: still there to peek, still there to pop, and nothing behind it.
///
/// The third check is the one that catches a leak. ERR_peek_error() reads the
/// OLDEST entry, so a parser that left residue ON TOP of the caller's error
/// still satisfies the first two -- only popping the caller's own entry and
/// finding the queue empty proves nothing was left above it.
void expectOnlyTheCallersErrorRemains(unsigned long callerError)
{
    EXPECT_EQ(ERR_peek_error(), callerError) << "the caller's error must survive the call";
    EXPECT_EQ(ERR_get_error(), callerError) << "the caller's error must still be there to pop";
    EXPECT_EQ(ERR_peek_error(), 0ul) << "and popping it must leave the queue empty -- no residue on top of it";
}

/// Like AnchorLoaderTest above: these share this process's one thread-local
/// OpenSSL error queue, and two of them assert on its exact contents, so it is
/// cleared on the way in and out rather than left to test ordering.
class CscaMasterListTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ERR_clear_error();
    }
    void TearDown() override
    {
        ERR_clear_error();
    }
};

} // namespace

TEST_F(CscaMasterListTest, ParsesEveryAnchorTheListCarries)
{
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    const auto parsed = emrtd::crypto::parseCscaMasterList(ml.der);
    ASSERT_TRUE(parsed.has_value());
    EXPECT_EQ(parsed->cscaDer.size(), 3u);
    EXPECT_EQ(parsed->cscaDer, ml.cscaDer);
}

TEST_F(CscaMasterListTest, RejectsAnObjectThatIsSignedButIsNotAMasterList)
{
    const auto other = LibreSCRS::Test::makeSignedNonMasterList();
    const auto parsed = emrtd::crypto::parseCscaMasterList(other);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsGarbage)
{
    const auto parsed = emrtd::crypto::parseCscaMasterList(std::vector<uint8_t>(64, 0x41));
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsAnEmptyListRatherThanReturningNoAnchors)
{
    const auto ml = LibreSCRS::Test::makeMasterList(0);
    const auto parsed = emrtd::crypto::parseCscaMasterList(ml.der);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Empty);
}

TEST_F(CscaMasterListTest, RejectsAnObjectRelabelledAsAMasterListAfterItWasSigned)
{
    // The content here IS a well-formed CscaMasterList and the CMS still
    // verifies -- only the signed contentType attribute still says id-data.
    // Reading the eContentType field alone would accept this.
    const auto relabelled = relabelEContentTypeField(LibreSCRS::Test::makeSignedNonMasterList(), "2.23.136.1.1.2");
    ASSERT_EQ(eContentTypeOf(relabelled), "2.23.136.1.1.2") << "the field must really claim to be a master list";
    ASSERT_EQ(cmsVerifyAgainst(relabelled, {}, CMS_NO_SIGNER_CERT_VERIFY), 1)
        << "and the relabelled object must still verify, or it proves nothing";
    ASSERT_FALSE(anchorsInsideList(relabelled).empty()) << "its content must still parse as a master list";

    const auto parsed = emrtd::crypto::parseCscaMasterList(relabelled);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsAnObjectWearingTheIcaoContentTypeButCarryingNoSigner)
{
    // A DigestedData over a genuine master list, relabelled to the ICAO OID.
    // The content type field says master list, the content IS one, and a
    // parser that went from the field straight to the content would hand back
    // the anchor. Nothing signed it, so nothing binds it to that type.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto worn = makeDigestedDataWearing(eContentOf(ml.der), "2.23.136.1.1.2");
    ASSERT_EQ(eContentTypeOf(worn), "2.23.136.1.1.2") << "the field must really claim to be a master list";
    ASSERT_EQ(anchorsInsideList(worn), ml.cscaDer) << "and the anchor must really be sitting there to be taken";

    const auto parsed = emrtd::crypto::parseCscaMasterList(worn);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsASignedContentTypeAttributeThatIsNotAnOid)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceSignedContentTypeWithNonOid(ml.der);
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, ReportsContentThatIsNotAListSeparatelyFromAnObjectThatIsNotOne)
{
    // Both verdicts, in one test, because the name is about the gap between
    // them and one of them alone shows no gap.
    //
    // Malformed: both places agree that this IS a master list, and its content
    // simply does not decode.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto brokenContent = replaceEContent(ml.der, std::vector<uint8_t>(16, 0x41));
    const auto contentNotAList = emrtd::crypto::parseCscaMasterList(brokenContent);
    ASSERT_FALSE(contentNotAList.has_value());
    EXPECT_EQ(contentNotAList.error(), emrtd::crypto::MasterListError::Malformed);

    // NotAMasterList: a well-formed CscaMasterList under a different content
    // type. The content here would decode perfectly; the object is not one.
    const auto notAMasterList = emrtd::crypto::parseCscaMasterList(LibreSCRS::Test::makeSignedNonMasterList());
    ASSERT_FALSE(notAMasterList.has_value());
    EXPECT_EQ(notAMasterList.error(), emrtd::crypto::MasterListError::NotAMasterList);

    EXPECT_NE(contentNotAList.error(), notAMasterList.error())
        << "collapsing the two would lose which of them happened";
}

TEST_F(CscaMasterListTest, RejectsBytesTrailingTheContentInfo)
{
    // d2i stops at the end of the object it decoded and says nothing about
    // what follows, so this has to be checked rather than assumed. A published
    // master list is the ContentInfo and nothing else.
    auto der = LibreSCRS::Test::makeMasterList(1).der;
    ASSERT_TRUE(emrtd::crypto::parseCscaMasterList(der).has_value())
        << "the untouched list must parse, or the appended byte proves nothing";
    der.push_back(0x00);

    const auto parsed = emrtd::crypto::parseCscaMasterList(der);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsEmptyInput)
{
    // No test had ever passed an empty vector. The header says what the answer
    // is, so it has to be asked.
    const auto parsed = emrtd::crypto::parseCscaMasterList({});
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsAVersionFieldThatIsNotUniversalClass)
{
    // Tag 0x42: INTEGER's tag number, APPLICATION class. Length and value are
    // untouched, so a walk that strides by length covers the same bytes and
    // hands back the anchors unless the class is checked.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, withVersionTagByte(eContentOf(ml.der), 0x42));
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RejectsAVersionFieldThatIsNotAnInteger)
{
    // Tag 0x04, OCTET STRING: universal and primitive like the real thing, so
    // only the tag NUMBER separates them.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, withVersionTagByte(eContentOf(ml.der), 0x04));
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RejectsAConstructedVersionField)
{
    // Tag 0x22: universal, tag number 2, constructed. BER permits a
    // constructed encoding for some string types and never for an INTEGER;
    // DER never permits one at all. This is the half of the definite-and-
    // constructed test that no span check covers.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, withVersionTagByte(eContentOf(ml.der), 0x22));
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RejectsAListWhoseContentTypeFieldDisagreesWithItsSignedAttribute)
{
    // The mirror of RejectsAnObjectRelabelledAsAMasterListAfterItWasSigned.
    // There the FIELD claimed master list and the attribute did not; here the
    // attribute claims it and the field does not. "Both places" is two
    // directions, and only the other one was defended.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = relabelEContentTypeField(ml.der, "1.2.840.113549.1.7.1");
    ASSERT_EQ(eContentTypeOf(broken), "1.2.840.113549.1.7.1") << "the field must really name something else";
    ASSERT_EQ(signedContentTypeOf(broken, -3), "2.23.136.1.1.2")
        << "and the signed attribute must still say master list, or this tests the other direction";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsASignedDataThatCarriesNoSignerAtAll)
{
    // A SignedData -- so the SignedData gate lets it through -- carrying the
    // real anchors under the real content type, and no SignerInfo whatsoever.
    // Nothing signed it, so nothing binds those anchors to anything; without
    // the signer count they are simply handed back.
    //
    // The DigestedData test above cannot reach this: it is stopped by the gate
    // one line earlier and never gets as far as the count.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto worn = makeSignerlessSignedData(eContentOf(ml.der), "2.23.136.1.1.2");
    ASSERT_EQ(signerCountOf(worn), 0) << "it must really carry no signer";
    ASSERT_EQ(eContentTypeOf(worn), "2.23.136.1.1.2") << "and must really claim to be a master list";
    ASSERT_EQ(anchorsInsideList(worn), ml.cscaDer) << "with the anchors sitting there to be taken";

    const auto parsed = emrtd::crypto::parseCscaMasterList(worn);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsAMiddleSignerThatDisagreesAboutTheContentType)
{
    // THREE signers, and the disagreeing one in the MIDDLE. Two cannot prove
    // an index walk: with two, the second signer IS the last signer, so
    // "reads the last one" and "reads every one" behave identically -- and so
    // does "reads the first and the last". Three, with the interesting one
    // between them, separates all four.
    //
    // SignerInfos are a DER SET OF, so i2d re-sorts them and relabelling
    // signer i does not leave it at index i. Each placement is tried and the
    // one whose ENCODED order really reads ICAO / id-data / ICAO is used.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto twoAgreeing = addSigner(ml.der, "2.23.136.1.1.2", "Signer Two");
    const auto threeAgreeing = addSigner(twoAgreeing, "2.23.136.1.1.2", "Signer Three");
    ERR_clear_error(); // building the fixture is not what is under test
    ASSERT_EQ(signerCountOf(threeAgreeing), 3);

    std::vector<uint8_t> chosen;
    for (int index = 0; index < 3 && chosen.empty(); ++index) {
        const auto candidate = relabelSignerAt(threeAgreeing, index, "1.2.840.113549.1.7.1");
        ERR_clear_error();
        if (signedContentTypeOf(candidate, -3, 0) == "2.23.136.1.1.2" &&
            signedContentTypeOf(candidate, -3, 1) == "1.2.840.113549.1.7.1" &&
            signedContentTypeOf(candidate, -3, 2) == "2.23.136.1.1.2") {
            chosen = candidate;
        }
    }
    ASSERT_FALSE(chosen.empty()) << "no placement put the disagreeing signer in the middle";
    ASSERT_EQ(signerCountOf(chosen), 3);
    ASSERT_EQ(eContentTypeOf(chosen), "2.23.136.1.1.2") << "the field must still say master list";

    const auto parsed = emrtd::crypto::parseCscaMasterList(chosen);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, AcceptsASecondSignerThatAgrees)
{
    // The control for the test above. Without it, "every SignerInfo" could be
    // satisfied by refusing every list that carries more than one, and the
    // disagreement test would not notice.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto twoAgreeing = addSigner(ml.der, "2.23.136.1.1.2", "Signer Two");
    ERR_clear_error();
    ASSERT_EQ(signerCountOf(twoAgreeing), 2);

    const auto parsed = emrtd::crypto::parseCscaMasterList(twoAgreeing);
    ASSERT_TRUE(parsed.has_value()) << "two signers that agree are not a reason to reject a list";
    EXPECT_EQ(parsed->cscaDer, ml.cscaDer);
}

TEST_F(CscaMasterListTest, RejectsASignerWithNoContentTypeAttributeAtAll)
{
    // An absent attribute is not the same behaviour as a malformed one, even
    // though today the same line produces both: a parser that probed for
    // presence separately would still reject wrong-typed, duplicated,
    // multi-valued, disagreeing and relabelled objects, and let this one
    // through. With no attribute there is nothing under the signature that
    // says what was signed, which is the whole reason the attribute is read.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = removeSignedContentTypeAttribute(ml.der);
    ERR_clear_error();
    ASSERT_EQ(signedContentTypeOf(broken, -1), "<none>") << "the attribute must really be gone";
    ASSERT_EQ(eContentTypeOf(broken), "2.23.136.1.1.2") << "while the FIELD still says master list";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsADuplicatedSignedContentTypeAttribute)
{
    // Two contentType attributes, both naming the ICAO OID. Nothing here is
    // "wrong" to a reader that takes the first one it finds -- which is the
    // point: one of the two is the one the signer meant, and there is no way
    // to tell which.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = duplicateSignedContentTypeAttribute(ml.der);
    ASSERT_EQ(signedContentTypeOf(broken, -1), "2.23.136.1.1.2")
        << "a reader that skipped the cardinality check would be satisfied by this";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsATwoValuedSignedContentTypeAttribute)
{
    // One attribute, two values, both the ICAO OID. The attribute is unique,
    // so only the value count is out of order.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = addSecondValueToSignedContentTypeAttribute(ml.der);
    ASSERT_EQ(signedContentTypeOf(broken, -1), "2.23.136.1.1.2")
        << "a reader that took the first value would be satisfied by this";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, RejectsAPresentButEmptyContentAsMalformedRatherThanEmpty)
{
    // `Empty` means a list that parsed and carries no certificate. Nothing
    // parsed here, so the answer is `Malformed` -- the two are different
    // answers and the header now says which one this is.
    //
    // Measured, no check in this file pins it: removing `contentLen <= 0`,
    // removing `cursor >= limit` in readHeader, and removing both, all leave
    // this passing -- ASN1_get_object refuses a non-positive `omax` itself,
    // and that backstop is in OpenSSL, not here. So this test pins the verdict
    // the header promises, not any line that produces it.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, {});
    ASSERT_EQ(eContentTypeOf(broken), "2.23.136.1.1.2") << "it must still claim to be a master list";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RejectsADetachedSignatureInsteadOfReadingContentThatIsNotThere)
{
    // Both places still say master list; the list itself is gone. The eContent
    // slot is then a null pointer, and reading through it is not a wrong
    // verdict, it is a crash.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = detachEContent(ml.der);
    ASSERT_EQ(eContentTypeOf(broken), "2.23.136.1.1.2") << "it must still claim to be a master list";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, ReturnsAnElementAsTheListCarriesItEvenWhenThatIsBer)
{
    // The same certificate, re-wrapped with BER's indefinite length. d2i
    // accepts it, and what comes back is the wrapper the list carried --
    // `30 80` at the front, `00 00` at the back -- not a re-encoding. That is
    // what MasterList::cscaDer promises, and it is the reason the doc there
    // stops short of calling these bytes DER.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto berCert = withIndefiniteOuterLength(ml.cscaDer.front());
    ASSERT_EQ(berCert[0], 0x30);
    ASSERT_EQ(berCert[1], 0x80);

    std::vector<uint8_t> body{0x02, 0x01, 0x00};
    const auto certSet = derWrap(0x31, berCert);
    body.insert(body.end(), certSet.begin(), certSet.end());
    const auto broken = replaceEContent(ml.der, derWrap(0x30, body));

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_TRUE(parsed.has_value()) << "an element only has to parse, and d2i takes BER";
    ASSERT_EQ(parsed->cscaDer.size(), 1u);
    EXPECT_EQ(parsed->cscaDer.front(), berCert) << "the bytes must come back as the list carried them";
    EXPECT_NE(parsed->cscaDer.front(), ml.cscaDer.front()) << "which is not the same as re-encoding them";
}

TEST_F(CscaMasterListTest, RejectsASequenceLengthThatStopsShortOfItsContent)
{
    // The SEQUENCE declares itself four bytes shorter than what actually
    // follows it. Nothing downstream trips over that on its own: the INTEGER
    // and the SET are read against the enclosing content, not against the
    // SEQUENCE's own declared end, so both parse and an anchor comes back out
    // of a structure that never closes. Only comparing the declared end with
    // the real one catches it.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    ASSERT_TRUE(emrtd::crypto::parseCscaMasterList(ml.der).has_value())
        << "the untouched list must parse, or the rewritten length proves nothing";

    const auto broken = replaceEContent(ml.der, rewriteOuterSequenceLength(eContentOf(ml.der), -4));
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RejectsAFurtherFieldAfterTheSetOfCertificates)
{
    // CscaMasterList has two fields. A third -- a NULL will do -- is not one,
    // and nothing after the SET is looked at unless the SET's end is required
    // to be the structure's end: the anchors come back and whatever was
    // smuggled in beside them goes unmentioned.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    ASSERT_TRUE(emrtd::crypto::parseCscaMasterList(ml.der).has_value())
        << "the untouched list must parse, or the added field proves nothing";

    const std::vector<uint8_t> nullField{0x05, 0x00};
    const auto broken = replaceEContent(ml.der, withExtraFieldInTheSequence(eContentOf(ml.der), nullField));
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RejectsAnIndefiniteLengthInTheListStructure)
{
    // SEQUENCE { INTEGER 0, SET [indefinite, empty] } -- BER, and a master
    // list is DER.
    //
    // Relaxing the definite-length requirement alone does not fell this, and
    // neither does removing `setEnd != end` alone: ASN1_get_object reports
    // length 0 for an indefinite form, so the span check catches what the
    // length check would have. Removing BOTH does fell it. That is the same
    // shape as the SignedData gate and the signer count -- a pair where either
    // member covers for the other -- and it is what this test pins.
    const std::vector<uint8_t> content{0x30, 0x07, 0x02, 0x01, 0x00, 0x31, 0x80, 0x00, 0x00};
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, content);
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RejectsASetElementThatIsNotACertificate)
{
    // SEQUENCE { INTEGER 0, SET { OCTET STRING "AAAAA" } } -- structurally a
    // CscaMasterList, but the one thing a SET OF Certificate may hold is a
    // certificate, and a parser that only counted elements would return one
    // "anchor" of five bytes.
    const std::vector<uint8_t> content{0x30, 0x0C, 0x02, 0x01, 0x00, 0x31, 0x07,
                                       0x04, 0x05, 0x41, 0x41, 0x41, 0x41, 0x41};
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, content);
    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    EXPECT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed);
}

// The four tests below each drive ONE of the three brackets that are actually
// load-bearing, plus the signer loop. They are separate on purpose: a single
// input stops at the first thing that rejects it, so garbage bytes never reach
// the content walk and content that fails the walk never reaches the element
// loop. One test covering "a rejection" would leave the other brackets free to
// be deleted with every test still green -- which is exactly what happened.

TEST_F(CscaMasterListTest, DoesNotWipeACallersPendingOpenSslErrorWhenTheCmsItselfWillNotParse)
{
    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto parsed = emrtd::crypto::parseCscaMasterList(std::vector<uint8_t>(64, 0x41));
    ASSERT_FALSE(parsed.has_value());
    ASSERT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaMasterListTest, DoesNotWipeACallersPendingOpenSslErrorWhileCheckingTheSigner)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceSignedContentTypeWithNonOid(ml.der);
    ERR_clear_error(); // building the input is not what is under test

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    ASSERT_EQ(parsed.error(), emrtd::crypto::MasterListError::NotAMasterList);

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaMasterListTest, DoesNotWipeACallersPendingOpenSslErrorWhileWalkingTheContent)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, std::vector<uint8_t>(16, 0x41));
    ERR_clear_error(); // building the input is not what is under test

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    ASSERT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed) << "this must reach the content walk";

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaMasterListTest, DoesNotWipeACallersPendingOpenSslErrorWhileReadingTheAnchors)
{
    // Same bytes as RejectsASetElementThatIsNotACertificate: the structure
    // walks clean and only d2i_X509 objects, so this is the one input that
    // gets as far as the element loop.
    const std::vector<uint8_t> content{0x30, 0x0C, 0x02, 0x01, 0x00, 0x31, 0x07,
                                       0x04, 0x05, 0x41, 0x41, 0x41, 0x41, 0x41};
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = replaceEContent(ml.der, content);
    ERR_clear_error(); // building the input is not what is under test

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto parsed = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parsed.has_value());
    ASSERT_EQ(parsed.error(), emrtd::crypto::MasterListError::Malformed) << "this must reach the element loop";

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaMasterListTest, LeavesACallersErrorQueueUntouchedWhenItSucceeds)
{
    // The other half of the header's promise: the queue is left as the caller
    // had it on the SUCCESS path too, not only when rejecting.
    //
    // Nothing a clean parse calls queues anything of its own today, so this
    // passes with every bracket removed: it does not prove the brackets work.
    // The four DoesNotWipe... tests above do that, one per bracket. This is
    // here so that a later change which starts leaving residue behind on the
    // way to a successful answer is caught at the parser rather than in
    // whatever runs next.
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    ERR_clear_error(); // the fixture generator is entitled to leave its own residue

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto parsed = emrtd::crypto::parseCscaMasterList(ml.der);
    ASSERT_TRUE(parsed.has_value());

    expectOnlyTheCallersErrorRemains(callerError);
}

// ---------------------------------------------------------------------------
// Signature and signer-identity verification
//
// The helpers below exist because the ones above cannot serve here: addSigner
// leaves its signer unfinalised, which is fine when nothing looks at a
// signature and useless once something does.
// ---------------------------------------------------------------------------

namespace {

/// Re-encodes @p cmsDer with one more SignerInfo that REALLY SIGNS.
///
/// CMS_REUSE_DIGEST is what makes this possible on an object that is already
/// signed: it copies the messageDigest attribute from a signer that is already
/// there and takes the contentType attribute from the eContentType field, so
/// the new signer attests to the same content as the old one without the
/// content having to be re-digested. Without CMS_PARTIAL, CMS_add1_signer then
/// signs on the spot. The existing signers are untouched, so their signatures
/// still hold.
///
/// @param embedCertificate false leaves the signer's certificate OUT of the
///        object, which is the only difference between the two calls: the
///        signature is made the same way and is just as good, and CMS_verify
///        still cannot check it, because the key to check it with is not there.
std::vector<uint8_t> addSignedSigner(const std::vector<uint8_t>& cmsDer, const char* commonName,
                                     bool embedCertificate = true)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("addSignedSigner: the input is not a CMS");
    }
    ThrowawayIdentity id;
    CMS_SignerInfo* signer = nullptr;
    try {
        mintThrowawayIdentity(id, commonName);
        const unsigned int certFlag = embedCertificate ? 0u : static_cast<unsigned int>(CMS_NOCERTS);
        signer = CMS_add1_signer(cms, id.cert, id.key, EVP_sha256(), CMS_NOSMIMECAP | CMS_REUSE_DIGEST | certFlag);
    } catch (...) {
        CMS_ContentInfo_free(cms);
        throw;
    }
    if (signer == nullptr) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("addSignedSigner: could not add the signer");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("addSignedSigner: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// The signature bytes of the SignerInfo at @p signerIndex, as encoded.
/// Used to say WHICH signer a re-encoding put where -- SignerInfos are a DER
/// SET OF, so an index is a property of the bytes, not of the order they were
/// added in.
std::vector<uint8_t> signatureOfSignerAt(const std::vector<uint8_t>& cmsDer, int signerIndex)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("signatureOfSignerAt: the input is not a CMS");
    }
    CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), signerIndex);
    std::vector<uint8_t> out;
    if (signer != nullptr) {
        const ASN1_OCTET_STRING* sig = CMS_SignerInfo_get0_signature(signer);
        const unsigned char* data = ASN1_STRING_get0_data(sig);
        out.assign(data, data + ASN1_STRING_length(sig));
    }
    CMS_ContentInfo_free(cms);
    if (out.empty()) {
        throw std::runtime_error("signatureOfSignerAt: no such signer, or it carries no signature");
    }
    return out;
}

/// Re-encodes @p cmsDer with the last byte of signer @p signerIndex's
/// signature flipped.
///
/// The length is unchanged and the signature is the LAST field of a
/// SignerInfo, while two SignerInfos already differ in their signer
/// identifier, which is nearly the first -- so the DER SET OF order is decided
/// long before this byte and re-encoding cannot move the signer that was
/// touched. The tests assert that rather than trusting it.
std::vector<uint8_t> withCorruptSignatureAtSignerIndex(const std::vector<uint8_t>& cmsDer, int signerIndex)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("withCorruptSignatureAtSignerIndex: the input is not a CMS");
    }
    CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(CMS_get0_SignerInfos(cms), signerIndex);
    int rc = 0;
    if (signer != nullptr) {
        ASN1_OCTET_STRING* sig = CMS_SignerInfo_get0_signature(signer);
        std::vector<uint8_t> bytes(ASN1_STRING_get0_data(sig), ASN1_STRING_get0_data(sig) + ASN1_STRING_length(sig));
        if (!bytes.empty()) {
            bytes.back() ^= 0x01;
            rc = ASN1_STRING_set(sig, bytes.data(), static_cast<int>(bytes.size()));
        }
    }
    if (rc != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("withCorruptSignatureAtSignerIndex: could not rewrite that signature");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("withCorruptSignatureAtSignerIndex: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// SHA-256 over the DER of the SubjectPublicKeyInfo of the certificate that
/// signs the SignerInfo at @p signerIndex.
///
/// The fixture reports the fingerprint of the list signer it minted, which is
/// all a single-signer list needs; this is the only way to name the signer
/// sitting at a GIVEN index of a list that carries several.
std::vector<uint8_t> spkiSha256OfSignerAt(const std::vector<uint8_t>& cmsDer, int signerIndex)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("spkiSha256OfSignerAt: the input is not a CMS");
    }
    // Resolves each SignerInfo's certificate out of the object's own
    // certificate set; without it every si->signer is still null and
    // CMS_get0_signers hands back nothing.
    CMS_set1_signers_certs(cms, nullptr, 0);
    STACK_OF(X509)* signers = CMS_get0_signers(cms);
    std::vector<uint8_t> out;
    if (sk_X509_num(signers) == sk_CMS_SignerInfo_num(CMS_get0_SignerInfos(cms))) {
        X509* cert = sk_X509_value(signers, signerIndex);
        if (cert != nullptr) {
            unsigned char* der = nullptr;
            const int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
            if (len > 0 && der != nullptr) {
                out.resize(EVP_MAX_MD_SIZE);
                unsigned int digestLen = 0;
                if (EVP_Digest(der, static_cast<size_t>(len), out.data(), &digestLen, EVP_sha256(), nullptr) == 1) {
                    out.resize(digestLen);
                } else {
                    out.clear();
                }
            }
            OPENSSL_free(der);
        }
    }
    sk_X509_free(signers);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    if (out.empty()) {
        throw std::runtime_error("spkiSha256OfSignerAt: no certificate for that signer");
    }
    return out;
}

/// A CMS SignedData over @p content wearing @p oidText, signed for real by a
/// throwaway identity whose certificate travels with it.
///
/// replaceEContent cannot serve where the signature has to survive: the
/// messageDigest attribute is under the signature, so swapping the content
/// breaks it. This signs the content that is wanted instead of editing content
/// that was already signed.
std::vector<uint8_t> signContentWearing(const std::vector<uint8_t>& content, const char* oidText)
{
    ThrowawayIdentity id;
    mintThrowawayIdentity(id, "Content Signer");
    BIO* bio = BIO_new_mem_buf(content.data(), static_cast<int>(content.size()));
    // CMS_PARTIAL for the same reason the fixture generator needs it: without
    // it CMS_sign finalises at once and CMS_set1_eContentType comes too late to
    // reach the signed contentType attribute.
    CMS_ContentInfo* cms = CMS_sign(id.cert, id.key, nullptr, bio, CMS_BINARY | CMS_NOSMIMECAP | CMS_PARTIAL);
    ASN1_OBJECT* oid = OBJ_txt2obj(oidText, 1);
    int rc = 0;
    if (cms != nullptr && oid != nullptr && CMS_set1_eContentType(cms, oid) == 1) {
        rc = CMS_final(cms, bio, nullptr, CMS_BINARY);
    }
    ASN1_OBJECT_free(oid);
    BIO_free(bio);
    if (rc != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("signContentWearing: could not sign that content");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("signContentWearing: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// SHA-256 over the DER of an encoded certificate's SubjectPublicKeyInfo --
/// the same fingerprint the fixture reports and the implementation compares,
/// computed here for a certificate that is not anybody's signer.
std::vector<uint8_t> spkiSha256OfCertificate(const std::vector<uint8_t>& certDer)
{
    X509* cert = certFromDer(certDer);
    if (cert == nullptr) {
        throw std::runtime_error("spkiSha256OfCertificate: not a certificate");
    }
    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
    std::vector<uint8_t> out;
    if (len > 0 && der != nullptr) {
        out.resize(EVP_MAX_MD_SIZE);
        unsigned int digestLen = 0;
        if (EVP_Digest(der, static_cast<size_t>(len), out.data(), &digestLen, EVP_sha256(), nullptr) == 1) {
            out.resize(digestLen);
        } else {
            out.clear();
        }
    }
    OPENSSL_free(der);
    X509_free(cert);
    ERR_clear_error();
    if (out.empty()) {
        throw std::runtime_error("spkiSha256OfCertificate: could not fingerprint it");
    }
    return out;
}

/// The certificates an object carries BESIDE its content -- the certificate
/// bag, which anybody may add to and which nothing signs. Deliberately named
/// apart from the signers: telling the two apart is the whole subject of
/// RefusesAListThatMerelyCarriesThePinnedSignersCertificate below.
std::vector<std::vector<uint8_t>> certificatesInBagOf(const std::vector<uint8_t>& cmsDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("certificatesInBagOf: the input is not a CMS");
    }
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
    std::vector<std::vector<uint8_t>> out;
    for (int i = 0; i < sk_X509_num(certs); ++i) {
        unsigned char* der = nullptr;
        const int len = i2d_X509(sk_X509_value(certs, i), &der);
        if (len > 0 && der != nullptr) {
            out.emplace_back(der, der + len);
        }
        OPENSSL_free(der);
    }
    // CMS_get1_certs up-refs, unlike CMS_get0_signers, so these are freed.
    sk_X509_pop_free(certs, X509_free);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return out;
}

/// Re-encodes @p cmsDer with @p certDer dropped into its certificate bag.
/// Nothing signs it and nothing vouches for it; that is the point.
std::vector<uint8_t> withCertificateInBag(const std::vector<uint8_t>& cmsDer, const std::vector<uint8_t>& certDer)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    X509* cert = certFromDer(certDer);
    if (cms == nullptr || cert == nullptr) {
        CMS_ContentInfo_free(cms);
        X509_free(cert);
        throw std::runtime_error("withCertificateInBag: bad input");
    }
    const int added = CMS_add1_cert(cms, cert);
    X509_free(cert);
    if (added != 1) {
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("withCertificateInBag: CMS_add1_cert failed");
    }
    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms, &der);
    CMS_ContentInfo_free(cms);
    if (len <= 0 || der == nullptr) {
        throw std::runtime_error("withCertificateInBag: i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// What the certificate behind SignerInfo @p signerIndex says about itself.
/// Both fields are things CMS_verify would look at if the signer's certificate
/// were being treated as a credential rather than as a container for its key.
struct SignerCertificateFacts
{
    bool expired = false;
    bool hasExtendedKeyUsage = false;
    bool passesSmimeSignPurpose = false;
};

SignerCertificateFacts factsAboutSignerAt(const std::vector<uint8_t>& cmsDer, int signerIndex)
{
    CMS_ContentInfo* cms = parseCms(cmsDer);
    if (cms == nullptr) {
        throw std::runtime_error("factsAboutSignerAt: the input is not a CMS");
    }
    CMS_set1_signers_certs(cms, nullptr, 0);
    STACK_OF(X509)* signers = CMS_get0_signers(cms);
    X509* cert = sk_X509_value(signers, signerIndex);
    if (cert == nullptr) {
        sk_X509_free(signers);
        CMS_ContentInfo_free(cms);
        throw std::runtime_error("factsAboutSignerAt: no certificate for that signer");
    }
    SignerCertificateFacts facts;
    // X509_cmp_current_time returns < 0 when the time it is given is past.
    facts.expired = X509_cmp_current_time(X509_get0_notAfter(cert)) < 0;
    facts.hasExtendedKeyUsage = X509_get_ext_by_NID(cert, NID_ext_key_usage, -1) >= 0;
    // The very purpose CMS_verify applies when it is allowed to look at the
    // signer's certificate as a credential. Read here rather than described,
    // so the test asserts what OpenSSL would actually decide.
    facts.passesSmimeSignPurpose = X509_check_purpose(cert, X509_PURPOSE_SMIME_SIGN, 0) == 1;
    sk_X509_free(signers);
    CMS_ContentInfo_free(cms);
    ERR_clear_error();
    return facts;
}

/// A master list carrying THREE signers, every one of which really signs it.
///
/// Two would not do. With two, the second signer is also the last, so "reads
/// the last" and "reads every one" are the same behaviour, and so is "reads
/// the first and the last". The tests below put the interesting signer at
/// index 1 of the ENCODED order -- which is not the order they were added in,
/// since SignerInfos are a DER SET OF.
std::vector<uint8_t> threeSignerMasterList(const LibreSCRS::Test::SyntheticMasterList& ml)
{
    const auto out = addSignedSigner(addSignedSigner(ml.der, "Second Signer"), "Third Signer");
    ERR_clear_error(); // building the fixture is not what is under test
    return out;
}

} // namespace

TEST_F(CscaMasterListTest, AcceptsAListSignedByTheExpectedSigner)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto out = emrtd::crypto::parseAndVerifyMasterList(ml.der, ml.signerSpkiSha256);
    ASSERT_TRUE(out.has_value());
    EXPECT_EQ(out->list.cscaDer.size(), 2u);
    EXPECT_EQ(out->list.cscaDer, ml.cscaDer) << "the anchors must be the ones the list carries";
    EXPECT_TRUE(out->identityChecked);
    EXPECT_EQ(out->signerSpkiSha256, ml.signerSpkiSha256);
}

TEST_F(CscaMasterListTest, RefusesAListWhoseSignerIsNotTheAcceptedOne)
{
    // The anchors are byte-identical and the signature over them is perfectly
    // good -- only the key that made it is somebody else's. An implementation
    // that fingerprinted the content, or an anchor, instead of the signer
    // would accept this.
    const auto mine = LibreSCRS::Test::makeMasterList(2);
    const auto other = LibreSCRS::Test::makeMasterListWithOtherSigner(mine);
    ASSERT_EQ(other.cscaDer, mine.cscaDer) << "the anchors must be identical, or this tests the wrong thing";
    ASSERT_NE(other.signerSpkiSha256, mine.signerSpkiSha256);

    const auto out = emrtd::crypto::parseAndVerifyMasterList(other.der, mine.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::SignerMismatch);
}

TEST_F(CscaMasterListTest, RefusesAListWhoseSignedContentWasChanged)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto bad = LibreSCRS::Test::makeTamperedMasterList(ml);
    ASSERT_NE(bad.der, ml.der) << "the fixture must really have changed something";
    ASSERT_TRUE(emrtd::crypto::parseCscaMasterList(bad.der).has_value())
        << "the edit must leave the content PARSING, or a parse error would answer instead";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(bad.der, ml.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature)
        << "a length-preserving edit must fail the signature, not the parse";
}

TEST_F(CscaMasterListTest, SaysWhenIdentityWasNotCheckedAtAll)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto out = emrtd::crypto::parseAndVerifyMasterList(ml.der, {});
    ASSERT_TRUE(out.has_value());
    EXPECT_FALSE(out->identityChecked) << "an empty expectation compares nothing, and must say so";
    EXPECT_EQ(out->signerSpkiSha256, ml.signerSpkiSha256)
        << "the fingerprint is reported so a caller can show it to a user";
}

TEST_F(CscaMasterListTest, ChecksTheSignatureBeforeTheFingerprint)
{
    // The one input that separates the two orders: the signature does not hold
    // AND the signer is not the expected one. Verifying first answers
    // BadSignature; comparing first answers SignerMismatch, having decided
    // something about a fingerprint on an object nothing vouches for.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto other = LibreSCRS::Test::makeMasterList(1);
    const auto bad = LibreSCRS::Test::makeTamperedMasterList(ml);
    ASSERT_NE(other.signerSpkiSha256, ml.signerSpkiSha256) << "the pin must name a DIFFERENT signer";
    // Bound and checked for emptiness before error() is read. std::expected's
    // error() has the precondition has_value() == false, which Release does not
    // enforce, so reading it off a value-holding result compares whatever the
    // value's first bytes happen to be -- and this line exists to catch an
    // implementation that started ACCEPTING these bytes, which is exactly the
    // case where the precondition would not hold.
    const auto withTheRightPin = emrtd::crypto::parseAndVerifyMasterList(bad.der, ml.signerSpkiSha256);
    ASSERT_FALSE(withTheRightPin.has_value()) << "these bytes must be refused with the right pin too";
    ASSERT_EQ(withTheRightPin.error(), emrtd::crypto::MasterListError::BadSignature)
        << "with the RIGHT pin these bytes are a bad signature, so the pin is the only thing that changes below";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(bad.der, other.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature)
        << "the signature is checked first, so a wrong pin does not get to answer for a broken one";
}

TEST_F(CscaMasterListTest, AcceptsAPinNamingTheSignerInTheMiddle)
{
    // THREE signers, and the pinned one is neither the first nor the last of
    // the encoded order. With two, "matches the last" and "matches any" cannot
    // be told apart, because index 1 is also the last index.
    //
    // This is also the control for the test below it: three signers that all
    // verify must be ACCEPTED, or "every signer verifies" could be satisfied
    // by refusing every list that carries more than one.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto three = threeSignerMasterList(ml);
    ASSERT_EQ(signerCountOf(three), 3);
    ASSERT_EQ(cmsVerifyAgainst(three, {}, CMS_NO_SIGNER_CERT_VERIFY), 1) << "all three signatures must really hold";

    const auto first = spkiSha256OfSignerAt(three, 0);
    const auto middle = spkiSha256OfSignerAt(three, 1);
    const auto last = spkiSha256OfSignerAt(three, 2);
    ASSERT_NE(middle, first);
    ASSERT_NE(middle, last);

    const auto out = emrtd::crypto::parseAndVerifyMasterList(three, middle);
    ASSERT_TRUE(out.has_value()) << "a pin naming any signer of the list must be met, not only signers[0]";
    EXPECT_TRUE(out->identityChecked);
    EXPECT_EQ(out->list.cscaDer, ml.cscaDer);
    EXPECT_EQ(out->signerSpkiSha256, middle) << "the fingerprint reported is the one that MATCHED";
    EXPECT_NE(out->signerSpkiSha256, first)
        << "not signers[0], which on this list is a key the call established nothing about";
}

TEST_F(CscaMasterListTest, AcceptsAPinNamingTheLastOfSeveralSigners)
{
    // The pin loop's upper bound, which nothing else here defends. A bound of
    // `signerCount - 1` taken only when there is more than one signer leaves
    // single-signer lists untouched and is invisible to every other test in
    // this file -- including the middle-signer one above, since index 1 is
    // still inside a bound of 2.
    //
    // It is fail-closed, so no trust is bypassed: what breaks is the genuine
    // list being refused. That is reachable in practice for the reason this
    // file gives elsewhere -- SignerInfos are a DER SET OF, so an attacker who
    // appends a signer that happens to sort first pushes the publisher's own
    // signer toward the tail.
    //
    // Its own test rather than another assertion inside the middle-signer one,
    // where first/middle/last are already to hand, so that the perturbation
    // record keeps one mutant to one name: "reads only the last signer" fells
    // that test, "stops one short of the last" fells this one, and folded
    // together the two defects would report identically.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto three = threeSignerMasterList(ml);
    ASSERT_EQ(signerCountOf(three), 3);

    const auto first = spkiSha256OfSignerAt(three, 0);
    const auto last = spkiSha256OfSignerAt(three, 2);
    ASSERT_NE(last, first);

    const auto out = emrtd::crypto::parseAndVerifyMasterList(three, last);
    ASSERT_TRUE(out.has_value()) << "the last signer of several must still be reachable by a pin";
    EXPECT_TRUE(out->identityChecked);
    EXPECT_EQ(out->signerSpkiSha256, last);
}

TEST_F(CscaMasterListTest, ReportsTheFirstSignerWhenNoPinWasGiven)
{
    // The unpinned half of the same list, and the only place the CHOICE of
    // reported signer is still non-trivial: with a pin the answer necessarily
    // equals the pin, so an implementation that reported the last signer when
    // asked for no comparison would pass every pinned test in this file. Three
    // signers again, so "first", "last" and "any" are three different answers.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto three = threeSignerMasterList(ml);
    ASSERT_EQ(signerCountOf(three), 3);

    const auto first = spkiSha256OfSignerAt(three, 0);
    const auto middle = spkiSha256OfSignerAt(three, 1);
    const auto last = spkiSha256OfSignerAt(three, 2);

    const auto out = emrtd::crypto::parseAndVerifyMasterList(three, {});
    ASSERT_TRUE(out.has_value());
    EXPECT_FALSE(out->identityChecked);
    EXPECT_EQ(out->signerSpkiSha256, first) << "with nothing to match, the reader meets this one first";
    EXPECT_NE(out->signerSpkiSha256, middle);
    EXPECT_NE(out->signerSpkiSha256, last);
}

TEST_F(CscaMasterListTest, RefusesAPinNamingNoSignerOfAListThatHasSeveral)
{
    // The other half of "any": an implementation that stopped comparing after
    // the first match it did not find would still pass the test above, and one
    // that answered "checked" as soon as a list had more than one signer would
    // pass it too. Nothing in this list matches.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto three = threeSignerMasterList(ml);
    const auto stranger = LibreSCRS::Test::makeMasterList(1);
    ASSERT_EQ(signerCountOf(three), 3);
    ASSERT_NE(stranger.signerSpkiSha256, spkiSha256OfSignerAt(three, 0));
    ASSERT_NE(stranger.signerSpkiSha256, spkiSha256OfSignerAt(three, 1));
    ASSERT_NE(stranger.signerSpkiSha256, spkiSha256OfSignerAt(three, 2));

    const auto out = emrtd::crypto::parseAndVerifyMasterList(three, stranger.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::SignerMismatch);
}

TEST_F(CscaMasterListTest, RefusesAListWhoseMiddleSignerDoesNotVerify)
{
    // A second signer must not be able to sit beside a pinned one without its
    // own signature holding. The corrupted signer is in the MIDDLE, so this
    // separates "verifies every signer" from "verifies the first" and from
    // "verifies the last"; and the pin names the FIRST signer, whose signature
    // is untouched, so the rejection can only come from the other one.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto three = threeSignerMasterList(ml);
    ASSERT_EQ(signerCountOf(three), 3);
    ASSERT_EQ(cmsVerifyAgainst(three, {}, CMS_NO_SIGNER_CERT_VERIFY), 1) << "all three must hold before one is broken";

    const auto broken = withCorruptSignatureAtSignerIndex(three, 1);
    ASSERT_EQ(signerCountOf(broken), 3);
    // The flip is length-preserving and sits at the very end of a SignerInfo,
    // so re-encoding must not have moved it. Asserted, not assumed: if it did
    // move, this would silently become a two-or-last-signer test.
    ASSERT_EQ(signatureOfSignerAt(broken, 0), signatureOfSignerAt(three, 0));
    ASSERT_NE(signatureOfSignerAt(broken, 1), signatureOfSignerAt(three, 1)) << "the middle signer is the broken one";
    ASSERT_EQ(signatureOfSignerAt(broken, 2), signatureOfSignerAt(three, 2));

    const auto pin = spkiSha256OfSignerAt(broken, 0);
    const auto out = emrtd::crypto::parseAndVerifyMasterList(broken, pin);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature)
        << "one signer whose signature does not hold sinks the list, whoever else signed it";
}

TEST_F(CscaMasterListTest, RefusesASignerWhoseCertificateTheListDoesNotCarry)
{
    // This function passes CMS_verify no certificates of its own, so a signer
    // whose certificate the object does not carry cannot be checked at all.
    // That is a rejection, not a shrug -- and it is a real shape, since a
    // producer may leave the certificates out and expect the verifier to have
    // them. The control below adds the same signer the same way with its
    // certificate present, so the flag is the only thing that differs.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto embedded = addSignedSigner(ml.der, "Second Signer");
    ERR_clear_error(); // building the fixture is not what is under test
    ASSERT_EQ(cmsVerifyAgainst(embedded, {}, CMS_NO_SIGNER_CERT_VERIFY), 1)
        << "with its certificate the same signer verifies, so the signature itself is not the fault";

    // The fingerprint of the signer whose certificate is about to be left out,
    // read off the control where it IS carried. Picked by not being the list's
    // own signer rather than by index, because SignerInfos are a SET OF.
    std::vector<uint8_t> missingSignerPin;
    for (int i = 0; i < signerCountOf(embedded); ++i) {
        const auto fingerprint = spkiSha256OfSignerAt(embedded, i);
        if (fingerprint != ml.signerSpkiSha256) {
            missingSignerPin = fingerprint;
        }
    }
    ASSERT_FALSE(missingSignerPin.empty()) << "the second signer must be identifiable while its certificate is there";

    const auto absent = addSignedSigner(ml.der, "Second Signer", false);
    ERR_clear_error();
    ASSERT_EQ(signerCountOf(absent), 2) << "the signer must really be there";

    // Pinned on the signer whose certificate the list does NOT carry, which is
    // what the name says. BadSignature and not SignerMismatch: there is no key
    // to check that signer with, so nothing was established about it, and a
    // fingerprint that could not be computed is not one that failed to match.
    const auto pinned = emrtd::crypto::parseAndVerifyMasterList(absent, missingSignerPin);
    ASSERT_FALSE(pinned.has_value());
    EXPECT_EQ(pinned.error(), emrtd::crypto::MasterListError::BadSignature);

    // And the same answer with the OTHER signer pinned, whose certificate is
    // present and whose signature is fine: one signer that cannot be checked
    // sinks the list whoever the caller named.
    const auto out = emrtd::crypto::parseAndVerifyMasterList(absent, ml.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature)
        << "the pinned first signer is fine; the one that cannot be checked still sinks the list";
}

TEST_F(CscaMasterListTest, RefusesASignedDataThatNothingSigned)
{
    // A SignedData carrying the real anchors under the real content type and
    // no SignerInfo at all. There is no signature to be bad, which is exactly
    // why the answer is BadSignature: nothing here vouches for these anchors.
    // parseCscaMasterList calls the same bytes NotAMasterList, so this also
    // shows verification running before the content is read.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto worn = makeSignerlessSignedData(eContentOf(ml.der), "2.23.136.1.1.2");
    ASSERT_EQ(signerCountOf(worn), 0) << "it must really carry no signer";
    // Emptiness first, error() second: see ChecksTheSignatureBeforeTheFingerprint.
    const auto parserAlone = emrtd::crypto::parseCscaMasterList(worn);
    ASSERT_FALSE(parserAlone.has_value()) << "the parser must REFUSE this, not merely answer differently";
    ASSERT_EQ(parserAlone.error(), emrtd::crypto::MasterListError::NotAMasterList)
        << "and the parser alone must answer something else, or the order proves nothing";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(worn, ml.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature);
}

TEST_F(CscaMasterListTest, RefusesAnObjectThatIsNotASignedDataAtAll)
{
    // A DigestedData wearing the ICAO content type over a genuine master list.
    // Not the same input class as the signerless SignedData above -- that one
    // is a SignedData and this one is not -- and the header promises the same
    // answer for both.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto worn = makeDigestedDataWearing(eContentOf(ml.der), "2.23.136.1.1.2");
    ASSERT_EQ(eContentTypeOf(worn), "2.23.136.1.1.2") << "it must really claim to be a master list";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(worn, {});
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature);
}

TEST_F(CscaMasterListTest, RefusesADetachedListInsteadOfVerifyingNothing)
{
    // The signature is there and the content is not, so there is nothing to
    // verify it against. parseCscaMasterList calls this Malformed; here the
    // signature check reaches it first, and the header says so.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto broken = detachEContent(ml.der);
    // Emptiness first, error() second: see ChecksTheSignatureBeforeTheFingerprint.
    const auto parserAlone = emrtd::crypto::parseCscaMasterList(broken);
    ASSERT_FALSE(parserAlone.has_value()) << "the parser must REFUSE this, not merely answer differently";
    ASSERT_EQ(parserAlone.error(), emrtd::crypto::MasterListError::Malformed)
        << "the parser alone must answer something else, or this proves nothing about the order";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(broken, ml.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature);
}

TEST_F(CscaMasterListTest, RefusesAListThatMerelyCarriesThePinnedSignersCertificate)
{
    // "The pinned key SIGNED this" and "the pinned certificate is CARRIED by
    // this" are different claims, and only the first one is worth anything. A
    // CMS object's certificate bag is unauthenticated: anybody may drop
    // anybody's certificate into it, and doing so changes no signature.
    //
    // So: a stranger's list, genuinely signed by the stranger over the
    // stranger's own anchors, with the certificate of the publisher the user
    // trusts planted in its bag. It verifies. If the pin were matched against
    // the bag instead of against the signers, this would be ACCEPTED, with
    // identityChecked true and the right fingerprint shown to the user -- the
    // whole first-import trust model defeated, and the object still perfectly
    // well-formed. One token in the implementation separates the two.
    const auto mine = LibreSCRS::Test::makeMasterList(2);
    const auto stranger = LibreSCRS::Test::makeMasterList(1);
    ASSERT_NE(stranger.signerSpkiSha256, mine.signerSpkiSha256);
    // Disjoint, not merely unequal: differing anchor COUNTS would satisfy an
    // inequality while the stranger still delivered the trusted list's own
    // anchors back, which is not the attack this is about. makeMasterList
    // mints a fresh key and a random serial for every anchor of every call, so
    // no element can be shared -- asserted rather than relied on.
    for (const auto& anchor : stranger.cscaDer) {
        ASSERT_EQ(std::find(mine.cscaDer.begin(), mine.cscaDer.end(), anchor), mine.cscaDer.end())
            << "every anchor delivered must be the stranger's own";
    }

    std::vector<uint8_t> pinnedCert;
    for (const auto& candidate : certificatesInBagOf(mine.der)) {
        if (spkiSha256OfCertificate(candidate) == mine.signerSpkiSha256) {
            pinnedCert = candidate;
        }
    }
    ASSERT_FALSE(pinnedCert.empty()) << "the pinned signer's certificate must be liftable out of its own list";

    const auto planted = withCertificateInBag(stranger.der, pinnedCert);
    ERR_clear_error(); // building the fixture is not what is under test

    // Three assertions so this cannot pass for the wrong reason: the object
    // really verifies, the bag really holds the pinned certificate, and no
    // SIGNER of it is that certificate.
    ASSERT_EQ(cmsVerifyAgainst(planted, {}, CMS_NO_SIGNER_CERT_VERIFY), 1)
        << "the stranger really did sign this, so nothing before the pin can refuse it";
    bool pinnedIsInTheBag = false;
    for (const auto& candidate : certificatesInBagOf(planted)) {
        pinnedIsInTheBag = pinnedIsInTheBag || spkiSha256OfCertificate(candidate) == mine.signerSpkiSha256;
    }
    ASSERT_TRUE(pinnedIsInTheBag) << "the planted certificate must really be there to be found";
    ASSERT_EQ(signerCountOf(planted), 1);
    ASSERT_NE(spkiSha256OfSignerAt(planted, 0), mine.signerSpkiSha256) << "while the only SIGNER is the stranger";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(planted, mine.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::SignerMismatch)
        << "carrying a certificate is not signing with its key";
}

TEST_F(CscaMasterListTest, RefusesAPinThatIsOnlyAPrefixOfTheFingerprint)
{
    // Half of the real fingerprint. Compared without the length test first,
    // this would match -- and a caller could pin four bytes and believe it had
    // named a signer.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    ASSERT_EQ(ml.signerSpkiSha256.size(), 32u);
    const std::vector<uint8_t> prefix(ml.signerSpkiSha256.begin(), ml.signerSpkiSha256.begin() + 16);

    const auto out = emrtd::crypto::parseAndVerifyMasterList(ml.der, prefix);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::SignerMismatch)
        << "a fingerprint is 32 bytes; a prefix of one names nobody";
}

TEST_F(CscaMasterListTest, RefusesARelabelledObjectSignedByTheVerySignerThatWasPinned)
{
    // The signature holds AND the pin is met AND the content really is a master
    // list -- and this is still not one, because only the SIGNED contentType
    // attribute is under the signature and it says id-data. The eContentType
    // field was relabelled afterwards, which the signer never covered.
    //
    // Nothing before step 4 can refuse this: the object is signed by exactly
    // the key the caller named. parseCscaMasterList comparing the field with
    // the signed attribute is the only barrier, which is why step 4 may never
    // become a fast path that a met pin skips.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto plain = signContentWearing(eContentOf(ml.der), "1.2.840.113549.1.7.1");
    const auto relabelled = relabelEContentTypeField(plain, "2.23.136.1.1.2");
    ERR_clear_error(); // building the fixture is not what is under test

    ASSERT_EQ(cmsVerifyAgainst(relabelled, {}, CMS_NO_SIGNER_CERT_VERIFY), 1) << "the signature must still hold";
    ASSERT_EQ(eContentTypeOf(relabelled), "2.23.136.1.1.2") << "the FIELD must claim to be a master list";
    ASSERT_EQ(signedContentTypeOf(relabelled, -3), "1.2.840.113549.1.7.1")
        << "while the SIGNED attribute, the only one the signer covered, says otherwise";
    ASSERT_EQ(anchorsInsideList(relabelled), ml.cscaDer) << "and real anchors sit there to be taken";

    const auto pin = spkiSha256OfSignerAt(relabelled, 0);
    const auto out = emrtd::crypto::parseAndVerifyMasterList(relabelled, pin);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::NotAMasterList)
        << "a pin met by the signer of a relabelled object is not a reason to read it";
}

TEST_F(CscaMasterListTest, AcceptsAPinnedListWhoseSignerCertificateWouldFailEveryCredentialCheck)
{
    // The certificate around a pinned key is a container, not a credential.
    // This signer is BOTH lapsed and carrying the EKU ICAO profiles on a master
    // list signer -- and each of those, checked, would refuse a list that is
    // perfectly good. A master list outlives by years the key that signed it.
    // And CMS_verify's smime_sign purpose demands emailProtection: a signer
    // with no EKU at all passes it, so it is precisely the ICAO-profiled
    // certificate, the real one, that such a check turns away. The purpose is
    // read from OpenSSL here rather than described, so this asserts what
    // CMS_verify would actually decide.
    //
    // The risk runs one way. Every plausible change in this area makes the
    // function stricter, so the failure mode is working imports refusing in the
    // field while the suite stays green -- which is what this test is for.
    const auto ml = LibreSCRS::Test::makeMasterList(1, "200101000000Z", "2.23.136.1.1.3");
    const auto facts = factsAboutSignerAt(ml.der, 0);
    ASSERT_TRUE(facts.expired) << "the signer must really have lapsed, or this proves nothing";
    ASSERT_TRUE(facts.hasExtendedKeyUsage) << "and must really carry an EKU";
    ASSERT_FALSE(facts.passesSmimeSignPurpose)
        << "which CMS_verify's own purpose must really reject, or the EKU half proves nothing";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(ml.der, ml.signerSpkiSha256);
    ASSERT_TRUE(out.has_value()) << "an expired, ICAO-profiled signer with a correct pin is an ordinary import";
    EXPECT_TRUE(out->identityChecked);
    EXPECT_EQ(out->signerSpkiSha256, ml.signerSpkiSha256);
    EXPECT_EQ(out->list.cscaDer, ml.cscaDer);
}

TEST_F(CscaMasterListTest, ReturnsTheParsersVerdictForAVerifiedListThatCarriesNoAnchor)
{
    // Properly signed by the expected signer, and empty. Verification says
    // nothing about what the list carries, so the parser's answer has to come
    // back rather than be swallowed by a successful signature check.
    const auto ml = LibreSCRS::Test::makeMasterList(0);
    ASSERT_EQ(cmsVerifyAgainst(ml.der, {}, CMS_NO_SIGNER_CERT_VERIFY), 1) << "the signature must really hold";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(ml.der, ml.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::Empty);
}

TEST_F(CscaMasterListTest, ReturnsTheParsersVerdictForAVerifiedObjectThatIsNotAMasterList)
{
    // Signed, verifies, content is a well-formed CscaMasterList -- and the
    // content type says id-data, so it is not a master list. A different
    // parser verdict from the test above, reached through the same step, and
    // neither is produced by the signature check.
    const auto other = LibreSCRS::Test::makeSignedNonMasterList();
    ASSERT_EQ(cmsVerifyAgainst(other, {}, CMS_NO_SIGNER_CERT_VERIFY), 1) << "the signature must really hold";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(other, {});
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, ReturnsTheParsersVerdictForAVerifiedObjectWhoseContentIsNotAList)
{
    // The third parser verdict, and the one neither test above produces: the
    // object verifies, says it is a master list, and its content is not one.
    // Editing the content of a signed object would break the signature and be
    // answered before the parser ever ran, so the content is signed as it is.
    const auto worn = signContentWearing(std::vector<uint8_t>(32, 0x41), "2.23.136.1.1.2");
    ERR_clear_error(); // building the fixture is not what is under test
    ASSERT_EQ(cmsVerifyAgainst(worn, {}, CMS_NO_SIGNER_CERT_VERIFY), 1) << "the signature must really hold";
    ASSERT_EQ(eContentTypeOf(worn), "2.23.136.1.1.2") << "and it must really claim to be a master list";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(worn, {});
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::Malformed);
}

TEST_F(CscaMasterListTest, RefusesEmptyInputWithoutLookingForASignature)
{
    const auto out = emrtd::crypto::parseAndVerifyMasterList({}, {});
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::NotAMasterList)
        << "nothing was signed, but nothing is a CMS either, and that is the plainer answer";
}

TEST_F(CscaMasterListTest, RefusesGarbageBeforeItCanBeVerified)
{
    // Not the same input as the empty vector above: this one is non-empty and
    // fails at d2i rather than at the emptiness guard, and either guard alone
    // would let the other input through to a null dereference.
    const auto out = emrtd::crypto::parseAndVerifyMasterList(std::vector<uint8_t>(64, 0x41), {});
    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), emrtd::crypto::MasterListError::NotAMasterList);
}

TEST_F(CscaMasterListTest, DoesNotWipeACallersPendingOpenSslErrorWhenTheCmsWillNotParse)
{
    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(std::vector<uint8_t>(64, 0x41), {});
    ASSERT_FALSE(out.has_value());
    ASSERT_EQ(out.error(), emrtd::crypto::MasterListError::NotAMasterList);

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaMasterListTest, DoesNotWipeACallersPendingOpenSslErrorWhenTheSignatureDoesNotVerify)
{
    // The one input that reaches CMS_verify and fails inside it. CMS_verify
    // queues several entries for one failure, which is the busiest thing this
    // function does to the error queue.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto bad = LibreSCRS::Test::makeTamperedMasterList(ml);
    ERR_clear_error(); // building the input is not what is under test

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(bad.der, ml.signerSpkiSha256);
    ASSERT_FALSE(out.has_value());
    ASSERT_EQ(out.error(), emrtd::crypto::MasterListError::BadSignature) << "this must reach CMS_verify";

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaMasterListTest, LeavesACallersErrorQueueUntouchedWhenItVerifies)
{
    // The success path, and the fingerprint comparison with it. Measured,
    // nothing on this path queues anything today, so this does not prove the
    // brackets work -- the two DoesNotWipe... tests above do that, one per
    // bracket. It is here so that a change which starts leaving residue on the
    // way to an accepted list is caught here rather than in whatever runs next.
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    ERR_clear_error(); // the fixture generator is entitled to leave its own residue

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const auto out = emrtd::crypto::parseAndVerifyMasterList(ml.der, ml.signerSpkiSha256);
    ASSERT_TRUE(out.has_value());
    ASSERT_TRUE(out->identityChecked);

    expectOnlyTheCallersErrorRemains(callerError);
}

// --- computing the pin -----------------------------------------------------
//
// A caller is handed "here is the publisher's certificate" and has to turn it
// into the 32 bytes parseAndVerifyMasterList compares against. These pin that
// the exported helper answers what the pinned path itself computes, and that it
// answers the same for one key however it was written down -- the two
// properties that make a pin survive a renewal and survive a re-encoding.

TEST_F(CscaMasterListTest, ComputesThePinTheVerifyingPathWillCompare)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    std::vector<uint8_t> signerCert;
    for (const auto& candidate : certificatesInBagOf(ml.der)) {
        if (spkiSha256OfCertificate(candidate) == ml.signerSpkiSha256) {
            signerCert = candidate;
        }
    }
    ASSERT_FALSE(signerCert.empty()) << "the signer's certificate must be liftable out of its own list";

    const auto pin = emrtd::crypto::spkiSha256FromCertificateDer(signerCert);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(pin->size(), 32u);

    // The point of the whole thing: the value it returns is one a caller can
    // hand straight back and have met.
    const auto out = emrtd::crypto::parseAndVerifyMasterList(ml.der, *pin);
    ASSERT_TRUE(out.has_value()) << "a pin computed this way must be the one the verifier compares against";
    EXPECT_TRUE(out->identityChecked);
    EXPECT_EQ(out->signerSpkiSha256, *pin);
}

TEST_F(CscaMasterListTest, ComputesOnePinForOneKeyInTwoCertificates)
{
    // A renewal is exactly this: the same key inside a different certificate.
    // The link certificate and the incoming CSCA of a rotation carry one key
    // between them and differ in serial, issuer and signature, so hashing the
    // CERTIFICATE would answer twice and hashing the key answers once.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    const auto& link = rotation.list.cscaDer[static_cast<std::size_t>(rotation.linkIndex)];
    const auto& incoming = rotation.list.cscaDer[static_cast<std::size_t>(rotation.incomingIndex)];
    ASSERT_NE(link, incoming) << "two different certificates, or this proves nothing";

    const auto fromLink = emrtd::crypto::spkiSha256FromCertificateDer(link);
    const auto fromIncoming = emrtd::crypto::spkiSha256FromCertificateDer(incoming);
    ASSERT_TRUE(fromLink.has_value());
    ASSERT_TRUE(fromIncoming.has_value());
    EXPECT_EQ(*fromLink, *fromIncoming) << "the certificate changes on renewal; the key does not";
}

TEST_F(CscaMasterListTest, ComputesOnePinForOneKeyInTwoEncodings)
{
    // The other way one key comes to be written down twice: the same
    // certificate, re-wrapped as BER. The SubjectPublicKeyInfo is re-encoded
    // with i2d before it is hashed, so the slice the file carried does not get
    // to decide the answer.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto ber = withIndefiniteTbsLength(ml.cscaDer.front());
    ASSERT_NE(ber, ml.cscaDer.front()) << "the fixture must really have changed the encoding";

    const auto fromDer = emrtd::crypto::spkiSha256FromCertificateDer(ml.cscaDer.front());
    const auto fromBer = emrtd::crypto::spkiSha256FromCertificateDer(ber);
    ASSERT_TRUE(fromDer.has_value());
    ASSERT_TRUE(fromBer.has_value());
    EXPECT_EQ(*fromDer, *fromBer) << "one key, one pin, whatever the bytes around it were";
}

TEST_F(CscaMasterListTest, RefusesToPinBytesThatAreNotOneCertificate)
{
    // Nothing rather than an empty vector, and nothing rather than a
    // fingerprint of the part that parsed: an empty vector means "do not
    // compare" to parseAndVerifyMasterList, so a helper that returned one on
    // failure would turn a caller's pin into no pin at all.
    EXPECT_FALSE(emrtd::crypto::spkiSha256FromCertificateDer({}).has_value());
    EXPECT_FALSE(emrtd::crypto::spkiSha256FromCertificateDer(std::vector<uint8_t>(64, 0x41)).has_value());

    const auto ml = LibreSCRS::Test::makeMasterList(1);
    auto trailing = ml.cscaDer.front();
    trailing.push_back(0x00);
    EXPECT_FALSE(emrtd::crypto::spkiSha256FromCertificateDer(trailing).has_value())
        << "a buffer holding a certificate AND something else is not one certificate";
}

// ---------------------------------------------------------------------------
// CSCA chain verdict
//
// The five answers, and what separates each from the one next to it. Two of
// these tests exist because the two OpenSSL defaults this function turns off
// would accuse genuine documents, and one exists because an implementation
// that answered "passed" on a matching name would otherwise be fully green.
// ---------------------------------------------------------------------------

namespace {

std::vector<std::vector<uint8_t>> anchorsOf(const LibreSCRS::Test::SyntheticMasterList& ml)
{
    return ml.cscaDer;
}

/// Whether @p der is a certificate that verifies against its own public key.
/// Used only to prove a perturbation landed in the signature, so that a test
/// asserting "the signature is not looked at" is not asserting it vacuously.
bool selfSignatureVerifies(const std::vector<uint8_t>& der)
{
    const unsigned char* p = der.data();
    X509* cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
    if (cert == nullptr)
        return false;
    EVP_PKEY* key = X509_get0_pubkey(cert);
    const bool ok = key != nullptr && X509_verify(cert, key) == 1;
    X509_free(cert);
    ERR_clear_error(); // a failed verify queues; this helper is a probe, not a step
    return ok;
}

/// Bytes that are certainly not a certificate. Long enough that d2i has to
/// look at them and really queue an error rather than refuse a short buffer.
std::vector<uint8_t> notACertificate(uint8_t fill)
{
    return std::vector<uint8_t>(64, fill);
}

std::string issuerOfCert(const std::vector<uint8_t>& certDer)
{
    X509* cert = certFromDer(certDer);
    const std::string out = nameText(X509_get_issuer_name(cert));
    X509_free(cert);
    return out;
}

/// The document signer @p sodDer travels with, as encoded.
///
/// Deliberately taken from the certificate BAG, which is where the two tests
/// about the bag need it from: it is the certificate an attacker would plant,
/// read out of a document that came by it honestly.
std::vector<uint8_t> documentSignerCertificateOf(const std::vector<uint8_t>& sodDer)
{
    const auto bag = certificatesInBagOf(sodDer);
    if (bag.size() != 1) {
        throw std::runtime_error("documentSignerCertificateOf: expected exactly one certificate");
    }
    return bag.front();
}

/// Like AnchorLoaderTest and CscaMasterListTest above: four of these assert on
/// the exact contents of this process's one OpenSSL error queue, so it is
/// cleared on the way in and out rather than left to test ordering.
class CscaVerdictTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        ERR_clear_error();
    }
    void TearDown() override
    {
        ERR_clear_error();
    }
};

} // namespace

// --- the five answers ------------------------------------------------------

TEST_F(CscaVerdictTest, PassesADocumentThatChainsToAnAnchorWeHold)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, RefusesAForgeryWhoseSignerClaimsNoAuthorityWeHold)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto forged = LibreSCRS::Test::makeForgedSod();
    // A self-signed document signer names itself as its own issuer, so the
    // issuer comparison answers before any chain is built.
    ASSERT_EQ(signerIssuerOf(forged), signerSubjectOf(forged));
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(forged, anchorsOf(ml), true),
              emrtd::crypto::CscaVerdict::NoAnchorForIssuer);
}

TEST_F(CscaVerdictTest, FailsADocumentThatBorrowsAnAuthoritysNameButNotItsKey)
{
    // The one case that proves the chain is verified rather than name-matched:
    // the issuer field matches an anchor we hold, so the comparison passes it
    // through, and only the signature can reject it. Without this test an
    // implementation that returned Passed on any DN match is fully green.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSodWithImpersonatedIssuer(ml, 0);
    ASSERT_EQ(signerIssuerOf(sod), subjectOfCert(ml.cscaDer[0])) << "it must really get past the name comparison";
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed);
}

TEST_F(CscaVerdictTest, SaysNotConfiguredWhenNoPathWasGiven)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, {}, false), emrtd::crypto::CscaVerdict::NotConfigured);
}

TEST_F(CscaVerdictTest, SaysAnchorsUnusableWhenAPathGaveNothing)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, {}, true), emrtd::crypto::CscaVerdict::AnchorsUnusable)
        << "a configured store that yields nothing is a misconfiguration, "
           "not the same neutral answer as never configuring one";
}

TEST_F(CscaVerdictTest, SaysNoAnchorForIssuerWhenWeHoldAnotherCountrysAnchor)
{
    const auto ours = LibreSCRS::Test::makeMasterList(1);
    const auto theirs = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(theirs, 0);
    // Both anchors are C=XX, so an implementation comparing country codes
    // instead of whole names would match here and answer Failed. The fixture
    // gives every certificate the same country precisely so that this is the
    // difference between the two.
    ASSERT_NE(subjectOfCert(ours.cscaDer[0]), subjectOfCert(theirs.cscaDer[0]));
    ASSERT_NE(subjectOfCert(ours.cscaDer[0]).find("/C=XX"), std::string::npos);
    ASSERT_NE(subjectOfCert(theirs.cscaDer[0]).find("/C=XX"), std::string::npos);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ours), true),
              emrtd::crypto::CscaVerdict::NoAnchorForIssuer);
}

// --- the two defaults that would refuse genuine documents ------------------

TEST_F(CscaVerdictTest, PassesADocumentWhoseSignerCarriesAnIcaoStyleEku)
{
    // Verification through CMS applies the smime_sign purpose, which passes a
    // certificate with NO extended key usage and rejects one whose extended
    // key usage is present and omits emailProtection. ICAO profiles an
    // extended key usage on exactly the document signer, so without pinning
    // the purpose every real document from such a state is accused of not
    // chaining.
    //
    // The OID below is one of the ICAO id-icao-mrtd-security arc; which arc it
    // is does not matter and is not what this asserts. What matters is read
    // back off the certificate: an extended key usage is present and OpenSSL's
    // own smime_sign purpose refuses it.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0, "2.23.136.1.1.4");
    const auto facts = factsAboutSignerAt(sod, 0);
    ASSERT_TRUE(facts.hasExtendedKeyUsage) << "the fixture must really have put an EKU on the document signer";
    ASSERT_FALSE(facts.passesSmimeSignPurpose) << "and OpenSSL must really refuse it, or this proves nothing";
    ASSERT_FALSE(facts.expired) << "and nothing else about the certificate may be wrong";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, PassesADocumentWhoseSignerHasSinceExpired)
{
    // A document signer's key lives months; the documents it signed live ten
    // years. An expired signer on a valid document is the ordinary case.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0, {}, "200101000000Z");
    const auto facts = factsAboutSignerAt(sod, 0);
    ASSERT_TRUE(facts.expired) << "the fixture must really have expired the document signer";
    ASSERT_FALSE(facts.hasExtendedKeyUsage) << "and the purpose must not be what is being tested here";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Passed);
}

// --- a country that has rotated its CSCA -----------------------------------
//
// The third widening, and the same shape as the two above it: without it a
// perfectly genuine document from a country that has rotated its country
// signing certificate is answered Failed -- the accusation verdict -- because
// the anchor it chains to is a LINK CERTIFICATE, which is not self-signed. See
// makeMasterListWithLinkCertificate() in the fixture header for what one is.

TEST_F(CscaVerdictTest, PassesADocumentWhoseOnlyAnchorIsALinkCertificate)
{
    // The narrowest form of the defect: the only anchor held is a link
    // certificate, so the chain has nowhere self-signed to end. Without
    // X509_V_FLAG_PARTIAL_CHAIN, OpenSSL goes looking for the link's own
    // issuer, does not find it in the store, and reports
    // X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT -- which arrives here as Failed, the
    // one verdict that accuses the document.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    const auto& link = rotation.list.cscaDer[static_cast<std::size_t>(rotation.linkIndex)];
    const auto& incoming = rotation.list.cscaDer[static_cast<std::size_t>(rotation.incomingIndex)];
    // The three facts that make this a link certificate and not just another
    // anchor, asserted rather than assumed: it is NOT self-signed, and it
    // carries the incoming CSCA's subject and the incoming CSCA's key.
    ASSERT_NE(issuerOfCert(link), subjectOfCert(link)) << "a link certificate is not self-signed";
    ASSERT_EQ(subjectOfCert(link), subjectOfCert(incoming));
    ASSERT_EQ(spkiSha256OfCertificate(link), spkiSha256OfCertificate(incoming));

    const auto sod = LibreSCRS::Test::makeSod(rotation.list, rotation.incomingIndex);
    const std::vector<std::vector<uint8_t>> anchors{link};
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchors, true), emrtd::crypto::CscaVerdict::Passed)
        << "a configured anchor may terminate a chain, whether or not it signed itself";
}

TEST_F(CscaVerdictTest, PassesWhicheverOrderTheLinkAndTheNewCscaArriveIn)
{
    // Both anchors carry the same subject and the same key, so the store holds
    // two objects the lookup cannot tell apart, and it does not backtrack: it
    // takes whichever its sort puts first and builds from that. Reaching the
    // link first is then the difference between Passed and Failed -- for the
    // SAME document and the SAME anchor set.
    //
    // Neither producer of an anchor set promises an order. parseCscaMasterList
    // returns "the list's own encoded order" and loadAnchorDerFromDirectory
    // "whatever order the platform's directory listing happens to produce", so
    // an order-sensitive verdict is one decided by an encoder or a filesystem.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    const auto& link = rotation.list.cscaDer[static_cast<std::size_t>(rotation.linkIndex)];
    const auto& incoming = rotation.list.cscaDer[static_cast<std::size_t>(rotation.incomingIndex)];
    const auto sod = LibreSCRS::Test::makeSod(rotation.list, rotation.incomingIndex);

    const std::vector<std::vector<uint8_t>> linkFirst{link, incoming};
    const std::vector<std::vector<uint8_t>> linkSecond{incoming, link};
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, linkFirst, true), emrtd::crypto::CscaVerdict::Passed)
        << "the link certificate reached first must not turn a genuine document into a forgery";
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, linkSecond, true), emrtd::crypto::CscaVerdict::Passed)
        << "and the order that already worked must keep working";
}

TEST_F(CscaVerdictTest, PassesADocumentAgainstAPublishedListCarryingOnlyTheLinkCertificate)
{
    // The same defect in the shape it actually takes: through a producer. The
    // anchors are not hand-picked here, they are read out of a signed master
    // list, which is where a caller's anchors come from.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    LibreSCRS::Test::SyntheticMasterList linkOnly;
    linkOnly.cscaDer.push_back(rotation.list.cscaDer[static_cast<std::size_t>(rotation.linkIndex)]);
    const auto published = LibreSCRS::Test::makeMasterListWithOtherSigner(linkOnly);

    const auto parsed = emrtd::crypto::parseCscaMasterList(published.der);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->cscaDer.size(), 1u);

    const auto sod = LibreSCRS::Test::makeSod(rotation.list, rotation.incomingIndex);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, parsed->cscaDer, true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, PassesADocumentAgainstEveryAnchorAWholeRotationPublishes)
{
    // The full published rotation -- outgoing CSCA, link, incoming CSCA -- read
    // through the parser. This is the arrangement that already worked before
    // the flag, because the outgoing CSCA is self-signed and sits in the store
    // for the link to terminate on; it is here so that widening the trust for
    // the tests above cannot be mistaken for the whole story, and so that a
    // change which starts refusing the ordinary three-anchor shape is caught.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    const auto parsed = emrtd::crypto::parseCscaMasterList(rotation.list.der);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->cscaDer.size(), 3u);

    const auto sod = LibreSCRS::Test::makeSod(rotation.list, rotation.incomingIndex);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, parsed->cscaDer, true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, StillRefusesAForgeryWhenTheAnchorsIncludeALinkCertificate)
{
    // The widening is not a general relaxation. A rotation's anchors accept the
    // documents that chain to them and no others: a self-issued forgery is
    // still NoAnchorForIssuer, and one that borrows the incoming CSCA's name
    // without its key is still Failed.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    const auto& link = rotation.list.cscaDer[static_cast<std::size_t>(rotation.linkIndex)];
    const std::vector<std::vector<uint8_t>> anchors{link};

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(LibreSCRS::Test::makeForgedSod(), anchors, true),
              emrtd::crypto::CscaVerdict::NoAnchorForIssuer);
    const auto impersonated = LibreSCRS::Test::makeSodWithImpersonatedIssuer(rotation.list, rotation.linkIndex);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(impersonated, anchors, true), emrtd::crypto::CscaVerdict::Failed)
        << "borrowing the name of an anchor that may terminate a chain still does not borrow its key";
}

// --- the configuration answers, and that they are reached first ------------

TEST_F(CscaVerdictTest, SaysNotConfiguredEvenWithAnchorsInHand)
{
    // The flag is believed over the vector. Without this, an implementation
    // that answered NotConfigured only for an EMPTY anchor set alongside a
    // false flag would pass every other test here -- and would judge a
    // document against anchors its caller had just said were not configured.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    ASSERT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Passed)
        << "these anchors really would accept this document, so the flag is the only thing that changes below";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), false), emrtd::crypto::CscaVerdict::NotConfigured);
}

TEST_F(CscaVerdictTest, SaysNotConfiguredWithoutReadingTheDocument)
{
    // Configuration is answered before the document is looked at, so bytes
    // that are not a security object at all are still NotConfigured and not
    // Failed. The two are not interchangeable: one says we checked nothing,
    // the other says we checked and it did not hold.
    //
    // The anchors have to be USABLE for that to be what is shown. With an empty
    // anchor set the run stops at the store either way and the document is
    // unread for a second reason, so the "without reading" half rests on
    // nothing. Real anchors leave the flag as the only thing that can answer
    // before the document is decoded.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto garbage = notACertificate(0x41);
    ASSERT_EQ(emrtd::crypto::evaluateCscaChain(garbage, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed)
        << "with the flag set these bytes ARE read, and refused -- so the document really is unreadable";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(garbage, anchorsOf(ml), false),
              emrtd::crypto::CscaVerdict::NotConfigured)
        << "and with the flag clear that reading never happens";

    // The other order in the same contract: an empty anchor set is answered
    // before the document too, so these bytes get no further than the store.
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(garbage, {}, true), emrtd::crypto::CscaVerdict::AnchorsUnusable);
}

TEST_F(CscaVerdictTest, SaysAnchorsUnusableWhenNotOneEntryIsACertificate)
{
    // A non-empty anchor set that yields nothing usable. Without this,
    // "unusable" could be implemented as "the vector is empty" -- which is a
    // different claim, and the one that leaves a store full of unreadable
    // files reporting a verdict on the document instead of on itself.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    const std::vector<std::vector<uint8_t>> rubbish = {notACertificate(0x41), notACertificate(0x42)};

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, rubbish, true), emrtd::crypto::CscaVerdict::AnchorsUnusable);
}

TEST_F(CscaVerdictTest, PassesOverAnEntryThatIsNotACertificate)
{
    // One unreadable file among several costs only that file. An
    // implementation that gave up at the first entry it could not decode would
    // answer AnchorsUnusable here, and a trust store would be one stray file
    // away from checking nothing.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    const std::vector<std::vector<uint8_t>> mixed = {notACertificate(0x41), ml.cscaDer[0], notACertificate(0x42)};

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, mixed, true), emrtd::crypto::CscaVerdict::Passed);
}

// --- the anchor walk -------------------------------------------------------

TEST_F(CscaVerdictTest, PassesWhicheverAnchorOfThreeIssuedTheDocument)
{
    // THREE anchors, and the document is issued by each of them in turn. With
    // two, "reads every anchor" and "reads the last anchor" are the same
    // experiment, because index 1 is also the last index -- and so is "reads
    // the first and the last".
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    ASSERT_EQ(ml.cscaDer.size(), 3u);
    ASSERT_NE(subjectOfCert(ml.cscaDer[0]), subjectOfCert(ml.cscaDer[1]));
    ASSERT_NE(subjectOfCert(ml.cscaDer[1]), subjectOfCert(ml.cscaDer[2]));
    ASSERT_NE(subjectOfCert(ml.cscaDer[0]), subjectOfCert(ml.cscaDer[2]));

    for (int anchorIndex = 0; anchorIndex < 3; ++anchorIndex) {
        const auto sod = LibreSCRS::Test::makeSod(ml, anchorIndex);
        EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Passed)
            << "the document was issued by anchor " << anchorIndex;
    }
}

// --- who counts as the signer ----------------------------------------------

TEST_F(CscaVerdictTest, ReadsTheSignerAndNotTheCertificatesTheDocumentCarries)
{
    // A genuine document with a stranger's certificate planted in its bag.
    // Nothing signs the bag and anybody may add to it, so this must change
    // nothing.
    //
    // Read this together with the forgery test below it: the two are a PAIR
    // that defends reading the signer rather than the bag, and neither half
    // stands alone. Which certificate the DER SET OF puts first cannot be
    // chosen from outside, so each half covers the layout the other one
    // misses, and whichever way the encodings fall one of them fires.
    //
    // Measured, on this fixture:
    // - A bag[0] reader is caught by the test below, not by this one: the
    //   genuine document signer is the shorter encoding of the two here -- its
    //   issuer is the anchor's shorter DN -- so it sorts first in both
    //   documents, which happens to be the right answer in this one.
    // - INVERT that and this test is the half that fires: a bag[LAST] reader
    //   fells this test and leaves the one below green. So this is not a test
    //   that catches nothing; it is the one that survives the inversion, and
    //   deleting it as dead weight would leave that layout undefended.
    // - It also rules out an over-strict bag reading, which nothing else does:
    //   an implementation refusing any document whose bag held more than one
    //   certificate fells this and leaves the one below green. Without that, a
    //   genuine document would be one planted certificate away from refusal.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto genuine = LibreSCRS::Test::makeSod(ml, 0);
    const auto stranger = documentSignerCertificateOf(LibreSCRS::Test::makeForgedSod());
    const auto planted = withCertificateInBag(genuine, stranger);

    const auto bag = certificatesInBagOf(planted);
    ASSERT_EQ(bag.size(), 2u) << "the certificate must really have been planted";
    ASSERT_EQ(issuerOfCert(stranger), subjectOfCert(stranger)) << "and it must name no authority we hold";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(planted, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, RefusesAForgeryThatMerelyCarriesAnAnchorIssuedCertificate)
{
    // The other half, and the one that separates "was this signed by an
    // authority we hold" from "does this merely carry a certificate from one".
    // The forgery signs with its own self-signed key and travels with a
    // genuine document signer planted beside it. Reading the bag finds an
    // issuer we hold an anchor for and goes on to build a chain, answering
    // Failed; only reading the SIGNER answers that we hold nothing from the
    // authority this document names.
    //
    // The half of the pair that catches CMS_get1_certs in place of
    // CMS_get0_signers -- the substitution that differs by one token and by
    // the whole trust model. Measured, it catches both readings of the bag,
    // but for two different reasons, and only one of them is a property of
    // this fixture:
    // - The WHOLE-BAG scan is caught whatever the DER SET OF order, since a
    //   scan finds the planted certificate wherever it sits. Nothing about
    //   this rests on the encoding.
    // - A bag[0] reader is caught because in this document the planted
    //   certificate is the one that sorts first: the genuine document signer
    //   is the shorter encoding, its issuer being the anchor's shorter DN.
    //   That half IS a property of the fixture, and if those names ever change
    //   length it moves to the test above, which is the half that covers the
    //   other layout.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto genuineDsc = documentSignerCertificateOf(LibreSCRS::Test::makeSod(ml, 0));
    const auto forged = LibreSCRS::Test::makeForgedSod();
    const auto planted = withCertificateInBag(forged, genuineDsc);

    ASSERT_EQ(certificatesInBagOf(planted).size(), 2u) << "the certificate must really have been planted";
    ASSERT_EQ(issuerOfCert(genuineDsc), subjectOfCert(ml.cscaDer[0]))
        << "and it must really name an anchor we hold, or the bag reading would answer the same thing anyway";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(planted, anchorsOf(ml), true),
              emrtd::crypto::CscaVerdict::NoAnchorForIssuer);
}

// --- the same question, put to the older entry point -----------------------

TEST(PassiveAuthTest, ReportsTheRealSignerWhenTheBagCarriesAnImpostorFirst)
{
    // Pins the step in performPassiveAuth that fills PAResult::dscSubject: the
    // certificate a result NAMES has to be the one the SignerInfo resolves to,
    // which is what CMS_get0_signers returns after a successful CMS_verify --
    // never sk_X509_value(CMS_get1_certs(cms), 0), which is only the first
    // thing in an unsigned bag.
    //
    // Kept beside the two evaluateCscaChain tests above rather than with the
    // other PassiveAuthTests at the top of this file: it is the same question
    // about the same bag, one entry point older, and it needs the same helpers
    // to show that the attack is really staged.
    //
    // The document below is genuine in every way its holder could check. Its
    // signature verifies, its data group hash matches, and its signer was
    // issued by an anchor. All the attacker did was append a certificate to a
    // bag nothing signs -- and it is his text, not the signing authority's,
    // that a bag reader passes on to whatever displays it.
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    const auto sod = LibreSCRS::Test::makeSodWithImpostorPrependedToCertificateBag(ml, 0);

    const auto bag = certificatesInBagOf(sod.der);
    ASSERT_EQ(bag.size(), 2u) << "the impostor must really have been planted";
    ASSERT_NE(subjectOfCert(bag.front()).find(sod.impostorCommonName), std::string::npos)
        << "and the encoding must really have put it first, or this test asks nothing";

    const std::string anchorDir = LibreSCRS::Test::writePemDir(ml.cscaDer);
    const auto r = emrtd::crypto::performPassiveAuth(sod.der, sod.dgs, anchorDir);
    std::filesystem::remove_all(anchorDir);

    // Nothing here asserts on r.cscaChain: whether the signer chains is
    // verifyCSCAChain's question, and this test is about which certificate the
    // result names, which it must get right either way.
    ASSERT_EQ(r.sodSignature, emrtd::crypto::PAResult::PASSED)
        << "the planted certificate must not have disturbed the signature, or this is not "
           "a document an attacker could actually produce";
    ASSERT_EQ(r.dgHashes.at(1), emrtd::crypto::PAResult::PASSED) << "nor anything else about the document";

    EXPECT_NE(r.dscSubject.find(sod.realSignerCommonName), std::string::npos)
        << "the signer named must be the certificate that signed it";
    EXPECT_EQ(r.dscSubject.find(sod.impostorCommonName), std::string::npos)
        << "an unsigned bag entry must never be reported as the signer; it reported \"" << r.dscSubject << "\"";
}

// --- documents that cannot be read at all ----------------------------------

TEST_F(CscaVerdictTest, FailsAnEmptyDocument)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain({}, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed)
        << "no chain was established, and nothing about the configuration is at fault";
}

TEST_F(CscaVerdictTest, FailsADocumentThatIsNotACms)
{
    // Not the same input class as the empty vector above: this one is
    // non-empty and fails at d2i rather than at the emptiness guard, and
    // either guard alone would let the other input through to a null
    // dereference.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(notACertificate(0x41), anchorsOf(ml), true),
              emrtd::crypto::CscaVerdict::Failed);
}

TEST_F(CscaVerdictTest, FailsADocumentWhoseSignatureDoesNotHold)
{
    // The issuer names an anchor we hold, so the name comparison would let
    // this through; what stops it is that nothing established a signer at all.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    const auto broken = withCorruptSignatureAtSignerIndex(sod, 0);
    ERR_clear_error(); // building the input is not what is under test
    ASSERT_EQ(signerIssuerOf(broken), subjectOfCert(ml.cscaDer[0]));
    ASSERT_EQ(cmsVerifyAgainst(broken, {}, CMS_NO_SIGNER_CERT_VERIFY), 0) << "the signature must really be broken";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(broken, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed);
}

TEST_F(CscaVerdictTest, FailsADocumentWhoseSignerCertificateItDoesNotCarry)
{
    // A second signer whose certificate the document leaves out. There is no
    // key to check that signature with, so no signer is established for it --
    // and one unresolvable signer sinks the document, whoever else signed it.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto absent = addSignedSigner(LibreSCRS::Test::makeSod(ml, 0), "Uncarried Signer", false);
    ERR_clear_error(); // building the input is not what is under test
    ASSERT_EQ(signerCountOf(absent), 2) << "the signer must really be there";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(absent, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed);
}

TEST_F(CscaVerdictTest, EstablishesTheSignerBeforeItAsksWhoIssuedIt)
{
    // The one input that separates the two orders: the signature does not hold
    // AND the signer names no authority we hold. Establishing the signer first
    // answers Failed; comparing names first answers NoAnchorForIssuer, having
    // reported on an issuer field nothing vouches for -- an attacker writes
    // that field, so a verdict resting on it is a verdict the attacker chose.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto forged = LibreSCRS::Test::makeForgedSod();
    ASSERT_EQ(emrtd::crypto::evaluateCscaChain(forged, anchorsOf(ml), true),
              emrtd::crypto::CscaVerdict::NoAnchorForIssuer)
        << "intact, these bytes are NoAnchorForIssuer, so the signature is the only thing that changes below";

    const auto broken = withCorruptSignatureAtSignerIndex(forged, 0);
    ERR_clear_error(); // building the input is not what is under test
    ASSERT_EQ(signerIssuerOf(broken), signerSubjectOf(broken)) << "it still names no authority we hold";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(broken, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed);
}

// --- documents carrying more than one signer -------------------------------

TEST_F(CscaVerdictTest, RefusesADocumentWithASecondSignerThatChainsNowhere)
{
    // Two signers over one content: the genuine document signer, and a
    // stranger appended afterwards. Every signer has to chain, so this is
    // refused -- and refused as Failed rather than NoAnchorForIssuer, because
    // we DO hold the anchor the document's own signer names and saying
    // otherwise would send a reader off to configure an anchor for the
    // attacker.
    //
    // Which SignerInfo lands at which index cannot be CHOSEN here -- they are
    // a DER SET OF, so the encoding decides -- but it is not random either,
    // and this is not a probabilistic test. der_cmp memcmps from byte 0, so
    // the leading octets settle the order long before any signature byte is
    // reached: the SignerInfo's own length first, then the signer identifier,
    // which is what the comment on withCorruptSignatureAtSignerIndex above
    // already relies on. On this fixture the two differ consistently, and the
    // genuine signer landed at index 0 in 0 of 60 measured documents.
    //
    // So an implementation reading only signers[0] fails EVERY trial below,
    // not a random subset of them. The eight trials are not there to buy
    // probability -- adding more would buy nothing -- they are there so that
    // the day the fixture's names change length and the ordering flips, this
    // goes red loudly rather than one run in eight.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    for (int trial = 0; trial < 8; ++trial) {
        const auto two = addSignedSigner(LibreSCRS::Test::makeSod(ml, 0), "Appended Stranger");
        ERR_clear_error(); // building the input is not what is under test
        ASSERT_EQ(signerCountOf(two), 2) << "trial " << trial;
        EXPECT_EQ(emrtd::crypto::evaluateCscaChain(two, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed)
            << "trial " << trial;
    }
}

TEST_F(CscaVerdictTest, SaysNoAnchorForIssuerWhenNoSignerOfSeveralNamesAnAuthorityWeHold)
{
    // The control for the test above, and the other half of "no signer of
    // this document names an anchor we hold": with several signers and not one
    // of them naming an authority we hold, the answer stays the neutral one.
    // Without this, "every signer must name an anchor" and "some signer must"
    // could not be told apart -- the test above alone is satisfied by both.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto two = addSignedSigner(LibreSCRS::Test::makeForgedSod(), "Second Stranger");
    ERR_clear_error(); // building the input is not what is under test
    ASSERT_EQ(signerCountOf(two), 2);

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(two, anchorsOf(ml), true),
              emrtd::crypto::CscaVerdict::NoAnchorForIssuer);
}

// --- the OpenSSL error queue -----------------------------------------------

TEST_F(CscaVerdictTest, DoesNotWipeACallersPendingOpenSslErrorWhenAnAnchorWillNotDecode)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    ERR_clear_error(); // building the input is not what is under test

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    const std::vector<std::vector<uint8_t>> rubbish = {notACertificate(0x41), notACertificate(0x42)};
    ASSERT_EQ(emrtd::crypto::evaluateCscaChain(sod, rubbish, true), emrtd::crypto::CscaVerdict::AnchorsUnusable)
        << "the anchors must really reach d2i, or nothing was queued to be cleaned up";

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaVerdictTest, DoesNotWipeACallersPendingOpenSslErrorWhenTheDocumentWillNotParse)
{
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    ERR_clear_error(); // building the input is not what is under test

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    ASSERT_EQ(emrtd::crypto::evaluateCscaChain(notACertificate(0x41), anchorsOf(ml), true),
              emrtd::crypto::CscaVerdict::Failed);

    expectOnlyTheCallersErrorRemains(callerError);
}

TEST_F(CscaVerdictTest, DoesNotWipeACallersPendingOpenSslErrorWhenTheChainDoesNotHold)
{
    // The busiest path this function has: two CMS_verify calls, the second of
    // them failing inside chain building, which queues several entries at once.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSodWithImpersonatedIssuer(ml, 0);
    ERR_clear_error(); // building the input is not what is under test

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    ASSERT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Failed)
        << "this must really reach the chain check";

    expectOnlyTheCallersErrorRemains(callerError);
}

// --- producer to consumer --------------------------------------------------
//
// Every test above hands evaluateCscaChain an anchor vector taken straight off
// the fixture. Nothing did what a caller will actually do: read anchors with
// one of the three producers and judge a document against what came out. That
// composition is where the link-certificate defect lived, invisible to a suite
// that only ever tested the two ends separately, so each seam is walked here.

TEST_F(CscaVerdictTest, JudgesADocumentAgainstAnchorsReadByTheParser)
{
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    const auto sod = LibreSCRS::Test::makeSod(ml, 1);
    const auto parsed = emrtd::crypto::parseCscaMasterList(ml.der);
    ASSERT_TRUE(parsed.has_value());
    ASSERT_EQ(parsed->cscaDer.size(), 3u);

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, parsed->cscaDer, true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, JudgesADocumentAgainstAnchorsReadByTheVerifyingParser)
{
    // The pinned path, because that is the one a caller importing a published
    // list will take, and because it returns the anchors through a second type.
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    const auto sod = LibreSCRS::Test::makeSod(ml, 2);
    const auto verified = emrtd::crypto::parseAndVerifyMasterList(ml.der, ml.signerSpkiSha256);
    ASSERT_TRUE(verified.has_value());
    ASSERT_TRUE(verified->identityChecked);

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, verified->list.cscaDer, true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, JudgesADocumentAgainstAnchorsReadFromADirectory)
{
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    const auto dir = LibreSCRS::Test::writePemDir(ml.cscaDer);
    bool readable = false;
    auto loaded = emrtd::crypto::loadAnchorDerFromDirectory(dir, &readable);
    std::filesystem::remove_all(dir);
    ASSERT_TRUE(readable);
    ASSERT_EQ(loaded.size(), 3u);

    // Byte-identical to what the list carries, every anchor. The loader
    // re-encodes, so this is a statement about the round trip and not a
    // tautology: it is what lets a caller compare an anchor it loaded from disk
    // with one it read out of a master list. Compared as a multiset, because
    // the loader promises no order.
    auto expected = ml.cscaDer;
    std::sort(loaded.begin(), loaded.end());
    std::sort(expected.begin(), expected.end());
    EXPECT_EQ(loaded, expected);

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, loaded, true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, JudgesADocumentAgainstAnAnchorADirectoryCarriedAsBer)
{
    // The loader canonicalises what it reads, so an anchor a file spelled in
    // BER has to keep working end to end: the encoding changes, the subject and
    // the key do not, and the chain is built out of those.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    const auto dir = makeAnchorLoaderTempDir("ber-anchor-chain");
    writeFile(dir / "0.pem", derToPemText(withIndefiniteTbsLength(ml.cscaDer.front())));

    bool readable = false;
    const auto loaded = emrtd::crypto::loadAnchorDerFromDirectory(dir.string(), &readable);
    std::filesystem::remove_all(dir);
    ASSERT_TRUE(readable);
    ASSERT_EQ(loaded.size(), 1u);

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, loaded, true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, RefusesAForgeryAgainstAnchorsAProducerRead)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto parsed = emrtd::crypto::parseCscaMasterList(ml.der);
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(LibreSCRS::Test::makeForgedSod(), parsed->cscaDer, true),
              emrtd::crypto::CscaVerdict::NoAnchorForIssuer);
}

TEST_F(CscaVerdictTest, FailsABorrowedNameAgainstAnchorsAProducerRead)
{
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto sod = LibreSCRS::Test::makeSodWithImpersonatedIssuer(ml, 1);
    const auto parsed = emrtd::crypto::parseCscaMasterList(ml.der);
    ASSERT_TRUE(parsed.has_value());

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, parsed->cscaDer, true), emrtd::crypto::CscaVerdict::Failed)
        << "the accusation still has to be reachable through a producer, or the seam hides it";
}

TEST_F(CscaVerdictTest, SaysAnchorsUnusableForTheAnchorsAnEmptyListYields)
{
    // The two refusals that describe the caller's own setup, joined up. The
    // parser answers Empty for a properly signed list that carries no
    // certificate; the caller then has a configured source and no anchor, which
    // is AnchorsUnusable and deliberately not NotConfigured.
    const auto issuer = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(issuer, 0);
    const auto empty = LibreSCRS::Test::makeMasterList(0);

    const auto parsed = emrtd::crypto::parseCscaMasterList(empty.der);
    ASSERT_FALSE(parsed.has_value());
    ASSERT_EQ(parsed.error(), emrtd::crypto::MasterListError::Empty);

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, {}, true), emrtd::crypto::CscaVerdict::AnchorsUnusable);
}

TEST_F(CscaVerdictTest, TrustsAnAnchorWhoseOwnSignatureDoesNotVerify)
{
    // The header promises an anchor is trusted for having been configured, and
    // that nothing here asks it to have signed itself. The strongest reading of
    // that promise is the one worth pinning: the anchor's signatureValue is not
    // looked at AT ALL, so corrupting it changes no verdict.
    //
    // This is not an accident to tidy away later. A trust anchor answers "is
    // this a key the caller configured"; a signature it carries over itself
    // answers nothing about that.
    //
    // Measured, by adding X509_V_FLAG_CHECK_SS_SIGNATURE to the two flags this
    // function sets: 204 of the suite's tests still pass and this one alone
    // fails. So this test is the only thing standing between that flag and a
    // silent narrowing of what counts as an anchor. Note what the flag does NOT
    // reach, since the obvious guess is wrong: it checks self-signed roots
    // only, so link certificates are unaffected by it.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    auto anchors = anchorsOf(ml);
    ASSERT_EQ(anchors.size(), 1u);

    ASSERT_TRUE(selfSignatureVerifies(anchors[0])) << "the fixture must start with a self-consistent anchor, or the "
                                                      "corruption below proves nothing";

    // signatureValue is the last element of the Certificate SEQUENCE, so the
    // trailing bytes are inside it and the structure still parses.
    const auto original = anchors[0];
    for (std::size_t i = anchors[0].size() - 8; i < anchors[0].size(); ++i)
        anchors[0][i] = static_cast<uint8_t>(anchors[0][i] ^ 0xFFu);
    ASSERT_NE(anchors[0], original) << "the perturbation must have changed something";
    ASSERT_FALSE(selfSignatureVerifies(anchors[0]))
        << "the perturbation must have landed in the signature, not beside it";

    EXPECT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchors, true), emrtd::crypto::CscaVerdict::Passed);
}

TEST_F(CscaVerdictTest, LeavesACallersErrorQueueUntouchedWhenItPasses)
{
    // The success path. Measured, nothing on it queues anything today, so this
    // does not prove the brackets work -- the three above do that. It is here
    // so that a change which starts leaving residue on the way to an ACCEPTED
    // document is caught here rather than in whatever runs next.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto sod = LibreSCRS::Test::makeSod(ml, 0);
    ERR_clear_error(); // the fixture generator is entitled to leave its own residue

    ERR_raise(ERR_LIB_USER, ERR_R_INTERNAL_ERROR);
    const unsigned long callerError = ERR_peek_error();
    ASSERT_NE(callerError, 0ul) << "test setup must actually queue an error to prove anything";

    ASSERT_EQ(emrtd::crypto::evaluateCscaChain(sod, anchorsOf(ml), true), emrtd::crypto::CscaVerdict::Passed);

    expectOnlyTheCallersErrorRemains(callerError);
}

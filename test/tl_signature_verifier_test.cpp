// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "tl_signature_verifier.h"
#include "pinned_tl_certs.h"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>

using namespace libresign;

namespace {

// Read a file into a byte vector (returns empty on failure).
std::vector<uint8_t> readFile(const std::string& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f)
        return {};
    return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
}

// Download Serbian TL if not cached.
std::vector<uint8_t> getSerbianTl()
{
    const std::string cachePath = "/tmp/tsl-rs.xml";
    auto data = readFile(cachePath);
    if (!data.empty())
        return data;

    // Try downloading
    int rc = std::system(
        "curl -sS -o /tmp/tsl-rs.xml "
        "'https://www.mit.gov.rs/tsl/TSL-RS.xml' 2>/dev/null");
    if (rc != 0)
        return {};
    return readFile(cachePath);
}

} // namespace

class TlSignatureVerifierTest : public ::testing::Test {
protected:
    TlSignatureVerifier verifier;
};

TEST_F(TlSignatureVerifierTest, VerifyRealSerbianTl)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available (no network or cache)";

    auto certSpan = pinned_certs::kSerbianTlSigningCert;
    bool ok = verifier.verify(tlXml, certSpan);
    EXPECT_TRUE(ok) << "Verification failed: " << verifier.lastError();
}

TEST_F(TlSignatureVerifierTest, TamperedContentFails)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available";

    // Tamper: flip a byte in the middle of the document
    auto tampered = tlXml;
    size_t mid = tampered.size() / 2;
    tampered[mid] ^= 0xFF;

    auto certSpan = pinned_certs::kSerbianTlSigningCert;
    bool ok = verifier.verify(tampered, certSpan);
    EXPECT_FALSE(ok) << "Tampered TL should not verify";
}

TEST_F(TlSignatureVerifierTest, WrongCertFails)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available";

    // Use the EU cert against the Serbian TL — should fail
    auto euCert = pinned_certs::kEuLotlSigningCert;
    bool ok = verifier.verify(tlXml, euCert);
    EXPECT_FALSE(ok) << "Wrong cert should not verify";
}

TEST_F(TlSignatureVerifierTest, EmptyInputFails)
{
    std::vector<uint8_t> empty;
    auto certSpan = pinned_certs::kSerbianTlSigningCert;

    EXPECT_FALSE(verifier.verify(empty, certSpan));
    EXPECT_FALSE(verifier.lastError().empty());
}

TEST_F(TlSignatureVerifierTest, EmptyCertFails)
{
    auto tlXml = getSerbianTl();
    if (tlXml.empty())
        GTEST_SKIP() << "Serbian TL not available";

    std::span<const uint8_t> emptyCert;
    EXPECT_FALSE(verifier.verify(tlXml, emptyCert));
}

TEST_F(TlSignatureVerifierTest, InvalidXmlFails)
{
    std::vector<uint8_t> garbage = {0x3C, 0x3F, 0x78, 0x6D, 0x6C}; // "<?xml" truncated
    auto certSpan = pinned_certs::kSerbianTlSigningCert;

    EXPECT_FALSE(verifier.verify(garbage, certSpan));
}

#else

TEST(TlSignatureVerifierTest, NativeNotEnabled)
{
    GTEST_SKIP() << "Native signing backend not enabled";
}

#endif

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#include "native/tsa_client.h"
#include "signing_test_support/mock_tsa_server.h"

#include <openssl/pem.h>
#include <openssl/pkcs7.h>
#include <openssl/x509.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <string>
#include <unistd.h>
#include <vector>

using namespace libresign;
using libresign::test::MockTsaServer;

TEST(TSAClient, RequestWithInvalidUrlFails)
{
    TSAClient tsa;
    std::vector<uint8_t> hash(32, 0x42);
    TSARequest req;
    req.url = "http://localhost:1/nonexistent";
    req.timeoutSeconds = 5;
    auto result = tsa.timestamp(hash, req);
    ASSERT_FALSE(result.success);
    ASSERT_FALSE(result.errorMessage.empty());
}

// A public authority's token verifies against the system store as the
// https client finds it, which the bundled OpenSSL alone does not.
TEST(TSAClient, RequestToPublicTSA)
{
    TSAClient tsa;
    std::vector<uint8_t> hash = {0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
                                 0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
                                 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};
    TSARequest req;
    req.url = "http://timestamp.digicert.com";
    req.timeoutSeconds = 15;
    auto result = tsa.timestamp(hash, req);
    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.token.empty());
    ASSERT_EQ(result.token[0], 0x30); // ASN.1 SEQUENCE tag
}

// Every case below turns the system store off: what vouches for the token is
// then exactly the anchors the case names, on any machine.
namespace {

const std::vector<uint8_t> kHash(32, 0x5a);

TSARequest requestTo(const MockTsaServer& server, std::vector<std::vector<uint8_t>> anchors)
{
    TSARequest req;
    req.url = server.url();
    req.timeoutSeconds = 5;
    req.trust.anchors = std::move(anchors);
    req.trust.includeSystemTrustStore = false;
    return req;
}

/// Subject CN of the certificate that signed @p token: which authority the
/// client actually accepted.
std::string signerName(const std::vector<uint8_t>& token)
{
    const unsigned char* p = token.data();
    PKCS7* p7 = d2i_PKCS7(nullptr, &p, static_cast<long>(token.size()));
    if (!p7)
        return {};
    std::string name;
    STACK_OF(X509)* signers = PKCS7_get0_signers(p7, nullptr, 0);
    if (signers && sk_X509_num(signers) == 1) {
        char buf[256] = {};
        X509_NAME_get_text_by_NID(X509_get_subject_name(sk_X509_value(signers, 0)), NID_commonName, buf, sizeof buf);
        name = buf;
    }
    sk_X509_free(signers);
    PKCS7_free(p7);
    return name;
}

} // namespace

// Harness pin: a token signed by the authority the anchor issued is accepted,
// so each refusal below is the client judging the signer and not a responder
// that never answered.
TEST(TSAClientTrust, ATokenThatChainsToAnAnchorIsAccepted)
{
    MockTsaServer server;
    auto result = TSAClient{}.timestamp(kHash, requestTo(server, {MockTsaServer::trustAnchor()}));
    ASSERT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(server.servedCount(), 1);
    EXPECT_EQ(signerName(result.token), "LibreSCRS Mock Time-Stamp Authority");
}

// The attack: the nonce and the imprint are in the request, in the clear, so
// an authority nobody trusts can echo both into a token it signs itself.
TEST(TSAClientTrust, ATokenFromAnAuthorityNoAnchorVouchesForIsRefused)
{
    MockTsaServer server(MockTsaServer::Authority::Unanchored);
    auto result = TSAClient{}.timestamp(kHash, requestTo(server, {MockTsaServer::trustAnchor()}));
    EXPECT_EQ(server.servedCount(), 1) << "the responder must have answered, nonce and imprint right";
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.token.empty());
    EXPECT_NE(result.errorMessage.find("time-stamping authority"), std::string::npos) << result.errorMessage;
}

TEST(TSAClientTrust, ATokenIsRefusedWhenNothingIsTrusted)
{
    MockTsaServer server;
    auto result = TSAClient{}.timestamp(kHash, requestTo(server, {}));
    EXPECT_EQ(server.servedCount(), 1);
    EXPECT_FALSE(result.success);
    EXPECT_TRUE(result.token.empty());
}

// A Trusted List can name the time-stamping unit itself rather than the CA
// that issued it; that certificate is the anchor as it is.
TEST(TSAClientTrust, AnAnchorThatIsTheAuthoritysOwnCertificateIsTrustedAsItIs)
{
    MockTsaServer server;
    auto result = TSAClient{}.timestamp(kHash, requestTo(server, {MockTsaServer::anchoredCertificate()}));
    EXPECT_TRUE(result.success) << result.errorMessage;
}

// The deferred anchors are the Trusted Lists not fetched yet: asked for only
// when the token does not verify without them, and then used.
TEST(TSAClientTrust, DeferredAnchorsAreFetchedOnlyWhenTheTokenNeedsThem)
{
    MockTsaServer server;
    int asked = 0;
    auto deferred = [&asked] {
        ++asked;
        return std::vector<std::vector<uint8_t>>{MockTsaServer::trustAnchor()};
    };

    auto req = requestTo(server, {MockTsaServer::trustAnchor()});
    req.trust.deferredAnchors = deferred;
    auto result = TSAClient{}.timestamp(kHash, req);
    EXPECT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(asked, 0) << "the token already verified; nothing deferred is needed";

    req = requestTo(server, {});
    req.trust.deferredAnchors = deferred;
    result = TSAClient{}.timestamp(kHash, req);
    EXPECT_TRUE(result.success) << result.errorMessage;
    EXPECT_EQ(asked, 1);

    // And once only: anchors that still do not vouch for the signer end it.
    MockTsaServer stranger(MockTsaServer::Authority::Unanchored);
    req = requestTo(stranger, {});
    req.trust.deferredAnchors = deferred;
    result = TSAClient{}.timestamp(kHash, req);
    EXPECT_FALSE(result.success);
    EXPECT_EQ(asked, 2);
}

// The system store vouches only while the host has not opted out of it. The
// store is whatever SSL_CERT_FILE names, so the case makes the anchor that
// file — the same override a packager uses to ship a CA bundle.
TEST(TSAClientTrust, TheSystemStoreVouchesOnlyWhileItIsIncluded)
{
    const auto pem =
        std::filesystem::temp_directory_path() / ("librescrs-tsa-system-store-" + std::to_string(::getpid()) + ".pem");
    {
        const auto der = MockTsaServer::trustAnchor();
        const unsigned char* p = der.data();
        X509* cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()));
        ASSERT_NE(cert, nullptr);
        std::FILE* f = std::fopen(pem.c_str(), "w");
        ASSERT_NE(f, nullptr);
        EXPECT_EQ(PEM_write_X509(f, cert), 1);
        std::fclose(f);
        X509_free(cert);
    }
    const char* previous = std::getenv("SSL_CERT_FILE");
    const std::optional<std::string> saved = previous ? std::optional<std::string>{previous} : std::nullopt;
    ::setenv("SSL_CERT_FILE", pem.c_str(), 1);

    MockTsaServer server;
    auto req = requestTo(server, {});
    req.trust.includeSystemTrustStore = true;
    auto included = TSAClient{}.timestamp(kHash, req);
    req.trust.includeSystemTrustStore = false;
    auto excluded = TSAClient{}.timestamp(kHash, req);

    if (saved)
        ::setenv("SSL_CERT_FILE", saved->c_str(), 1);
    else
        ::unsetenv("SSL_CERT_FILE");
    std::filesystem::remove(pem);

    EXPECT_TRUE(included.success) << included.errorMessage;
    EXPECT_FALSE(excluded.success);
}

TEST(TSAClient, RejectsWrongHashSize)
{
    TSAClient tsa;
    std::vector<uint8_t> shortHash(16, 0xAA);
    TSARequest req;
    req.url = "http://timestamp.digicert.com";
    req.timeoutSeconds = 5;
    auto result = tsa.timestamp(shortHash, req);
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.errorMessage.find("32-byte"), std::string::npos);
}

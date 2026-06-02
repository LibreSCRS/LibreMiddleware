// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/openssl_raii.h"
#include "native/revocation_client.h"

#include <openssl/x509.h>

using namespace libresign;

TEST(RevocationClient, ExtractCrlUrlsFromNullCert)
{
    auto urls = RevocationClient::extractCrlUrls(nullptr);
    ASSERT_TRUE(urls.empty());
}

TEST(RevocationClient, ExtractOcspUrlsFromNullCert)
{
    auto urls = RevocationClient::extractOcspUrls(nullptr);
    ASSERT_TRUE(urls.empty());
}

TEST(RevocationClient, FetchCrlFromInvalidUrlReturnsEmpty)
{
    RevocationClient client;
    // null issuer is rejected before any network call — exercises the
    // signature-verification guard.
    auto crl = client.fetchCrl("http://localhost:1/nonexistent", nullptr, 3);
    ASSERT_TRUE(crl.empty());
}

TEST(RevocationClient, FetchOcspFromInvalidUrlReturnsEmpty)
{
    RevocationClient client;
    // null cert/issuer is rejected before any network call.
    std::vector<X509*> emptyChain;
    auto resp = client.fetchOcsp(nullptr, nullptr, emptyChain, "http://localhost:1/nonexistent", 3);
    ASSERT_TRUE(resp.empty());
}

// A bare X509 carries no CRL Distribution Point and no OCSP AIA extension, so
// extractCrlUrls/extractOcspUrls yield nothing and collectForChain attempts no
// network at all — the cert is simply unrevocable. For a long-term (B-LT)
// signature that is a fail-closed condition: collectForChain must REPORT the
// gap (by chain index) rather than silently returning empty revocation data.
TEST(RevocationClient, CollectForChainReportsNonRootCertWithoutRevocationEndpoints)
{
    X509Ptr leaf(X509_new());
    X509Ptr issuer(X509_new());
    ASSERT_TRUE(leaf && issuer);

    std::vector<X509*> chain{leaf.get(), issuer.get()};
    RevocationClient client;
    auto data = client.collectForChain(chain);

    // The leaf (index 0) is the only non-root cert; it has no endpoints, so it
    // is the lone gap. The trailing issuer is treated as the root and skipped.
    EXPECT_EQ(data.certsWithoutRevocation, (std::vector<std::size_t>{0}));
    EXPECT_TRUE(data.crls.empty());
    EXPECT_TRUE(data.ocspResponses.empty());
}

// A single-cert chain has no non-root cert to revoke, so there is no gap.
TEST(RevocationClient, CollectForChainSingleCertHasNoRevocationGap)
{
    X509Ptr only(X509_new());
    ASSERT_TRUE(only);

    std::vector<X509*> chain{only.get()};
    auto data = RevocationClient{}.collectForChain(chain);

    EXPECT_TRUE(data.certsWithoutRevocation.empty());
}

// ---- CRL freshness (crlWindowValid) ----

namespace {
struct Asn1TimeFree
{
    void operator()(ASN1_TIME* t) const
    {
        ASN1_STRING_free(reinterpret_cast<ASN1_STRING*>(t));
    }
};
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Asn1TimeFree>;

constexpr std::time_t kFixedNow = 1700000000; // deterministic reference instant
constexpr long kSkew = 300;
} // namespace

TEST(RevocationClient, CrlWindowValidAcceptsCurrentWindow)
{
    Asn1TimePtr thisU(ASN1_TIME_set(nullptr, kFixedNow - 3600));
    Asn1TimePtr nextU(ASN1_TIME_set(nullptr, kFixedNow + 3600));
    ASSERT_TRUE(thisU && nextU);
    EXPECT_TRUE(RevocationClient::crlWindowValid(thisU.get(), nextU.get(), kFixedNow, kSkew));
}

TEST(RevocationClient, CrlWindowValidRejectsElapsedNextUpdate)
{
    Asn1TimePtr thisU(ASN1_TIME_set(nullptr, kFixedNow - 7200));
    Asn1TimePtr nextU(ASN1_TIME_set(nullptr, kFixedNow - 3600)); // stale
    ASSERT_TRUE(thisU && nextU);
    EXPECT_FALSE(RevocationClient::crlWindowValid(thisU.get(), nextU.get(), kFixedNow, kSkew));
}

TEST(RevocationClient, CrlWindowValidRejectsFutureThisUpdate)
{
    Asn1TimePtr thisU(ASN1_TIME_set(nullptr, kFixedNow + 7200)); // not yet valid
    Asn1TimePtr nextU(ASN1_TIME_set(nullptr, kFixedNow + 10800));
    ASSERT_TRUE(thisU && nextU);
    EXPECT_FALSE(RevocationClient::crlWindowValid(thisU.get(), nextU.get(), kFixedNow, kSkew));
}

TEST(RevocationClient, CrlWindowValidAcceptsAbsentNextUpdate)
{
    Asn1TimePtr thisU(ASN1_TIME_set(nullptr, kFixedNow - 3600));
    ASSERT_TRUE(thisU);
    EXPECT_TRUE(RevocationClient::crlWindowValid(thisU.get(), nullptr, kFixedNow, kSkew));
}

TEST(RevocationClient, CrlWindowValidRejectsAbsentThisUpdate)
{
    Asn1TimePtr nextU(ASN1_TIME_set(nullptr, kFixedNow + 3600));
    ASSERT_TRUE(nextU);
    EXPECT_FALSE(RevocationClient::crlWindowValid(nullptr, nextU.get(), kFixedNow, kSkew));
}

// X509_cmp_time returns 0 on a parse error. A non-null but unparseable time
// field must fail CLOSED (reject) — not silently pass the window — to match
// the OCSP path (OCSP_check_validity fails closed on unparseable times).
TEST(RevocationClient, CrlWindowValidRejectsUnparseableThisUpdate)
{
    Asn1TimePtr bad(ASN1_TIME_new()); // empty/unset → X509_cmp_time errors (0)
    Asn1TimePtr nextU(ASN1_TIME_set(nullptr, kFixedNow + 3600));
    ASSERT_TRUE(bad && nextU);
    EXPECT_FALSE(RevocationClient::crlWindowValid(bad.get(), nextU.get(), kFixedNow, kSkew));
}

TEST(RevocationClient, CrlWindowValidRejectsUnparseableNextUpdate)
{
    Asn1TimePtr thisU(ASN1_TIME_set(nullptr, kFixedNow - 3600));
    Asn1TimePtr bad(ASN1_TIME_new()); // empty/unset → X509_cmp_time errors (0)
    ASSERT_TRUE(thisU && bad);
    EXPECT_FALSE(RevocationClient::crlWindowValid(thisU.get(), bad.get(), kFixedNow, kSkew));
}

#else
TEST(RevocationClient, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif

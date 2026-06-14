// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/openssl_raii.h"
#include "native/revocation_client.h"
#include "native/trusted_list_parser.h" // isSafeFetchUrl — shared SSRF gate

#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <ctime>
#include <vector>

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
    // null cert/issuer is rejected before any network call — exercises the
    // signature-verification guard.
    auto crl = client.fetchCrl("http://localhost:1/nonexistent", nullptr, nullptr, 3);
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

// ---- SSRF guard on CRL CDP / OCSP AIA URLs ----

// The cloud-metadata service (169.254.169.254, AWS/GCP/Azure) is the canonical
// SSRF target. A CRL Distribution Point or OCSP/AIA URL pointing at it — or any
// loopback/link-local/RFC1918/ULA/multicast literal — must be rejected by the
// shared scheme-agnostic host gate, for both http and https.
TEST(RevocationClient, SsrfGuardRejectsCloudMetadataAndPrivateLiterals)
{
    using libresign::TrustedListParser;
    // Cloud metadata link-local 169.254.0.0/16 — rejected over http and https.
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://169.254.169.254/latest/meta-data/", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("https://169.254.169.254/crl", true));
    // Loopback, RFC1918, ULA, multicast literals.
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://127.0.0.1/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://10.0.0.5/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://192.168.1.1/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://172.16.0.1/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://[::1]/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://[fe80::1]/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://[fd00::1]/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://[ff02::1]/crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://224.0.0.1/crl", true));
    // Plain http is allowed for the revocation path (allowPlainHttp=true) when
    // the host is public; https-only mode (the TSL path) rejects http entirely.
    EXPECT_TRUE(TrustedListParser::isSafeFetchUrl("http://crl.example.com/ca.crl", true));
    EXPECT_FALSE(TrustedListParser::isSafeFetchUrl("http://crl.example.com/ca.crl", false));
    EXPECT_TRUE(TrustedListParser::isSafeFetchUrl("https://crl.example.com/ca.crl", false));

    // End-to-end: fetchCrl / fetchOcsp short-circuit (return empty) on an
    // unsafe URL before any network I/O, falling through to fail-closed.
    RevocationClient client;
    X509Ptr cert(X509_new());
    X509Ptr issuer(X509_new());
    ASSERT_TRUE(cert && issuer);
    EXPECT_TRUE(client.fetchCrl("http://169.254.169.254/crl", cert.get(), issuer.get(), 1).empty());
    std::vector<X509*> chain{cert.get(), issuer.get()};
    EXPECT_TRUE(client.fetchOcsp(cert.get(), issuer.get(), chain, "http://169.254.169.254/ocsp", 1).empty());
}

// ---- CRL-revoked fail-closed (crlRevokesCert) ----

namespace {
// Build a CA cert + key, then a leaf issued by it; return all three. Serial of
// the leaf is fixed so the test can revoke exactly that serial.
struct CaAndLeaf
{
    EvpPkeyPtr caKey;
    X509Ptr ca;
    EvpPkeyPtr leafKey;
    X509Ptr leaf;
    long leafSerial = 0x4242;
};

CaAndLeaf makeCaAndLeaf()
{
    CaAndLeaf out;
    out.caKey.reset(EVP_EC_gen("P-256"));
    out.leafKey.reset(EVP_EC_gen("P-256"));

    out.ca.reset(X509_new());
    X509_set_version(out.ca.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(out.ca.get()), 1);
    X509_gmtime_adj(X509_getm_notBefore(out.ca.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(out.ca.get()), 365L * 24 * 3600);
    X509_set_pubkey(out.ca.get(), out.caKey.get());
    X509_NAME_add_entry_by_txt(X509_get_subject_name(out.ca.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Test CA"), -1, -1, 0);
    X509_set_issuer_name(out.ca.get(), X509_get_subject_name(out.ca.get()));
    X509_sign(out.ca.get(), out.caKey.get(), EVP_sha256());

    out.leaf.reset(X509_new());
    X509_set_version(out.leaf.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(out.leaf.get()), out.leafSerial);
    X509_gmtime_adj(X509_getm_notBefore(out.leaf.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(out.leaf.get()), 365L * 24 * 3600);
    X509_set_pubkey(out.leaf.get(), out.leafKey.get());
    X509_NAME_add_entry_by_txt(X509_get_subject_name(out.leaf.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Leaf"), -1, -1, 0);
    X509_set_issuer_name(out.leaf.get(), X509_get_subject_name(out.ca.get()));
    X509_sign(out.leaf.get(), out.caKey.get(), EVP_sha256());
    return out;
}

// Build a CRL signed by ca/caKey; optionally revoke `revokedSerial`.
X509CrlPtr makeCrl(X509* ca, EVP_PKEY* caKey, const long* revokedSerial)
{
    X509CrlPtr crl(X509_CRL_new());
    X509_CRL_set_version(crl.get(), 1);
    X509_CRL_set_issuer_name(crl.get(), X509_get_subject_name(ca));

    Asn1TimePtr last(ASN1_TIME_set(nullptr, std::time(nullptr) - 3600));
    Asn1TimePtr next(ASN1_TIME_set(nullptr, std::time(nullptr) + 3600));
    X509_CRL_set1_lastUpdate(crl.get(), last.get());
    X509_CRL_set1_nextUpdate(crl.get(), next.get());

    if (revokedSerial) {
        X509_REVOKED* rev = X509_REVOKED_new();
        ASN1IntPtr serial(ASN1_INTEGER_new());
        ASN1_INTEGER_set(serial.get(), *revokedSerial);
        X509_REVOKED_set_serialNumber(rev, serial.get());
        Asn1TimePtr when(ASN1_TIME_set(nullptr, std::time(nullptr) - 1800));
        X509_REVOKED_set_revocationDate(rev, when.get());
        X509_CRL_add0_revoked(crl.get(), rev); // takes ownership of rev
    }

    X509_CRL_sort(crl.get());
    X509_CRL_sign(crl.get(), caKey, EVP_sha256());
    return crl;
}
} // namespace

// crlRevokesCert mirrors the OCSP V_OCSP_CERTSTATUS_GOOD gate: a CRL that lists
// the cert's serial as revoked must report true (fetchCrl then fails closed),
// and a CRL that does not list it must report false (evidence is usable).
TEST(RevocationClient, CrlRevokesCertDetectsRevokedSerial)
{
    auto env = makeCaAndLeaf();
    ASSERT_TRUE(env.ca && env.leaf && env.caKey);

    // CRL revoking the leaf's serial → revoked.
    auto revokingCrl = makeCrl(env.ca.get(), env.caKey.get(), &env.leafSerial);
    EXPECT_TRUE(RevocationClient::crlRevokesCert(revokingCrl.get(), env.leaf.get()));

    // CRL revoking a different serial → not revoked.
    long otherSerial = 0x9999;
    auto otherCrl = makeCrl(env.ca.get(), env.caKey.get(), &otherSerial);
    EXPECT_FALSE(RevocationClient::crlRevokesCert(otherCrl.get(), env.leaf.get()));

    // Empty CRL (no entries) → not revoked.
    auto emptyCrl = makeCrl(env.ca.get(), env.caKey.get(), nullptr);
    EXPECT_FALSE(RevocationClient::crlRevokesCert(emptyCrl.get(), env.leaf.get()));

    // Null arguments → not revoked (no crash).
    EXPECT_FALSE(RevocationClient::crlRevokesCert(nullptr, env.leaf.get()));
    EXPECT_FALSE(RevocationClient::crlRevokesCert(revokingCrl.get(), nullptr));
}

#else
TEST(RevocationClient, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif

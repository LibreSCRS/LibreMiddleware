// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/revocation_client.h"

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

#else
TEST(RevocationClient, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif

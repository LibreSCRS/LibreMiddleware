// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "libresign/native/tsa_client.h"

using namespace libresign;

TEST(TSAClient, RequestWithInvalidUrlFails)
{
    TSAClient tsa;
    std::vector<uint8_t> hash(32, 0x42);
    auto result = tsa.timestamp(hash, "http://localhost:1/nonexistent", 5);
    ASSERT_FALSE(result.success);
    ASSERT_FALSE(result.errorMessage.empty());
}

TEST(TSAClient, RequestToPublicTSA)
{
    TSAClient tsa;
    std::vector<uint8_t> hash = {0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea,
                                 0xa0, 0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b,
                                 0x82, 0x2c, 0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};
    auto result = tsa.timestamp(hash, "http://timestamp.digicert.com", 15);
    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.token.empty());
    ASSERT_EQ(result.token[0], 0x30); // ASN.1 SEQUENCE tag
}

TEST(TSAClient, RejectsWrongHashSize)
{
    TSAClient tsa;
    std::vector<uint8_t> shortHash(16, 0xAA);
    auto result = tsa.timestamp(shortHash, "http://timestamp.digicert.com", 5);
    ASSERT_FALSE(result.success);
    ASSERT_NE(result.errorMessage.find("32-byte"), std::string::npos);
}

#else
TEST(TSAClient, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include "http_client.h"

TEST(HttpClientTest, ConstructAndDestruct)
{
    libresign::HttpClient client;
    // Should not crash
}

TEST(HttpClientTest, GetToUnreachableHostReturnsError)
{
    libresign::HttpClient client;
    auto resp = client.get("http://127.0.0.1:1/nonexistent", 2);
    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
}

TEST(HttpClientTest, PostToUnreachableHostReturnsError)
{
    libresign::HttpClient client;
    auto resp = client.post("http://127.0.0.1:1/nonexistent", "{}", 2);
    EXPECT_EQ(resp.statusCode, 0);
    EXPECT_FALSE(resp.errorMessage.empty());
}

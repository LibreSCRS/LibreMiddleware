// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/TsaProvider.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::Signing;

TEST(SigningRequestTsaOverrideTest, UnsetHasNoOverride)
{
    SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf")
        .outputFile("/tmp/out.pdf")
        .format(SignatureFormat::Pades)
        .packaging(PackagingMode::Enveloped)
        .level(SignatureLevel::B_B);
    auto req = std::move(b).build();
    EXPECT_FALSE(static_cast<bool>(req.tsaOverride()));
}

TEST(SigningRequestTsaOverrideTest, SetStaticTsaOverride)
{
    SigningRequest::Builder b;
    b.inputFile("/tmp/in.pdf")
        .outputFile("/tmp/out.pdf")
        .format(SignatureFormat::Pades)
        .packaging(PackagingMode::Enveloped)
        .level(SignatureLevel::B_T)
        .tsaOverride(staticTsa("https://tsa.example.com"));
    auto req = std::move(b).build();
    ASSERT_TRUE(static_cast<bool>(req.tsaOverride()));
    TsaContext ctx;
    auto r = req.tsaOverride()(ctx);
    EXPECT_EQ(r.url, "https://tsa.example.com");
}

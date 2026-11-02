// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/TsaProvider.h>

#include <gtest/gtest.h>

using namespace LibreSCRS::Signing;

TEST(SigningRequestTsaOverrideTest, UnsetHasNoOverride)
{
    SigningRequest::Builder b;
    b.format(SignatureFormat::Pades).packaging(PackagingMode::Enveloped).level(SignatureLevel::B_B);
    auto req = std::move(b).buildForBufferSign();
    EXPECT_TRUE(req.tsaOverride().url.empty());
}

TEST(SigningRequestTsaOverrideTest, SetStaticTsaOverride)
{
    SigningRequest::Builder b;
    b.format(SignatureFormat::Pades)
        .packaging(PackagingMode::Enveloped)
        .level(SignatureLevel::B_T)
        .tsaOverride(staticTsa("https://tsa.example.com"));
    auto req = std::move(b).buildForBufferSign();
    EXPECT_EQ(req.tsaOverride().url, "https://tsa.example.com");
}

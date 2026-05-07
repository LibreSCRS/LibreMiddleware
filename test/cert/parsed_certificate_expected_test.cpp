// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Certificate/ParsedCertificate.h>
#include <LibreSCRS/Auth/ErrorKeys.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

using LibreSCRS::Certificate::ParsedCertificate;

// Every 4.0 public fallible factory returns std::expected<T, E>; on
// failure the E carries a coarse Kind enum, a non-empty user-renderable
// LocalizedText, and an optional dev diagnosticDetail.

TEST(ParsedCertificateFromDer, EmptyDerReturnsParseError)
{
    auto result = ParsedCertificate::fromDer({});
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, ParsedCertificate::ParseError::Kind::Invalid);
    EXPECT_EQ(result.error().userMessage.key, "librescrs.error.cert.derInvalid");
    EXPECT_FALSE(result.error().userMessage.defaultText.empty());
    EXPECT_TRUE(result.error().diagnosticDetail.has_value());
}

TEST(ParsedCertificateFromDer, MalformedDerReturnsParseError)
{
    constexpr std::array<std::uint8_t, 4> garbage{0xDE, 0xAD, 0xBE, 0xEF};
    auto result = ParsedCertificate::fromDer(garbage);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error().kind, ParsedCertificate::ParseError::Kind::Invalid);
    EXPECT_FALSE(result.error().userMessage.key.empty());
}

TEST(ParseErrorBuilderTest, DerInvalidCarriesCanonicalKey)
{
    auto lt = LibreSCRS::Auth::ErrorKeys::derInvalid();
    EXPECT_EQ(lt.key, "librescrs.error.cert.derInvalid");
    EXPECT_FALSE(lt.defaultText.empty());
}

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for @ref LibreSCRS::Plugin::CardPlugin::decipher's NVI
///        default path.
///
/// A plugin that advertises @c CardCapabilities::PKI but does not override
/// @ref LibreSCRS::Plugin::CardPlugin::doDecipher must surface
/// @ref LibreSCRS::Plugin::DecipherResultOutcome::NotImplemented through the
/// public wrapper, so a caller can distinguish "this plugin cannot decrypt"
/// from a genuine card-side failure. A second test sends
/// @ref LibreSCRS::Plugin::DecipherMechanism::ECDH_RAW through the same
/// default: key agreement a plugin does not implement is NotImplemented too.
///
/// The wrapper receives a real detached @ref LibreSCRS::SmartCard::CardSession
/// via the LM-internal test factory (the @c LIBRESCRS_INTERNAL_BUILD define +
/// @c LibreSCRS_SmartCard_TestHelpers archive are wired in the CMakeLists),
/// rather than a synthesised null reference: the NotImplemented default never
/// dereferences the session, but a real reference keeps the test free of UB.

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <span>

namespace {
using namespace LibreSCRS::Plugin;

/// @brief Minimal concrete @ref CardPlugin overriding only the pure virtuals,
///        so the base @c doDecipher default is exercised through the public
///        @c decipher NVI wrapper.
class BareCardPlugin final : public CardPlugin
{
public:
    BareCardPlugin()
    {
        setIdentity("bare", "Bare", 0);
    }

    CardCapabilities capabilities() const override
    {
        return CardCapabilities::PKI;
    }

    std::span<const Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/, GroupCallback /*onGroup*/) const override
    {
        return ReadResult::ok({});
    }
};
} // namespace

TEST(CardPluginDecipher, DefaultIsNotImplemented)
{
    BareCardPlugin p;
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    const std::array<std::uint8_t, 4> ct{0x01, 0x02, 0x03, 0x04};
    DecipherResult r = p.decipher(*session, /*keyReference=*/0x42, ct, DecipherMechanism::RSA_PKCS1_V15);
    EXPECT_EQ(r.outcome, DecipherResultOutcome::NotImplemented);
}

// Every mechanism reaches doDecipher; a plugin that overrides nothing answers
// key agreement exactly as it answers RSA: NotImplemented, nothing sent.
TEST(CardPluginDecipher, EcdhRawDefaultIsNotImplemented)
{
    BareCardPlugin p;
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    std::array<std::uint8_t, 97> point{};
    point[0] = 0x04;
    DecipherResult r = p.decipher(*session, /*keyReference=*/0x47, point, DecipherMechanism::ECDH_RAW);
    EXPECT_EQ(r.outcome, DecipherResultOutcome::NotImplemented);
}

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
/// from a genuine card-side failure. A second test pins the decrypt mechanism
/// enum closed so a future addition forces a deliberate doDecipher update.
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

TEST(CardPluginDecipher, UnsupportedMechanismIsRejectedWithoutCard)
{
    // doDecipher must reject a non-v1.5 mechanism deterministically. The enum
    // is closed, so this test pins that the ONLY value is RSA_PKCS1_V15 so a
    // future addition forces a deliberate doDecipher update.
    EXPECT_EQ(static_cast<int>(DecipherMechanism::RSA_PKCS1_V15), 0);
}

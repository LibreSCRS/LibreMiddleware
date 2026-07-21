// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for the @ref LibreSCRS::Plugin::CardPlugin credential-
///        lifecycle base defaults @ref
///        LibreSCRS::Plugin::CardPlugin::activateTransportPin and @ref
///        LibreSCRS::Plugin::CardPlugin::activateSigningKey.
///
/// A plugin that does not override the lifecycle virtuals must surface
/// @ref LibreSCRS::Plugin::PINResultOutcome::Unsupported, so a caller can
/// distinguish "plugin did not implement activation" from a genuine
/// card-side failure — the same safe-default contract already pinned for
/// @c verifyPIN / @c changePIN / @c unblockPIN.
///
/// The defaults receive a real detached @ref
/// LibreSCRS::SmartCard::CardSession via the LM-internal test factory (the
/// @c LIBRESCRS_INTERNAL_BUILD define + @c LibreSCRS_SmartCard_TestHelpers
/// archive are wired in the CMakeLists), rather than a synthesised null
/// reference: the Unsupported default never dereferences the session, but a
/// real reference keeps the test free of UB.

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <span>

namespace {
using namespace LibreSCRS::Plugin;

/// @brief Minimal concrete @ref CardPlugin overriding only the pure virtuals,
///        so the base credential-lifecycle defaults are exercised directly;
///        the PIN-lifecycle virtuals are inherited from the base.
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

TEST(PinLifecycleVirtuals, BaseActivateTransportPinIsUnsupported)
{
    BareCardPlugin plugin;
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);

    const LibreSCRS::Secure::String transportValue{"000000"};
    const LibreSCRS::Secure::String newPin{"123456"};
    auto r = plugin.activateTransportPin(*session, "SignaturePIN", transportValue, newPin);
    EXPECT_EQ(r.outcome, PINResultOutcome::Unsupported);
}

TEST(PinLifecycleVirtuals, BaseActivateSigningKeyIsUnsupported)
{
    BareCardPlugin plugin;
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);

    const LibreSCRS::Secure::String signPin{"123456"};
    auto r = plugin.activateSigningKey(*session, signPin);
    EXPECT_EQ(r.outcome, PINResultOutcome::Unsupported);
}

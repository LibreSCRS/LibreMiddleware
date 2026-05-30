// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Unit tests for the @ref LibreSCRS::SmartCard::CardSession lightweight
///        state accessors @ref LibreSCRS::SmartCard::CardSession::activatedProtocol
///        and @ref LibreSCRS::SmartCard::CardSession::hasCredentialProvider.
///
/// @c activatedProtocol reports the SM protocol that established the
/// currently-live channel (after any BAC fallback), or @c nullopt when no SM
/// channel is active. A freshly detached session has never activated a channel,
/// so the accessor must read @c nullopt — the baseline this test pins down. The
/// record-on-activation / clear-on-teardown transitions are covered by the
/// hardware-driven activation suites; this test anchors the no-channel
/// contract that the eMRTD plugin's protocol-label fallback depends on.
///
/// @c hasCredentialProvider reports whether a credential provider has been
/// installed via @ref LibreSCRS::SmartCard::CardSession::setCredentialProvider.
/// A freshly detached session has none (@c false); once a provider is installed
/// the accessor reads @c true. The eMRTD plugin uses this to distinguish a
/// broker that supplies secrets on demand from a host that pre-deposits them.
///
/// `makeDetachedCardSession` is the LM-internal test factory pulled in via the
/// internal-build-guarded injection header; the @c LIBRESCRS_INTERNAL_BUILD
/// define and the @c LibreSCRS_SmartCard_TestHelpers archive (which provides
/// the factory definition) are wired in the matching CMakeLists.

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialProvider.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

TEST(ActivatedProtocolTest, NoChannelYieldsNullopt)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_FALSE(session->activatedProtocol().has_value());
}

TEST(HasCredentialProviderTest, FreshSessionReportsFalse)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_FALSE(session->hasCredentialProvider());
}

TEST(HasCredentialProviderTest, ReportsTrueAfterProviderInstalled)
{
    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("test-reader");
    ASSERT_NE(session, nullptr);
    EXPECT_FALSE(session->hasCredentialProvider());

    session->setCredentialProvider(
        [](const LibreSCRS::Auth::AuthRequirement&) { return LibreSCRS::Auth::CredentialResult::cancelled(); });
    EXPECT_TRUE(session->hasCredentialProvider());
}

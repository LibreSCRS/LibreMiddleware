// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Phase 1 (LM 4.0 CancelToken migration): NVI + LibreSCRS::CancelToken
///        cancellation.
///
/// The public @ref LibreSCRS::Plugin::CardPlugin::readCard wraps the
/// protected virtual @ref LibreSCRS::Plugin::CardPlugin::doReadCard.
/// The wrapper observes a @ref LibreSCRS::CancelToken and short-circuits
/// before dispatching when @c isCancelled() returns true. The plugin-side
/// virtual no longer takes a cancellation parameter — operation is treated
/// as atomic from a cancellation standpoint (PC/SC transport is atomic).

// ErrorKeys.h transitively pulls in LocalizedText.h; no direct include needed.
#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>
#include <LibreSCRS/Trust/TrustStore.h>

#include <memory>

#include <gtest/gtest.h>

#include <array>
#include <string>
#include <utility>

namespace {

using namespace LibreSCRS;

class StubPlugin : public Plugin::CardPlugin
{
public:
    StubPlugin()
    {
        setIdentity("stub", "Stub", /*priority=*/100);
    }

    [[nodiscard]] std::span<const Plugin::Atr> supportedAtrs() const noexcept override
    {
        static constexpr std::array<Plugin::Atr, 0> kAtrs{};
        return kAtrs;
    }

    [[nodiscard]] Plugin::CardCapabilities capabilities() const override
    {
        return Plugin::CardCapabilities::None;
    }

    Plugin::ReadResult doReadCard(SmartCard::CardSession& /*session*/, GroupCallback /*onGroup*/) const override
    {
        // The NVI wrapper short-circuits before dispatching when the token
        // reports isCancelled(); plugins observe atomic operation semantics
        // and do not see the cancellation parameter directly.
        observed_invoked = true;
        return Plugin::ReadResult::ok(Plugin::CardData{});
    }

    void doSetTrustStore(std::shared_ptr<const LibreSCRS::Trust::TrustStore> /*store*/) noexcept override
    {
        ++trustStoreInjectCount;
    }

    mutable bool observed_invoked = false;
    mutable int trustStoreInjectCount = 0;
};

// Convenience: build a detached CardSession (no real PCSC I/O) for tests
// that only need a stable session reference.
std::shared_ptr<SmartCard::CardSession> openDetachedSession()
{
    return SmartCard::detail::makeDetachedCardSession(std::string{"test-reader"});
}

} // namespace

TEST(CancellationNvi, DefaultTokenDispatchesToImpl)
{
    StubPlugin plugin;
    auto session = openDetachedSession();
    auto r = plugin.readCard(*session);
    EXPECT_TRUE(plugin.observed_invoked);
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::Ok);
}

TEST(CancellationNvi, CancelledTokenShortCircuitsBeforeImpl)
{
    StubPlugin plugin;
    auto session = openDetachedSession();
    CancelSource src;
    auto token = src.token();
    src.requestCancel();
    auto r = plugin.readCard(*session, /*onGroup=*/{}, std::move(token));
    // Wrapper short-circuits before dispatching to doReadCard, so the stub
    // implementation is NOT invoked.
    EXPECT_FALSE(plugin.observed_invoked);
    // 4.0: dedicated Status::Cancelled (mirrors SignResult::cancelled).
    // Pre-4.0 this folded into CommunicationError with a sentinel key.
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::Cancelled);
}

// Confirms the protected virtual is invoked when the token is present but
// not yet cancelled.
TEST(CancellationNvi, LiveTokenDispatchesToImplWhenNotCancelled)
{
    StubPlugin plugin;
    auto session = openDetachedSession();
    CancelSource src;
    auto token = src.token();
    auto r = plugin.readCard(*session, /*onGroup=*/{}, std::move(token));
    EXPECT_TRUE(plugin.observed_invoked);
    EXPECT_EQ(r.status, Plugin::ReadResult::Status::Ok);
}

// 4.0 NVI: setTrustStore is single-shot. The first call dispatches
// to doSetTrustStore; every subsequent call is silently ignored.
TEST(SetTrustStoreNvi, SingleShotIgnoresSubsequentInjections)
{
    StubPlugin plugin;
    EXPECT_EQ(plugin.trustStoreInjectCount, 0);

    plugin.setTrustStore(nullptr);
    EXPECT_EQ(plugin.trustStoreInjectCount, 1);

    // Second and third calls must be no-ops (the doSetTrustStore counter
    // does not advance). The wrapper itself is noexcept.
    plugin.setTrustStore(nullptr);
    plugin.setTrustStore(nullptr);
    EXPECT_EQ(plugin.trustStoreInjectCount, 1);
    static_assert(noexcept(plugin.setTrustStore(nullptr)),
                  "CardPlugin::setTrustStore must be noexcept post-4.0 NVI hardening");
}

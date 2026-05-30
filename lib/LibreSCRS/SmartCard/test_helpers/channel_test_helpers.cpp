// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Test-only injection seam for @ref LibreSCRS::SmartCard::CardSession's
///        active secure-channel slot.
///
/// This translation unit is compiled into the build-tree-only
/// @ref LibreSCRS_SmartCard_TestHelpers archive — it is never installed and
/// never linked into the production @c libLibreSCRS_SmartCard shared
/// library. Production builds therefore never carry
/// @ref detail::ChannelInjector::installForTesting in their dynamic export
/// set; the friend declaration on @ref CardSession remains the only path
/// into the @c Impl::activeChannel slot from outside @c CardSession.cpp.

#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>
#include <LibreSCRS/SmartCard/detail/ChannelInjection.h>
#include <LibreSCRS_internal/SecureChannel/ISecureChannel.h>
#include <LibreSCRS_internal/SmartCard/CardSessionImpl.h>

#include <memory>
#include <mutex>
#include <optional>
#include <utility>

namespace LibreSCRS::SmartCard::detail {

void ChannelInjector::installForTesting(CardSession& session,
                                        std::unique_ptr<LibreSCRS::SecureChannel::ISecureChannel> channel,
                                        std::optional<SmProtocolRequest> recordedProtocol) noexcept
{
    // Mirrors the locking discipline of the activation paths so the install
    // is ordered against any concurrent hasLiveSecureChannel /
    // clearActiveChannel call from another thread. Any previously installed
    // channel is dropped without an explicit close(); the regression tests
    // that use this helper own the channel lifecycle and arrange teardown
    // themselves when required. When @p recordedProtocol is set it is stamped
    // alongside the channel under the same lock, mirroring the activation
    // paths so a test can reconstruct the recorded-protocol-but-non-live-channel
    // window the activatedProtocol accessor must report as nullopt.
    try {
        std::lock_guard lock(session.d->sessionMutex);
        session.d->activeChannel = std::move(channel);
        session.d->activatedProtocol = std::move(recordedProtocol);
    } catch (...) {
        // noexcept contract: swallow any exception. Lock acquisition
        // failure is the only realistic path here and is harmless for a
        // test-only helper — the assignment simply does not happen.
    }
}

} // namespace LibreSCRS::SmartCard::detail

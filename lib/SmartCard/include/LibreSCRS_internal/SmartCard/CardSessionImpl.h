// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/SmartCard/CardSessionImpl.h is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/SecureChannel/PaceParams.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS_internal/SecureChannel/BacChannel.h>
#include <LibreSCRS_internal/SmartCard/SessionPresence.h>

#include <pcsc_connection.h>

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
} // namespace LibreSCRS::SecureChannel

namespace LibreSCRS::SmartCard {

namespace Internal {

// Process-wide monotonic counter. Starts at 0; the helper returns the
// pre-increment value + 1 so the first @ref CardSession's generation is 1
// and 0 is reserved for "null / moved-from". Inline so that the production
// translation unit and the test-helper translation unit share a single
// atomic counter; both link against the same @ref LibreSCRS_SmartCard
// target and see the same definition.
inline std::uint64_t nextCardSessionGeneration() noexcept
{
    static std::atomic<std::uint64_t> counter{0};
    return counter.fetch_add(1, std::memory_order_relaxed) + 1;
}

} // namespace Internal

/// @brief Private state of @ref CardSession. Lives in an LM-internal header
///        so that the test-helper translation unit (built as a separate
///        archive, @ref LibreSCRS_SmartCard_TestHelpers) can install a
///        synthetic @ref LibreSCRS::SecureChannel::ISecureChannel without
///        re-exporting the test-only injection seam through the production
///        shared library's dynamic symbol table.
struct LIBRESCRS_INTERNAL CardSession::Impl
{
    std::unique_ptr<LibreSCRS::SmartCard::Internal::PCSCConnection> ownedConn;
    std::string readerName;
    std::vector<std::uint8_t> atr;
    std::uint64_t generation{Internal::nextCardSessionGeneration()};

    // 4.1: cross-plugin secure-channel coordination state.
    //
    // shared_ptr (not unique_ptr) so that the SM-aware transmit funnel can
    // snapshot the channel under the session mutex, release the mutex, and
    // dispatch the transmit on a pinned pointer that survives a concurrent
    // teardown on another thread. The session is the sole conceptual owner;
    // shared_ptr is purely a lifetime-pinning vehicle for the snapshot.
    std::shared_ptr<LibreSCRS::SecureChannel::ISecureChannel> activeChannel;
    std::array<LibreSCRS::Secure::String, LibreSCRS::Auth::kPaceSecretKindCount> paceCredentialsCache;
    // BAC consumes a structurally distinct tuple (documentNumber + two dates)
    // rather than a single secret, so it gets its own cache slot disjoint
    // from the PACE credentials cache.
    std::optional<LibreSCRS::SecureChannel::BacInput> bacInput;
    std::optional<LibreSCRS::Auth::CredentialProvider> credentialProvider;
    std::mutex sessionMutex;
    std::atomic<bool> dead{false};

    // Thread currently owning the active-channel lock (holds the live
    // ActiveChannelHolder). std::thread::id{} == no owner. Set (release) when
    // a holder takes the lock, cleared (release) when that holder releases.
    // Read (acquire) by the re-entrancy guard BEFORE locking sessionMutex, so
    // it must be readable without sessionMutex — hence atomic. Off the wire
    // path; lock-freedom not required.
    std::atomic<std::thread::id> activeChannelOwner{};

    [[nodiscard]] bool callerOwnsActiveChannel() const noexcept
    {
        return activeChannelOwner.load(std::memory_order_acquire) == std::this_thread::get_id();
    }

    // SessionPresence registration: populated when this session activates a
    // secure-messaging channel through a shared_ptr-managed CardSession. The
    // RAII handle removes the entry from the process-local registry on
    // destruction; ~Impl therefore covers session teardown automatically,
    // and clearActiveChannel/markDead reset the optional explicitly so the
    // registry reflects the absence of a live SM channel even if the
    // shared_ptr outlives the channel.
    std::optional<LibreSCRS::SmartCard::Internal::SessionPresence::Registration> presence;
};

} // namespace LibreSCRS::SmartCard

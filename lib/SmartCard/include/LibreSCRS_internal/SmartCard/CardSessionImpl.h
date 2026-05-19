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

#include "smartcard/pcsc_connection.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
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
    std::unique_ptr<LibreSCRS::SecureChannel::ISecureChannel> activeChannel;
    std::array<LibreSCRS::Secure::String, LibreSCRS::Auth::kPaceSecretKindCount> paceCredentialsCache;
    // BAC consumes a structurally distinct tuple (documentNumber + two dates)
    // rather than a single secret, so it gets its own cache slot disjoint
    // from the PACE credentials cache.
    std::optional<LibreSCRS::SecureChannel::BacInput> bacInput;
    std::optional<LibreSCRS::Auth::CredentialProvider> credentialProvider;
    std::mutex sessionMutex;
    std::atomic<bool> dead{false};
};

} // namespace LibreSCRS::SmartCard

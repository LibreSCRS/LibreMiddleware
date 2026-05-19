// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Out-of-line definitions for the non-virtual base
///        @ref LibreSCRS::Plugin::CardPlugin::canHandle (NVI over
///        @ref LibreSCRS::Plugin::CardPlugin::supportedAtrs) and the
///        cancel-aware @c readCard / @c sign / @c setTrustStore funnels.
///
/// Lives alongside @c card_plugin_key_function.cpp in the @c CardPlugin_Impl
/// translation unit so consumers of the registry get the symbol "for free"
/// — no separate library link required. Per Meyers, *Effective C++* 3e
/// Item 39 (NVI), the public non-virtual @c canHandle calls the protected
/// virtual @c supportedAtrs so the matching policy is centralised here and
/// derived plugins never re-implement the byte loop.

#include <LibreSCRS/Auth/ErrorKeys.h>
#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Trust/TrustStore.h>

#include <atomic>
#include <memory>
#include <string>
#include <utility>

namespace LibreSCRS::Plugin {

bool CardPlugin::canHandle(std::span<const std::uint8_t> atr) const noexcept
{
    for (const auto& entry : supportedAtrs()) {
        if (entry.matches(atr)) {
            return true;
        }
    }
    return false;
}

ReadResult CardPlugin::readCard(SmartCard::CardSession& session, GroupCallback onGroup, CancelToken token) const
{
    if (token.isCancelled())
        return ReadResult::cancelled();
    return doReadCard(session, std::move(onGroup));
}

SignResult CardPlugin::sign(SmartCard::CardSession& session, std::uint16_t keyReference,
                            std::span<const std::uint8_t> data, SignMechanism mechanism, CancelToken token) const
{
    if (token.isCancelled()) {
        return SignResult::cancelled();
    }
    return doSign(session, keyReference, data, mechanism);
}

void CardPlugin::setTrustStore(std::shared_ptr<const LibreSCRS::Trust::TrustStore> trustStore) noexcept
{
    // Single-shot: test_and_set returns the prior flag value. First
    // caller observes false (publish path runs), every later caller
    // observes true (no-op). std::memory_order_acq_rel pairs an
    // acquire on this read with a release on doSetTrustStore's writes
    // becoming visible to subsequent threads.
    if (trustStoreInjectedFlag.test_and_set(std::memory_order_acq_rel))
        return;
    doSetTrustStore(std::move(trustStore));
}

} // namespace LibreSCRS::Plugin

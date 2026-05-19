// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS_internal/SecureChannel/detail/ChannelStateMutator.h>

#include <utility>

namespace LibreSCRS::SecureChannel::detail {

void ChannelStateMutator::setCurrentApplet(ISecureChannel& ch, LibreSCRS::SmartCard::AppletAid aid) noexcept
{
    ch.setCurrentApplet(std::move(aid));
}

void ChannelStateMutator::replaceKeys(ISecureChannel& ch, SessionKeys keys) noexcept
{
    ch.replaceKeys(std::move(keys));
}

} // namespace LibreSCRS::SecureChannel::detail

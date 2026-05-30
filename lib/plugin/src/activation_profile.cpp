// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include <LibreSCRS/Plugin/ActivationProfile.h>

namespace LibreSCRS::Plugin {

using LibreSCRS::SecureChannel::ChannelActivationError;

bool isStopError(ChannelActivationError e) noexcept
{
    switch (e) {
    case ChannelActivationError::Cancelled:
    case ChannelActivationError::UserCancelled:
    case ChannelActivationError::CardRemoved:
        return true;
    default:
        return false;
    }
}

bool shouldTryFallback(const ActivationProfile& profile, ChannelActivationError e) noexcept
{
    return profile.allowBacFallback && !isStopError(e);
}

std::expected<LibreSCRS::SmartCard::ActiveChannelHolder, ChannelActivationError>
acquireChannelForProfile(LibreSCRS::SmartCard::CardSession& session, const ActivationProfile& profile,
                         LibreSCRS::CancelToken token)
{
    // Precondition: callers guard on requiresActivation(); a plain profile never reaches here.
    auto first = session.activateChannelWithSm(*profile.aid, profile.primary, token);
    if (first || !shouldTryFallback(profile, first.error())) {
        return first;
    }
    return session.activateChannelWithSm(
        *profile.aid, LibreSCRS::SmartCard::SmProtocolRequest{LibreSCRS::SmartCard::BacRequest{}}, token);
}

} // namespace LibreSCRS::Plugin

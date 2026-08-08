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
    // Fall back to BAC ONLY when the document is structurally without PACE
    // (PaceUnsupported). BAC derives its keys from the document's printed
    // access data — a strictly weaker channel than PACE — so falling back on
    // any other non-stop error is a silent protocol-downgrade surface: a
    // transient failure, a wrong secret, or (worst) a detected downgrade would
    // otherwise coax a PACE-capable document onto the weaker channel. A
    // detected downgrade in particular (PaceDowngradeDetected) must never be
    // answered by retrying the very protocol the downgrade aimed for.
    return profile.allowBacFallback && e == ChannelActivationError::PaceUnsupported;
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

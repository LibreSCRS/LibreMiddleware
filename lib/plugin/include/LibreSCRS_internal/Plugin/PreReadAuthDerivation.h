// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS_internal/Plugin/PreReadAuthDerivation.h is internal to LibreMiddleware."
#endif

#pragma once

/// @file
/// @brief The ONE profile→pre-read-auth mapping, shared by the
///        @ref LibreSCRS::Plugin::CardPlugin base derivation and any plugin
///        whose @c preReadAuth override answers from a hypothetical profile
///        (e.g. "as if a credential provider were installed" on a
///        provider-less presence session).
///
/// The mapping and the profile computation are the two halves of "what will
/// the user be asked"; keeping the mapping in exactly one place means a
/// report-side override can never diverge from the activation-side answer on
/// the same profile. Header-only inline in a NON-installed internal header:
/// no exported symbol, no ABI change.

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/PaceSecretKind.h>
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/SmartCard/SmProtocolRequest.h>

#include <variant>

namespace LibreSCRS::Plugin::detail {

/// @brief Map an activation profile to the pre-read prompt it implies.
///
/// A CAN-keyed PACE profile maps to the CAN unlock prompt; every other
/// activating profile (MRZ-keyed PACE, PIN/PUK-as-PACE, or plain BAC)
/// collects the MRZ as its pre-read secret; a non-activating profile asks
/// nothing.
[[nodiscard]] inline Auth::PreReadAuthMethod preReadAuthForProfile(const ActivationProfile& profile)
{
    if (!profile.requiresActivation()) {
        return Auth::PreReadAuthMethod::None;
    }
    if (const auto* pace = std::get_if<SmartCard::PaceRequest>(&profile.primary)) {
        return pace->secretKind == Auth::PaceSecretKind::Can ? Auth::PreReadAuthMethod::Can
                                                             : Auth::PreReadAuthMethod::Mrz;
    }
    if (std::holds_alternative<SmartCard::ChipAuthRequest>(profile.primary)) {
        // Reuse of an already-proven live tunnel collects no user secret;
        // the Mrz fallthrough below would promise a prompt that never comes.
        return Auth::PreReadAuthMethod::None;
    }
    return Auth::PreReadAuthMethod::Mrz;
}

} // namespace LibreSCRS::Plugin::detail

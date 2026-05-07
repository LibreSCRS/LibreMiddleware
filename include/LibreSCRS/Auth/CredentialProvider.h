// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Auth::CredentialProvider — @c SyncProvider
///        specialisation for the host-supplied callback that answers an
///        @ref LibreSCRS::Auth::AuthRequirement with a populated
///        @ref LibreSCRS::Auth::CredentialResult.
/// @since 4.0

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/SyncProvider.h>

namespace LibreSCRS::Auth {

/// @brief Host-supplied callback that collects credentials on demand.
///
/// The callback receives an @ref LibreSCRS::Auth::AuthRequirement describing
/// what to collect and returns a @ref LibreSCRS::Auth::CredentialResult
/// carrying either the populated values, a user-cancelled outcome, or a
/// provider-side error.
///
/// @par See LibreSCRS::SyncProvider
/// The invocation, thread-safety, empty-callable, and `CopyConstructible`
/// contracts are documented once on the generic alias. Refer there for the
/// normative wording. `SigningService::sign` and the PIN-changing entries on
/// `CardPlugin` map an empty callable to `Status::InvalidRequest` rather
/// than letting `std::bad_function_call` propagate.
using CredentialProvider = SyncProvider<CredentialResult, AuthRequirement>;

} // namespace LibreSCRS::Auth

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::SyncProvider — generic synchronous-callback alias
///        used by every host-supplied runtime-secret provider on the public
///        LibreSCRS API.
/// @since 4.0

#include <functional>

namespace LibreSCRS {

/// @brief Generic synchronous host-supplied callback alias.
///
/// `SyncProvider<Result, Context>` is the canonical shape for every
/// runtime-secret / runtime-config callback exposed across the LibreSCRS
/// public API. Specialisations include
/// @ref LibreSCRS::Auth::CredentialProvider
/// (`SyncProvider<CredentialResult, AuthRequirement>`) and
/// @ref LibreSCRS::Signing::TsaProvider
/// (`SyncProvider<TsaRequest, TsaContext>`). Future additions follow the same
/// shape rather than introducing a new bespoke alias each time.
///
/// @par Invocation contract
/// The middleware calls a `SyncProvider` synchronously on the same thread
/// that invoked the public-API entry point (e.g. `SigningService::sign`,
/// `CardPlugin::changePIN`). Implementations are free to perform blocking
/// work — open a modal dialog, query a configuration service, hit the
/// keychain — for as long as user interaction or remote IO requires.
/// The middleware does not impose a timeout.
///
/// @par Thread-safety
/// Thread-safe (see API-POLICY §8). If the host invokes a public LibreSCRS
/// entry point from multiple threads concurrently, the SAME provider
/// instance may be invoked concurrently. Providers MUST be reentrant —
/// providers backed by a Qt modal dialog should marshal to the GUI thread
/// via `QMetaObject::invokeMethod`, providers backed by a TUI prompt should
/// serialise prompts under a mutex, etc.
///
/// @par Empty-callable contract
/// An empty `std::function` is never invoked. Public entry points that
/// accept a `SyncProvider` check `static_cast<bool>(provider)` before
/// calling and translate emptiness to a runtime-result error
/// (`SigningResult::Status::InvalidRequest`,
/// `PINResult::Status::InvalidRequest`, etc.) rather than letting
/// `std::bad_function_call` propagate. Hosts wishing to opt into a
/// "no provider available" path simply pass a default-constructed
/// `SyncProvider`.
///
/// @par CopyConstructible state
/// Every state captured by the closure must be `CopyConstructible` — the
/// `std::function` contract requires the target to be stored behind a
/// type-erased copy. Closures that capture move-only resources
/// (`std::unique_ptr<PromptDialog>`, raw file descriptors, live HTTP
/// clients) should wrap the move-only state in a `std::shared_ptr` before
/// capture; the shared_ptr itself is `CopyConstructible` and keeps the
/// underlying resource alive for the full provider lifetime.
///
/// @tparam Result Value type the middleware expects back from the provider.
/// @tparam Context Input record describing what the middleware needs.
///
/// @since 4.0
template <typename Result, typename Context>
using SyncProvider = std::function<Result(const Context&)>;

} // namespace LibreSCRS

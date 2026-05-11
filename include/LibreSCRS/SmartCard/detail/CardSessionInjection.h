// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "LibreSCRS/SmartCard/detail/CardSessionInjection.h is internal to LibreMiddleware"
#endif

/// @file
/// @brief Test-only injection header for the detached-session factory
///        `LibreSCRS::SmartCard::detail::makeDetachedCardSession`.
///
/// The detached-session factory returns a CardSession that owns a
/// PCSCConnection constructed with `LibreSCRS::SmartCard::Internal::PCSCConnection::DetachedTag`
/// — no SCard context, no card handle, no transmit I/O. The only purpose
/// of such a session is to serve as a stable per-session key for plugins
/// that maintain a `std::map<PCSCConnection*, ...>` per-session state
/// table. Plugins' canHandleConnection / readCard paths that attempt real
/// I/O will fail gracefully (returning false / empty data) on a detached
/// session, but the state-separation invariants of the per-session map
/// remain observable.
///
/// The declaration itself lives in `<LibreSCRS/SmartCard/CardSession.h>`
/// so the friend declaration on `CardSession` can name it. Including this
/// header pulls CardSession.h; the `#error` guard above keeps the include
/// to internal translation units.
#include <LibreSCRS/SmartCard/CardSession.h>

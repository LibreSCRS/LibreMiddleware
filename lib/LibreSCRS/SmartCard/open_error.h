// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <LibreSCRS/LocalizedText.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/TransportError.h>

namespace LibreSCRS::SmartCard::Internal {

// The failure message every failed open carries (defined once, built at load).
extern const LocalizedText kOpenFailedMsg;

// A failed open as the OpenError the caller sees: the kind of the same name
// (CardReset has no counterpart at open and is ReaderUnavailable), the shared
// user message, and a diagnostic that names the open.
[[nodiscard]] OpenError toOpenError(const TransportError& e);

} // namespace LibreSCRS::SmartCard::Internal

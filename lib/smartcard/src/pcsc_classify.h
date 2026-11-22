// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <LibreSCRS/SmartCard/TransportError.h>

#include <string>

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

namespace LibreSCRS::SmartCard::Internal {

// The one place a PC/SC code becomes a kind, on every body alike (PC/SC or
// CryptoTokenKit, which raise the same codes). A code not listed means this
// connection cannot continue, so it is ReaderUnavailable.
[[nodiscard]] TransportError::Kind classifyPcscCode(LONG code) noexcept;

[[nodiscard]] TransportError pcscFailure(LONG code, std::string detail);

} // namespace LibreSCRS::SmartCard::Internal

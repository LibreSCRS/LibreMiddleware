// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Open a real PC/SC connection outside CardSession, for hardware
///        probes and diagnostic tools only.
///
/// This header is on the include path of the build-tree-only
/// @c LibreSCRS_SmartCard_RawDiagnostic archive's consumers and of nothing
/// else, and the function's only definition lives in that archive. Production
/// code opens a card through @c CardSession::open, which keeps one session
/// per reader; a library source that tried this instead could neither name
/// the function (the friend declaration in pcsc_connection.h is not visible
/// to ordinary lookup) nor, having declared it itself, link it.

#pragma once

#include <pcsc_connection.h>

#include <memory>
#include <string>

namespace LibreSCRS::SmartCard::Internal {

/// Connect to @p readerName directly. Throws PCSCError when the reader has no
/// card or PC/SC refuses the connection.
[[nodiscard]] std::unique_ptr<PCSCConnection> openRawDiagnostic(const std::string& readerName);

} // namespace LibreSCRS::SmartCard::Internal

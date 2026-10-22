// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

// The connection's tracer and its one shared rule, used by every body of
// PCSCConnection. Hidden: nothing outside the SmartCard library calls them.

#include "pcsc_connection.h" // DWORD

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <string>

namespace LibreSCRS::SmartCard::Internal::detail {

// INSes whose payload carries PIN / PUK / new-PIN bytes (kept consistent
// with transmitRaw's masking precedent):
//   0x20 VERIFY
//   0x24 CHANGE REFERENCE DATA
//   0x2C RESET RETRY COUNTER (PUK + new PIN in P1=0x00/0x02 forms)
[[nodiscard]] inline constexpr bool isSensitiveIns(std::uint8_t ins) noexcept
{
    return ins == 0x20 || ins == 0x24 || ins == 0x2C;
}

/// Whether LIBRESCRS_PCSC_TRACE asks for a trace (read once).
[[nodiscard]] LIBRESCRS_INTERNAL bool pcscTraceEnabled();

/// One trace block for a lifecycle event of the connection at @p conn.
LIBRESCRS_INTERNAL void emitPcscTraceEvent(const char* phase, const std::string& readerName, const void* conn);

/// One trace block for an APDU on the wire; PIN-bearing data is redacted.
LIBRESCRS_INTERNAL void emitPcscTraceWire(const char* phase, const std::string& readerName, const void* conn,
                                          const std::uint8_t* bytes, DWORD len);

} // namespace LibreSCRS::SmartCard::Internal::detail

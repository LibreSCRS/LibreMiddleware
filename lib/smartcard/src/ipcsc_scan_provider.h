// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

namespace LibreSCRS::SmartCard::Internal {

class IPCSCScanProvider
{
public:
    virtual ~IPCSCScanProvider() = default;
    virtual LONG establishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2,
                                  LPSCARDCONTEXT phContext) = 0;
    virtual LONG releaseContext(SCARDCONTEXT hContext) = 0;
    virtual LONG listReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders) = 0;
    virtual LONG getStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE* rgReaderStates,
                                 DWORD cReaders) = 0;
    virtual LONG cancel(SCARDCONTEXT hContext) = 0;

    /// What SCARD_E_NO_ACCESS from establishContext means for this source;
    /// the monitor reports it once, in its Error event.
    [[nodiscard]] virtual const char* refusalDetail() const noexcept
    {
        return "PC/SC access denied to this process (SCARD_E_NO_ACCESS)";
    }
};

} // namespace LibreSCRS::SmartCard::Internal

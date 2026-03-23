// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#ifdef __APPLE__
#include <PCSC/winscard.h>
#include <PCSC/wintypes.h>
#else
#include <winscard.h>
#endif

namespace smartcard {

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
};

} // namespace smartcard

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#ifndef SMARTCARD_PCSC_SCAN_PROVIDER_H
#define SMARTCARD_PCSC_SCAN_PROVIDER_H

#include "ipcsc_scan_provider.h"

namespace smartcard {

class PCSCScanProvider : public IPCSCScanProvider
{
public:
    LONG establishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext) override
    {
        return SCardEstablishContext(dwScope, pvReserved1, pvReserved2, phContext);
    }
    LONG releaseContext(SCARDCONTEXT hContext) override
    {
        return SCardReleaseContext(hContext);
    }
    LONG listReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders) override
    {
        return SCardListReaders(hContext, mszGroups, mszReaders, pcchReaders);
    }
    LONG getStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE* rgReaderStates,
                         DWORD cReaders) override
    {
        return SCardGetStatusChange(hContext, dwTimeout, rgReaderStates, cReaders);
    }
    LONG cancel(SCARDCONTEXT hContext) override
    {
        return SCardCancel(hContext);
    }
};

} // namespace smartcard

#endif // SMARTCARD_PCSC_SCAN_PROVIDER_H

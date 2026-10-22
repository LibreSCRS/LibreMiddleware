// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "ctk_smartcard.h"
#include "ipcsc_scan_provider.h"

#include <LibreSCRS/Export.h>

#include <atomic>
#include <memory>

namespace LibreSCRS::SmartCard::Internal {

/// Reader events from CryptoTokenKit's slot list, answered in PC/SC terms so
/// the monitor's loop runs unchanged. Never opens a card session.
///
/// - establishContext takes the slot manager: SCARD_E_NO_ACCESS without one.
/// - Slot states map to PC/SC states: Missing UNKNOWN|UNAVAILABLE, Empty
///   EMPTY, ValidCard PRESENT with the ATR, MuteCard PRESENT|MUTE, Probing
///   the settled state before it. INUSE and EXCLUSIVE never appear. The
///   upper 16 bits count the slot's transitions.
/// - The PnP pseudo-reader carries the slot count in its upper 16 bits, as
///   pcsc-lite carries the reader count.
/// - Slots that were there and are all gone answer SCARD_E_NO_SERVICE, so
///   the monitor takes the manager again (the system service restarted).
///
/// @par Thread-safety
/// As IPCSCScanProvider: one thread waits, another may cancel.
class LIBRESCRS_INTERNAL CtkScanProvider final : public IPCSCScanProvider
{
public:
    CtkScanProvider();
    explicit CtkScanProvider(std::unique_ptr<Ctk::CtkSlots> slots);

    LONG establishContext(DWORD dwScope, LPCVOID pvReserved1, LPCVOID pvReserved2, LPSCARDCONTEXT phContext) override;
    LONG releaseContext(SCARDCONTEXT hContext) override;
    LONG listReaders(SCARDCONTEXT hContext, LPCSTR mszGroups, LPSTR mszReaders, LPDWORD pcchReaders) override;
    LONG getStatusChange(SCARDCONTEXT hContext, DWORD dwTimeout, SCARD_READERSTATE* rgReaderStates,
                         DWORD cReaders) override;
    LONG cancel(SCARDCONTEXT hContext) override;
    [[nodiscard]] const char* refusalDetail() const noexcept override
    {
        return Ctk::kNoManagerDetail;
    }

private:
    std::unique_ptr<Ctk::CtkSlots> slots;
    // Slots were seen since the manager was taken: their all going away
    // means the service went, not that the last reader was unplugged.
    std::atomic<bool> sawSlots{false};
};

} // namespace LibreSCRS::SmartCard::Internal

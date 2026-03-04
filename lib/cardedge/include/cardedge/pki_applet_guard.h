// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef CARDEDGE_PKI_APPLET_GUARD_H
#define CARDEDGE_PKI_APPLET_GUARD_H

#include <functional>
#include "smartcard/pcsc_connection.h"

namespace cardedge {

// RAII guard: acquires an exclusive PC/SC transaction, selects the CardEdge
// PKI applet (AID_PKCS15) on construction, and — if a re-selection hook is
// provided — calls it to restore the card's home applet before releasing the
// transaction on destruction.
//
// Holding the transaction serialises access across all processes sharing the
// reader (e.g. LibreCelik + PKCS#11 module). The re-selection hook ensures
// each consumer finds the card in a predictable state after the guard exits.
//
// Usage:
//   // eID — must return to the eID applet so the PKCS#11 module or the
//   //        next process picks the card up in a known state.
//   PkiAppletGuard guard(conn, [](auto& c) {
//       CardReaderGemalto::selectApplication(c);
//   });
//
//   // PKS / Health PKI — no home applet; guard just serialises access.
//   PkiAppletGuard guard(conn);

class PkiAppletGuard {
public:
    using ReselHook = std::function<void(smartcard::PCSCConnection&)>;

    explicit PkiAppletGuard(smartcard::PCSCConnection& conn,
                            ReselHook on_exit = nullptr);
    ~PkiAppletGuard() noexcept;

    PkiAppletGuard(const PkiAppletGuard&) = delete;
    PkiAppletGuard& operator=(const PkiAppletGuard&) = delete;

private:
    smartcard::PCSCConnection& conn;
    smartcard::CardTransaction  tx;
    ReselHook                  on_exit;
};

} // namespace cardedge

#endif // CARDEDGE_PKI_APPLET_GUARD_H

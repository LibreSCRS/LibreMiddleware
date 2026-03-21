// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef CARDEDGE_PKI_APPLET_GUARD_H
#define CARDEDGE_PKI_APPLET_GUARD_H

#include "smartcard/pcsc_connection.h"

namespace cardedge {

// RAII guard: acquires an exclusive PC/SC transaction and selects the CardEdge
// PKI applet (AID_PKCS15) on construction. Releases the transaction on destruction.
//
// Holding the transaction serialises access across all processes sharing the
// reader (e.g. LibreCelik + PKCS#11 module).
//
// Usage:
//   PkiAppletGuard guard(conn);
//   auto certs = readCertificates(conn);

class PkiAppletGuard
{
public:
    explicit PkiAppletGuard(smartcard::PCSCConnection& conn);
    ~PkiAppletGuard() noexcept;

    PkiAppletGuard(const PkiAppletGuard&) = delete;
    PkiAppletGuard& operator=(const PkiAppletGuard&) = delete;

private:
    smartcard::PCSCConnection& conn;
    smartcard::CardTransaction tx;
};

} // namespace cardedge

#endif // CARDEDGE_PKI_APPLET_GUARD_H

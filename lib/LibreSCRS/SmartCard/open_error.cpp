// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "open_error.h"

#include <string>

namespace LibreSCRS::SmartCard::Internal {

namespace {

OpenError::Kind openKind(TransportError::Kind kind) noexcept
{
    switch (kind) {
    case TransportError::Kind::NoCardPresent:
        return OpenError::Kind::NoCardPresent;
    case TransportError::Kind::ProtocolError:
        return OpenError::Kind::ProtocolError;
    case TransportError::Kind::SessionRefused:
        return OpenError::Kind::SessionRefused;
    default:
        return OpenError::Kind::ReaderUnavailable;
    }
}

} // namespace

// Shared failure message for CardSession::open(). Constructed once at load
// (LocalizedText allocates two std::strings) so open()'s noexcept body never
// runs a throwing first-call static initialisation — a load-time OOM here
// terminates before main(), never a per-call terminate in the noexcept path.
// The neutral translator-friendly key surfaces to hosts, which are free to
// refine based on @ref OpenError::kind; the defaultText is a plain sentence so
// an untranslated host still has readable text.
const LocalizedText kOpenFailedMsg{
    "librescrs.smartcard.error.openFailed",
    "Failed to open the card session. Check that the reader is connected and a card is inserted."};

OpenError toOpenError(const TransportError& e)
{
    return OpenError{openKind(e.kind), kOpenFailedMsg, std::string{"CardSession open failed: "} + e.detail};
}

} // namespace LibreSCRS::SmartCard::Internal

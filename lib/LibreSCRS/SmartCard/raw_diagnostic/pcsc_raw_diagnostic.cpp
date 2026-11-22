// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pcsc_raw_diagnostic.h"

namespace LibreSCRS::SmartCard::Internal {

std::expected<std::unique_ptr<PCSCConnection>, TransportError> openRawDiagnostic(const std::string& readerName)
{
    return PCSCConnection::open(readerName);
}

} // namespace LibreSCRS::SmartCard::Internal

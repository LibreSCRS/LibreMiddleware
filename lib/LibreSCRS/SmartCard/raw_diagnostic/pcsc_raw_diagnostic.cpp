// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pcsc_raw_diagnostic.h"

namespace LibreSCRS::SmartCard::Internal {

std::unique_ptr<PCSCConnection> openRawDiagnostic(const std::string& readerName)
{
    return std::unique_ptr<PCSCConnection>(new PCSCConnection(readerName));
}

} // namespace LibreSCRS::SmartCard::Internal

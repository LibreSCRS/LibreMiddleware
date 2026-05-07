// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#define LIBRESCRS_INTERNAL_BUILD
#endif
#include <LibreSCRS/Certificate/ObjectIdentifier.h>

#include "internal/OidDatabase.h"

#include <utility>

namespace LibreSCRS::Certificate {

ObjectIdentifier::ObjectIdentifier(std::string oidString) : dottedDecimal(std::move(oidString)) {}

std::string ObjectIdentifier::friendlyName() const
{
    auto sv = detail::lookupOidName(dottedDecimal);
    return std::string(sv);
}

} // namespace LibreSCRS::Certificate

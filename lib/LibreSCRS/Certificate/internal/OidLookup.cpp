// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#define LIBRESCRS_INTERNAL_BUILD
#endif
#include "OidDatabase.h"

#include <algorithm>

namespace LibreSCRS::Certificate::detail {

std::string_view lookupOidName(std::string_view oid) noexcept
{
    if (kOidNamesTable.size == 0 || oid.empty())
        return {};

    const OidNameEntry* begin = kOidNamesTable.data;
    const OidNameEntry* end = kOidNamesTable.data + kOidNamesTable.size;
    auto it = std::lower_bound(begin, end, oid, [](const OidNameEntry& e, std::string_view v) { return e.oid < v; });
    if (it != end && it->oid == oid)
        return it->friendlyName;
    return {};
}

} // namespace LibreSCRS::Certificate::detail

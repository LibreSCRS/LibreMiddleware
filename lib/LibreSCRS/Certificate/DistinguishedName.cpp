// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Certificate/DistinguishedName.h>

namespace LibreSCRS::Certificate {

namespace {

std::string findFirst(const std::vector<DistinguishedNameComponent>& components, const std::string& oid)
{
    for (const auto& c : components) {
        if (c.oid.dottedDecimal == oid)
            return c.value;
    }
    return {};
}

} // namespace

std::string DistinguishedName::commonName() const
{
    return findFirst(components, "2.5.4.3");
}
std::string DistinguishedName::organization() const
{
    return findFirst(components, "2.5.4.10");
}
std::string DistinguishedName::organizationalUnit() const
{
    return findFirst(components, "2.5.4.11");
}
std::string DistinguishedName::country() const
{
    return findFirst(components, "2.5.4.6");
}

} // namespace LibreSCRS::Certificate

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
std::string DistinguishedName::stateOrProvince() const
{
    return findFirst(components, "2.5.4.8");
}
std::string DistinguishedName::locality() const
{
    return findFirst(components, "2.5.4.7");
}
std::string DistinguishedName::emailAddress() const
{
    return findFirst(components, "1.2.840.113549.1.9.1");
}

} // namespace LibreSCRS::Certificate

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SecureChannel/PaceParams.h>

#include "pace.h"

#include <optional>
#include <vector>

namespace LibreSCRS::SecureChannel {

namespace {

// Map a raw byte from EF.CardAccess to PaceStandardisedDomainParam, or
// std::nullopt for RFU / unassigned values (BSI TR-03110-3 §A.2.1.1 reserves
// 0–7 and 17–31). Switching at the byte boundary keeps the typed enum
// guarantee at the API surface — callers never observe an out-of-range
// discriminant value.
std::optional<PaceStandardisedDomainParam> mapStandardisedDomainParam(int raw)
{
    switch (raw) {
    case 8:
        return PaceStandardisedDomainParam::Secp192r1;
    case 9:
        return PaceStandardisedDomainParam::BrainpoolP192r1;
    case 10:
        return PaceStandardisedDomainParam::Secp224r1;
    case 11:
        return PaceStandardisedDomainParam::BrainpoolP224r1;
    case 12:
        return PaceStandardisedDomainParam::Secp256r1;
    case 13:
        return PaceStandardisedDomainParam::BrainpoolP256r1;
    case 14:
        return PaceStandardisedDomainParam::BrainpoolP384r1;
    case 15:
        return PaceStandardisedDomainParam::BrainpoolP512r1;
    case 16:
        return PaceStandardisedDomainParam::Secp521r1;
    default:
        return std::nullopt;
    }
}

} // namespace

std::vector<PaceSecurityInfo> parsePaceOidsFromCardAccess(std::span<const std::uint8_t> cardAccess)
{
    std::vector<std::uint8_t> buf(cardAccess.begin(), cardAccess.end());
    const auto raw = emrtd::crypto::parseCardAccessWithParams(buf);

    std::vector<PaceSecurityInfo> out;
    out.reserve(raw.size());
    for (const auto& [oid, paramIdRaw] : raw) {
        if (auto mapped = mapStandardisedDomainParam(paramIdRaw); mapped.has_value()) {
            out.push_back(PaceSecurityInfo{oid, *mapped});
        }
        // Out-of-range / RFU paramIds are intentionally dropped: surface only
        // the populated BSI table to the typed enum public surface.
    }
    return out;
}

} // namespace LibreSCRS::SecureChannel

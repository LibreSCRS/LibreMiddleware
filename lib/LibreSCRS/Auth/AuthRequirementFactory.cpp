// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Auth/AuthRequirement.h>

namespace LibreSCRS::Auth {

namespace {

FieldDescriptor bounds(std::optional<std::size_t> minLength, std::optional<std::size_t> maxLength)
{
    FieldDescriptor f;
    f.minLength = minLength;
    f.maxLength = maxLength;
    return f;
}

FieldDescriptor makePaceSecretField(PaceSecretKind kind)
{
    switch (kind) {
    case PaceSecretKind::Can:
        return bounds(6, 6);
    case PaceSecretKind::Mrz:
        return bounds(std::nullopt, std::nullopt);
    case PaceSecretKind::Pin:
        return bounds(4, 12);
    case PaceSecretKind::Puk:
        return bounds(4, 16);
    }
    return bounds(std::nullopt, std::nullopt);
}

} // namespace

AuthRequirement AuthRequirement::forSigning()
{
    AuthRequirement r;
    r.purposeValue = Purpose::Signing;
    r.fieldList.push_back(bounds(4, 12));
    return r;
}

AuthRequirement AuthRequirement::forPaceSecret(PaceSecretKind kind, LocalizedText reasonForUser) noexcept
{
    try {
        AuthRequirement r;
        r.purposeValue = Purpose::EstablishPaceChannel;
        r.fieldList.push_back(makePaceSecretField(kind));
        if (!reasonForUser.defaultText.empty() || !reasonForUser.key.empty()) {
            r.messageText = std::move(reasonForUser);
        }
        r.paceKindValue = kind;
        return r;
    } catch (...) {
        // Allocation failure constructing the PACE/BAC prompt descriptor.
        // The factory is declared `noexcept` (API-POLICY §5.1 — infallible
        // by construction); honour the contract with a degraded-but-valid
        // sentinel rather than terminating. CustomExtension purpose +
        // empty field list signals "no actionable prompt"; the OOM marker
        // key on `messageText` informs diagnostics.
        AuthRequirement r;
        r.purposeValue = Purpose::CustomExtension;
        try {
            LocalizedText marker;
            marker.key = "lc-auth-oom-fallback";
            r.messageText = std::move(marker);
        } catch (...) {
            // Marker assignment also failed — leave the requirement bare.
        }
        return r;
    }
}

} // namespace LibreSCRS::Auth

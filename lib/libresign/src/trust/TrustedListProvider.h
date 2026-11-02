// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "../native/trusted_list_parser.h"

#include <LibreSCRS/Trust/TrustStore.h> // for TrustAnchor

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

/// @brief Stateless helper: extract qualified-CA / qualified-TSA anchors
///        from a parsed @ref TrustedListInfo. Maps @c TrustedServiceEntry
///        items by @c serviceType to @c TrustAnchor instances. Used by
///        @c TrustStoreService eager-fetch workers to hand pre-mapped
///        anchors to @c TrustStoreInternalAccess::mergeTrustedListAnchors.
[[nodiscard]] std::vector<LibreSCRS::Trust::TrustAnchor> extractAnchorsFromTrustedList(const TrustedListInfo& info);

/// @brief The certificates (DER) of the qualified time-stamping services
///        (@c Svctype/TSA/QTST) of @p info, under the same status rule as
///        @ref extractAnchorsFromTrustedList. A qualified CA service is not
///        among them: a list that vouches for a certificate issuer does not
///        thereby vouch for a time-stamping authority.
[[nodiscard]] std::vector<std::vector<uint8_t>> timestampAuthorityCertificates(const TrustedListInfo& info);

} // namespace libresign

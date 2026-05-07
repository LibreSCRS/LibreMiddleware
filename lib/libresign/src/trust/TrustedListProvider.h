// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include "../../LibreSCRS/Trust/internal/TrustAnchorProvider.h"
#include "../native/trusted_list_parser.h"

#include <string>

namespace libresign {

/// @brief Provider that wraps a successfully-fetched + parsed TL.
/// Maps TrustedServiceEntry items by serviceType to TrustAnchor instances.
class TrustedListProvider : public LibreSCRS::Trust::detail::TrustAnchorProvider
{
public:
    TrustedListProvider(TrustedListInfo info, std::string sourceLabel);

    [[nodiscard]] std::vector<LibreSCRS::Trust::TrustAnchor> anchors() const override;

private:
    std::vector<LibreSCRS::Trust::TrustAnchor> cached;
};

/// @brief Stateless helper: extract qualified-CA / qualified-TSA anchors
///        from a parsed @ref TrustedListInfo. Same selection rules the
///        @ref TrustedListProvider constructor applies. Used by
///        @c TrustStoreService eager-fetch workers to hand pre-mapped
///        anchors to @c TrustStoreInternalAccess::mergeTrustedListAnchors
///        without instantiating the provider class.
[[nodiscard]] std::vector<LibreSCRS::Trust::TrustAnchor> extractAnchorsFromTrustedList(const TrustedListInfo& info,
                                                                                       const std::string& sourceLabel);

} // namespace libresign

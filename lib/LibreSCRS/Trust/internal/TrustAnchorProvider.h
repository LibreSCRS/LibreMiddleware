// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Trust/TrustStore.h> // for TrustAnchor

#include <vector>

namespace LibreSCRS::Trust::detail {

/// @brief Abstract source of trust anchors. Concrete subclasses encapsulate
///        per-source ingestion concerns (filesystem walk, parsed TL data).
/// @note LM-internal — never exposed to public consumers.
class TrustAnchorProvider
{
public:
    virtual ~TrustAnchorProvider() = default;
    [[nodiscard]] virtual std::vector<TrustAnchor> anchors() const = 0;
};

} // namespace LibreSCRS::Trust::detail

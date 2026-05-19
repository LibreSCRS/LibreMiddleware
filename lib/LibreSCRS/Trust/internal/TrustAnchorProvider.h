// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>
#include <LibreSCRS/Trust/TrustStore.h> // for TrustAnchor

#include <vector>

namespace LibreSCRS::Trust::detail {

/// @brief Abstract source of trust anchors. Concrete subclasses encapsulate
///        per-source ingestion concerns (filesystem walk, parsed TL data).
/// @note LM-internal but cross-`.so`: concrete subclasses live in the
///        `LibreSign` archive (linked into @c libLibreSCRS_Signing.so) while
///        the abstract base's typeinfo + vtable live in @c libLibreSCRS_Trust.so.
///        @c LIBRESCRS_PUBLIC_API ensures the typeinfo/vtable cross the .so
///        boundary so RTTI + virtual dispatch work under @c -fvisibility=hidden.
class LIBRESCRS_PUBLIC_API TrustAnchorProvider
{
public:
    virtual ~TrustAnchorProvider() = default;
    [[nodiscard]] virtual std::vector<TrustAnchor> anchors() const = 0;
};

} // namespace LibreSCRS::Trust::detail

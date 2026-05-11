// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS/Export.h>

#include <cstddef>
#include <string_view>

namespace LibreSCRS::Certificate::detail {

/// @brief Single OID → friendly-name entry in the codegen-emitted table.
struct OidNameEntry
{
    std::string_view oid;
    std::string_view friendlyName;
};

/// @brief Wrapper produced by the codegen step (OidDatabaseGenerated.cpp);
///        exposes the sorted constexpr array via a stable handle so the
///        lookup TU can binary-search without ODR-violating duplicate
///        external linkage of the array itself.
struct OidNameTableHandle
{
    const OidNameEntry* data;
    std::size_t size;
};

/// @brief Forward declaration of the codegen-defined table handle.
/// @note The `extern` qualifier here forces external linkage for a
///       const namespace-scope variable (C++ defaults const namespace-scope
///       variables to internal linkage). The matching definition lives in
///       OidDatabaseGenerated.cpp and gets external linkage by virtue of
///       this prior declaration.
extern const OidNameTableHandle kOidNamesTable;

/// @brief Lookup friendly name for @p oid (dotted-decimal string).
/// @return Empty string_view when no entry matches.
/// @note Exported via @ref LIBRESCRS_PUBLIC_API for the OID-database test
/// suite which links across the SHARED LibreSCRS_Certificate boundary.
[[nodiscard]] LIBRESCRS_PUBLIC_API std::string_view lookupOidName(std::string_view oid) noexcept;

} // namespace LibreSCRS::Certificate::detail

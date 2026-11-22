// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0 and LibreSCRS contributors

#pragma once

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "smartcard/or_throw.h is internal to LibreMiddleware"
#endif

#include <LibreSCRS/SmartCard/TransportError.h>

#include <expected>
#include <stdexcept>
#include <utility>

namespace LibreSCRS::SmartCard::Internal {

/// The one place a TransportError becomes an exception: card libraries that
/// work with exceptions take a connection's answer through it, and the plugin
/// entry that contains their exceptions turns them into a result. The kind is
/// not read past this point, so the exception is a plain std::runtime_error.
template <class T>
[[nodiscard]] T orThrow(std::expected<T, TransportError> r)
{
    if (!r) {
        throw std::runtime_error(r.error().detail);
    }
    return std::move(*r);
}

inline void orThrow(std::expected<void, TransportError> r)
{
    if (!r) {
        throw std::runtime_error(r.error().detail);
    }
}

} // namespace LibreSCRS::SmartCard::Internal

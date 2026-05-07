// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <openssl/crypto.h>

#include <cstddef>
#include <memory>
#include <type_traits>

namespace LibreSCRS::Secure::detail {

/// @brief std::allocator wrapper that cleanses memory before deallocate.
///
/// Forwards allocation to std::allocator<T>; on deallocate, calls
/// OPENSSL_cleanse over the freed range, then forwards to std::allocator
/// for actual delete. Stateless; all instances compare equal.
///
/// @note Cleanse happens at deallocate, not at element destroy. Element
///       destruction may leave bytes resident in the same block until the
///       block itself is freed; this is by design — earlier cleansing would
///       fight container reallocation semantics.
template <class T>
struct secure_allocator
{
    using value_type = T;
    using propagate_on_container_copy_assignment = std::false_type;
    using propagate_on_container_move_assignment = std::false_type;
    using propagate_on_container_swap = std::false_type;
    using is_always_equal = std::true_type;

    constexpr secure_allocator() noexcept = default;
    template <class U>
    constexpr secure_allocator(const secure_allocator<U>&) noexcept
    {}

    [[nodiscard]] T* allocate(std::size_t n)
    {
        return std::allocator<T>{}.allocate(n);
    }

    void deallocate(T* p, std::size_t n) noexcept
    {
        if (p && n > 0)
            OPENSSL_cleanse(p, n * sizeof(T));
        std::allocator<T>{}.deallocate(p, n);
    }
};

template <class T, class U>
constexpr bool operator==(const secure_allocator<T>&, const secure_allocator<U>&) noexcept
{
    return true;
}

} // namespace LibreSCRS::Secure::detail

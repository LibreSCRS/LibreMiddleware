// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

#include <openssl/crypto.h>

#include <cstdint>
#include <tuple>
#include <vector>

/// @file
/// @brief One scope guard that wipes every buffer it was handed, for the key
///        material three key-agreement paths hold on the heap.
///
/// Each of those paths used to declare its own local `struct` for this, and one
/// of them declared two. The bodies were the same loop over a different arity,
/// so the arity is what this takes as a parameter. That is the whole difference
/// the four copies expressed.
///
/// Why a guard at all, rather than cleansing at the end of the function: every
/// one of these paths can leave through a throw or an early return on a card
/// that answers wrongly, and the bytes that would be left behind are the ones a
/// heap reader could use to reproduce the session keys.

namespace LibreSCRS::Internal::Crypto {

/// @brief Cleanses every referenced buffer on scope exit, in declaration order.
///
/// Holds REFERENCES, so the buffers stay where their function declared them and
/// keep being written through their own names; the guard only says when they
/// are wiped. Non-copyable for the reason any scope guard is: a copy would wipe
/// the same buffers a second time at a moment nobody chose.
template <class... Vs>
class CleanseGuard
{
public:
    explicit CleanseGuard(Vs&... vs) noexcept : m_refs(vs...) {}
    CleanseGuard(const CleanseGuard&) = delete;
    CleanseGuard& operator=(const CleanseGuard&) = delete;
    CleanseGuard(CleanseGuard&&) = delete;
    CleanseGuard& operator=(CleanseGuard&&) = delete;

    ~CleanseGuard()
    {
        std::apply([](auto&... v) { (cleanse(v), ...); }, m_refs);
    }

private:
    /// OPENSSL_cleanse is documented for a non-null pointer; an empty vector's
    /// data() may legitimately be null, so the emptiness test is a contract
    /// check and not an optimisation.
    static void cleanse(std::vector<std::uint8_t>& v) noexcept
    {
        if (!v.empty()) {
            OPENSSL_cleanse(v.data(), v.size());
        }
    }

    std::tuple<Vs&...> m_refs;
};

/// Deduction guide: `CleanseGuard guard{a, b, c};` at a call site, without the
/// caller spelling out a parameter pack of identical types.
template <class... Vs>
CleanseGuard(Vs&...) -> CleanseGuard<Vs...>;

} // namespace LibreSCRS::Internal::Crypto

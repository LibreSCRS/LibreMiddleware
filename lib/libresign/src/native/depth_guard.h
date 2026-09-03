// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#pragma once

/// @file
/// @brief The recursion counter four parsing paths in this library each wrote
///        out for themselves, byte for byte.
///
/// Three of them guard attacker-supplied PDF structure ("[[[[[...", a /Pages
/// tree with a /Parent cycle) and the fourth guards a JAdES payload that is
/// itself a JWS. A stack overflow from unbounded recursion cannot be caught, so
/// each of those paths compares the counter against its own ceiling and throws
/// or refuses BEFORE descending. That check stays at the call site: the ceiling
/// and the diagnostic differ per path and are not this type's business. What is
/// this type's business is the pairing -- increment on the way in, decrement on
/// every way out, including the throw the check itself performs one frame down.

namespace libresign {

/// @brief Increments the referenced counter for the lifetime of the scope.
///
/// Holds a REFERENCE, so the counter stays where its owner declared it (a
/// member, or a `thread_local` at namespace scope) and this only says when it
/// goes up and down. Non-copyable and non-movable for the reason any scope
/// guard is: a copy would decrement a second time at a moment nobody chose.
class DepthGuard
{
public:
    explicit DepthGuard(int& depth) noexcept : m_depth(depth)
    {
        ++m_depth;
    }
    DepthGuard(const DepthGuard&) = delete;
    DepthGuard& operator=(const DepthGuard&) = delete;
    DepthGuard(DepthGuard&&) = delete;
    DepthGuard& operator=(DepthGuard&&) = delete;

    ~DepthGuard()
    {
        --m_depth;
    }

private:
    int& m_depth;
};

} // namespace libresign

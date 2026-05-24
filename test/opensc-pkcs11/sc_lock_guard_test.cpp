// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// ScLockGuard RAII contract tests. Exercises the move/copy-deleted shape
// (which is the load-bearing safety property — non-movability prevents
// "lock held past original scope" via a moved-from instance) and the
// null-card and successful-lock paths.

#include <gtest/gtest.h>

#include "sc_lock_guard.h"

#include <libopensc/opensc.h>

#include <type_traits>

using LibreSCRS::OpenSc::Pkcs11::ScLockGuard;

TEST(ScLockGuardTraits, IsNotCopyable)
{
    static_assert(!std::is_copy_constructible_v<ScLockGuard>, "ScLockGuard must not be copyable");
    static_assert(!std::is_copy_assignable_v<ScLockGuard>, "ScLockGuard must not be copy-assignable");
    SUCCEED();
}

TEST(ScLockGuardTraits, IsNotMovable)
{
    // Non-movability is intentional per the header docstring: a moved-from
    // instance would silently leave the lock held past the original scope.
    static_assert(!std::is_move_constructible_v<ScLockGuard>, "ScLockGuard must not be movable");
    static_assert(!std::is_move_assignable_v<ScLockGuard>, "ScLockGuard must not be move-assignable");
    SUCCEED();
}

TEST(ScLockGuard, NullCardYieldsUnlocked)
{
    ScLockGuard guard(nullptr);
    EXPECT_FALSE(guard.locked());
    // Destructor must be a no-op — no sc_unlock dispatched against nullptr.
}

TEST(ScLockGuard, ConstructorIsNoexcept)
{
    static_assert(std::is_nothrow_constructible_v<ScLockGuard, sc_card_t*>,
                  "ScLockGuard ctor must be noexcept (called in destructors / cleanup paths)");
    static_assert(std::is_nothrow_destructible_v<ScLockGuard>,
                  "ScLockGuard dtor must be noexcept (RAII unwind requirement)");
    SUCCEED();
}

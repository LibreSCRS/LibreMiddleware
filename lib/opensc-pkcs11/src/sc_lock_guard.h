// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief Pure RAII wrapper around @c sc_lock / @c sc_unlock for the
///        vendored libopensc surface.
///
/// Holds an @c sc_card_t transaction across a scope so the calling
/// sequence is exception-safe even if intervening C++ throws. Load-bearing
/// for PIV slot 9C "PIN ALWAYS" where the re-VERIFY + sign must execute
/// inside one uninterrupted card transaction (NIST SP 800-73 §3.2.4) —
/// any intervening APDU (e.g. OpenSC's piv_card_reader_lock_obtained
/// re-reading the Discovery Object) clears card-side auth state and the
/// subsequent PSO answers 6982.
///
/// Non-copyable and non-movable on purpose: the lock-pair has strict
/// scope identity and a moved-from instance would silently leave the lock
/// held past the original scope.

#include <libopensc/opensc.h>

namespace LibreSCRS::OpenSc::Pkcs11 {

/// @brief Scoped @c sc_lock / @c sc_unlock pair.
///
/// Construct with a bound @c sc_card_t; if @c sc_lock fails, @ref locked()
/// returns @c false and the destructor is a no-op (no unbalanced
/// @c sc_unlock against a card that was never locked).
class ScLockGuard
{
public:
    explicit ScLockGuard(sc_card_t* card) noexcept : card_(card), ok_(false)
    {
        if (card_) {
            ok_ = (sc_lock(card_) == SC_SUCCESS);
        }
    }

    ~ScLockGuard() noexcept
    {
        if (ok_ && card_) {
            sc_unlock(card_);
        }
    }

    ScLockGuard(const ScLockGuard&) = delete;
    ScLockGuard& operator=(const ScLockGuard&) = delete;
    ScLockGuard(ScLockGuard&&) = delete;
    ScLockGuard& operator=(ScLockGuard&&) = delete;

    /// @brief True iff the underlying @c sc_lock succeeded.
    [[nodiscard]] bool locked() const noexcept
    {
        return ok_;
    }

private:
    sc_card_t* card_;
    bool ok_;
};

} // namespace LibreSCRS::OpenSc::Pkcs11

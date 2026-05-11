// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// PIN-guard pattern per feedback_pin_guard_pattern.md:
// - g_pinFailed shared across the test binary
// - SKIP_IF_PIN_FAILED first line of every real-card test
// - LOGIN_OR_ABORT wraps real-card C_Login; aborts the suite on PIN
//   failure so the retry counter cannot be exhausted by repeat tests.

#pragma once

#include <gtest/gtest.h>

#include <atomic>
#include <cstdlib>
#include <string>

namespace LibreSCRS::Tests::E2E {

inline std::atomic<bool> g_pinFailed{false};

#define SKIP_IF_PIN_FAILED()                                                                                           \
    do {                                                                                                               \
        if (::LibreSCRS::Tests::E2E::g_pinFailed.load(std::memory_order_relaxed))                                      \
            GTEST_SKIP() << "PIN previously failed in this suite; aborting to avoid lockout.";                         \
    } while (0)

[[nodiscard]] inline std::string env(const char* name)
{
    const char* v = std::getenv(name);
    return v ? std::string{v} : std::string{};
}

#define REQUIRE_ENV(NAME)                                                                                              \
    do {                                                                                                               \
        if (::LibreSCRS::Tests::E2E::env(NAME).empty())                                                                \
            GTEST_SKIP() << "Missing env: " #NAME;                                                                     \
    } while (0)

/// @brief Marks the PIN-failed flag so subsequent tests skip rather than retry.
///        Aborts the test immediately. Three consecutive PIN failures permanently
///        block most cards — this guard prevents that scenario in the test suite.
inline void markPinFailedAndAbort(int line, const std::string& detail)
{
    g_pinFailed.store(true, std::memory_order_relaxed);
    FAIL() << "PIN failure at line " << line << ": " << detail
           << " — aborting suite to prevent retry-counter exhaustion.";
}

#define LOGIN_OR_ABORT(rv, slotID, mechName)                                                                           \
    do {                                                                                                               \
        if ((rv) != CKR_OK) {                                                                                          \
            ::LibreSCRS::Tests::E2E::markPinFailedAndAbort(__LINE__, std::string{"slot="} + std::to_string(slotID) +   \
                                                                         " mech=" + (mechName));                       \
            return;                                                                                                    \
        }                                                                                                              \
    } while (0)

} // namespace LibreSCRS::Tests::E2E

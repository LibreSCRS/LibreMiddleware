// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <chrono>
#include <thread>

namespace LibreSCRS::Test {

// Polls @p pred until it holds or @p limit passes. The limit only bounds a
// failure; a passing test waits for the condition, not for the time.
template <typename Pred>
bool waitFor(Pred pred, std::chrono::milliseconds limit)
{
    const auto deadline = std::chrono::steady_clock::now() + limit;
    while (!pred()) {
        if (std::chrono::steady_clock::now() >= deadline)
            return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    return true;
}

} // namespace LibreSCRS::Test

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// 4-line probe to verify std::expected is available before bumping
// LM's CMake target to cxx_std_23. Compiled by check-std-expected
// CMake configure step; if compilation fails, abort with diagnostic
// directing to the LibreSCRS::Expected<T,E> fallback wrapper.

#include <expected>
#include <string>

int main()
{
    std::expected<int, std::string> r = 42;
    return r.value() == 42 ? 0 : 1;
}

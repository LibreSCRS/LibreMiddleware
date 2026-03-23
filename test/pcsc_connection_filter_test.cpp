// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

TEST(PCSCConnectionFilter, FilterAPIExists)
{
    using Filter = smartcard::PCSCConnection::TransmitFilter;
    static_assert(std::is_invocable_r_v<smartcard::APDUResponse, Filter, const smartcard::APDUCommand&>);
    SUCCEED();
}

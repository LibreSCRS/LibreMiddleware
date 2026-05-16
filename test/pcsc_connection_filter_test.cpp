// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <apdu.h>
#include <smartcard/pcsc_connection.h>

TEST(PCSCConnectionFilter, FilterAPIExists)
{
    using Filter = LibreSCRS::SmartCard::Internal::PCSCConnection::TransmitFilter;
    static_assert(std::is_invocable_r_v<LibreSCRS::SmartCard::Internal::APDUResponse, Filter,
                                        const LibreSCRS::SmartCard::Internal::APDUCommand&>);
    SUCCEED();
}

TEST(PCSCConnectionCancel, CancelAPIExists)
{
    // PCSCConnection::cancel() must exist and be callable.
    // Verifies the method signature at compile time.
    static_assert(std::is_member_function_pointer_v<decltype(&LibreSCRS::SmartCard::Internal::PCSCConnection::cancel)>);
    SUCCEED();
}

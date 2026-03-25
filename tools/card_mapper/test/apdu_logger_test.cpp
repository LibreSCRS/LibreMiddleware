// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "apdu_logger.h"

#include <gtest/gtest.h>

using namespace card_mapper;

TEST(ApduLogger, EmptyTrace)
{
    ApduLogger logger;
    auto trace = logger.formatTrace();
    EXPECT_TRUE(trace.empty());
}

TEST(ApduLogger, LogSingleEntry)
{
    ApduLogger logger;

    smartcard::APDUCommand cmd;
    cmd.cla = 0x00;
    cmd.ins = 0xA4;
    cmd.p1 = 0x04;
    cmd.p2 = 0x00;
    cmd.data = {0xA0, 0x00};
    cmd.le = 0;
    cmd.hasLe = true;

    smartcard::APDUResponse resp;
    resp.data = {0x6F, 0x10};
    resp.sw1 = 0x90;
    resp.sw2 = 0x00;

    logger.log(cmd, resp);

    auto trace = logger.formatTrace();
    // Should contain >> for command
    EXPECT_NE(trace.find(">>"), std::string::npos);
    // Should contain << for response
    EXPECT_NE(trace.find("<<"), std::string::npos);
    // Should contain the SW bytes
    EXPECT_NE(trace.find("90 00"), std::string::npos);
}

TEST(ApduLogger, LogMultipleEntries)
{
    ApduLogger logger;

    smartcard::APDUCommand cmd1;
    cmd1.cla = 0x00;
    cmd1.ins = 0xA4;
    cmd1.p1 = 0x04;
    cmd1.p2 = 0x00;
    cmd1.hasLe = false;

    smartcard::APDUResponse resp1;
    resp1.sw1 = 0x90;
    resp1.sw2 = 0x00;

    smartcard::APDUCommand cmd2;
    cmd2.cla = 0x00;
    cmd2.ins = 0xB0;
    cmd2.p1 = 0x00;
    cmd2.p2 = 0x00;
    cmd2.le = 0xFF;
    cmd2.hasLe = true;

    smartcard::APDUResponse resp2;
    resp2.data = {0x01, 0x02, 0x03};
    resp2.sw1 = 0x90;
    resp2.sw2 = 0x00;

    logger.log(cmd1, resp1);
    logger.log(cmd2, resp2);

    EXPECT_EQ(logger.getEntries().size(), 2u);

    auto trace = logger.formatTrace();
    // Should have two >> lines
    size_t pos1 = trace.find(">>");
    EXPECT_NE(pos1, std::string::npos);
    size_t pos2 = trace.find(">>", pos1 + 2);
    EXPECT_NE(pos2, std::string::npos);
}

TEST(ApduLogger, Clear)
{
    ApduLogger logger;

    smartcard::APDUCommand cmd;
    cmd.cla = 0x00;
    cmd.ins = 0xA4;
    cmd.p1 = 0x00;
    cmd.p2 = 0x00;
    cmd.hasLe = false;

    smartcard::APDUResponse resp;
    resp.sw1 = 0x90;
    resp.sw2 = 0x00;

    logger.log(cmd, resp);
    EXPECT_EQ(logger.getEntries().size(), 1u);

    logger.clear();
    EXPECT_EQ(logger.getEntries().size(), 0u);
}

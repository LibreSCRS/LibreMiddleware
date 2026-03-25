// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "scaffold_generator.h"

#include <gtest/gtest.h>

using namespace card_mapper;

TEST(ScaffoldGenerator, GeneratesValidHeader)
{
    ScanResult scanResult;
    scanResult.atr = {0x3B, 0xFF, 0x94, 0x00, 0x00};

    AppletInfo applet;
    applet.name = "Test Applet";
    applet.aids = {{0xF3, 0x81, 0x00, 0x01}};
    applet.rootNode.name = "MF";
    applet.rootNode.fidHi = 0x3F;
    applet.rootNode.fidLo = 0x00;
    applet.rootNode.isDir = true;

    FileNode ef;
    ef.name = "EF (0F02)";
    ef.fidHi = 0x0F;
    ef.fidLo = 0x02;

    FileNode df;
    df.name = "DF";
    df.isDir = true;
    df.children = {ef};
    applet.rootNode.children = {df};

    DataFile dataFile;
    dataFile.name = "EF (0F02)";
    dataFile.fidHi = 0x0F;
    dataFile.fidLo = 0x02;
    dataFile.tags = {
        {0x060A, "kTag_060A", "Tag 1546", "string", ""},
        {0x060B, "kTag_060B", "Tag 1547", "string", ""},
    };
    applet.dataFiles = {dataFile};

    scanResult.detectedApplets = {applet};

    auto header = generateProtocolHeader("newcard", scanResult);

    // Check SPDX header
    EXPECT_NE(header.find("SPDX-License-Identifier: LGPL-2.1-or-later"), std::string::npos);
    // Check pragma once
    EXPECT_NE(header.find("#pragma once"), std::string::npos);
    // Check namespace
    EXPECT_NE(header.find("namespace newcard::protocol"), std::string::npos);
    EXPECT_NE(header.find("} // namespace newcard::protocol"), std::string::npos);
    // Check ATR comment
    EXPECT_NE(header.find("ATR: 3B FF 94 00 00"), std::string::npos);
    // Check AID uses constexpr std::array
    EXPECT_NE(header.find("constexpr std::array<uint8_t, 4> kAID_0"), std::string::npos);
    EXPECT_NE(header.find("0xF3"), std::string::npos);
    // Check includes
    EXPECT_NE(header.find("#include <cstdint>"), std::string::npos);
    EXPECT_NE(header.find("#include <array>"), std::string::npos);
    // Check file IDs
    EXPECT_NE(header.find("kFile_0F02_H"), std::string::npos);
    EXPECT_NE(header.find("kFile_0F02_L"), std::string::npos);
    // Check TLV tags
    EXPECT_NE(header.find("kTag_060A"), std::string::npos);
    EXPECT_NE(header.find("kTag_060B"), std::string::npos);
}

TEST(ScaffoldGenerator, EmptyScanResult)
{
    ScanResult scanResult;
    auto header = generateProtocolHeader("empty", scanResult);

    EXPECT_NE(header.find("namespace empty::protocol"), std::string::npos);
    EXPECT_NE(header.find("#pragma once"), std::string::npos);
}

TEST(ScaffoldGenerator, MultipleApplets)
{
    ScanResult scanResult;
    scanResult.atr = {0x3B};

    AppletInfo applet1;
    applet1.name = "App1";
    applet1.aids = {{0xA0, 0x01}};
    applet1.rootNode.name = "MF";

    AppletInfo applet2;
    applet2.name = "App2";
    applet2.aids = {{0xB0, 0x02}};
    applet2.rootNode.name = "MF";

    scanResult.detectedApplets = {applet1, applet2};

    auto header = generateProtocolHeader("multi", scanResult);

    // Both AIDs should be present
    EXPECT_NE(header.find("kAID_0"), std::string::npos);
    EXPECT_NE(header.find("kAID_1"), std::string::npos);
    EXPECT_NE(header.find("0xA0"), std::string::npos);
    EXPECT_NE(header.find("0xB0"), std::string::npos);
}

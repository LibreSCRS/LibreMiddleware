// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "output_formatter.h"

#include <gtest/gtest.h>

using namespace card_mapper;

TEST(OutputFormatter, FormatHexEmpty)
{
    EXPECT_EQ(formatHex({}), "");
}

TEST(OutputFormatter, FormatHexSingle)
{
    EXPECT_EQ(formatHex({0xAB}), "AB");
}

TEST(OutputFormatter, FormatHexMultiple)
{
    EXPECT_EQ(formatHex({0xF3, 0x81, 0x00, 0x02}), "F3 81 00 02");
}

TEST(OutputFormatter, FormatFid)
{
    EXPECT_EQ(formatFid(0x0F, 0x02), "0F02");
    EXPECT_EQ(formatFid(0xD0, 0x01), "D001");
    EXPECT_EQ(formatFid(0x3F, 0x00), "3F00");
}

TEST(OutputFormatter, AsciiTreeSimple)
{
    FileNode root;
    root.name = "MF";
    root.fidHi = 0x3F;
    root.fidLo = 0x00;
    root.isDir = true;

    FileNode df;
    df.name = "DF.App";
    df.isDir = true;

    FileNode ef1;
    ef1.name = "EF.Data1";
    ef1.fidHi = 0x0F;
    ef1.fidLo = 0x02;
    ef1.format = "TLV";

    FileNode ef2;
    ef2.name = "EF.Data2";
    ef2.fidHi = 0x0F;
    ef2.fidLo = 0x03;
    ef2.format = "binary";
    ef2.note = "[optional]";

    df.children = {ef1, ef2};
    root.children = {df};

    std::string tree = formatAsciiTree(root);

    // Check root node
    EXPECT_NE(tree.find("MF (3F00)"), std::string::npos);
    // Check box-drawing characters
    EXPECT_NE(tree.find("\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80"), std::string::npos); // └──
    EXPECT_NE(tree.find("\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80"), std::string::npos); // ├──
    // Check file details
    EXPECT_NE(tree.find("EF.Data1 (0F02)"), std::string::npos);
    EXPECT_NE(tree.find("TLV"), std::string::npos);
    EXPECT_NE(tree.find("[optional]"), std::string::npos);
}

TEST(OutputFormatter, AsciiTreeSizeEstimate)
{
    FileNode root;
    root.name = "MF";

    FileNode ef;
    ef.name = "EF.Portrait";
    ef.fidHi = 0x0F;
    ef.fidLo = 0x06;
    ef.format = "binary JPEG";
    ef.sizeEstimate = "~15KB";

    root.children = {ef};

    std::string tree = formatAsciiTree(root);
    EXPECT_NE(tree.find("~15KB"), std::string::npos);
    EXPECT_NE(tree.find("binary JPEG"), std::string::npos);
}

TEST(OutputFormatter, MermaidTreeBasic)
{
    FileNode root;
    root.name = "MF";
    root.fidHi = 0x3F;
    root.fidLo = 0x00;
    root.isDir = true;

    FileNode ef;
    ef.name = "EF.Data";
    ef.fidHi = 0x0F;
    ef.fidLo = 0x02;
    ef.format = "TLV";

    root.children = {ef};

    std::string mermaid = formatMermaidTree(root);

    EXPECT_NE(mermaid.find("graph TD"), std::string::npos);
    EXPECT_NE(mermaid.find("-->"), std::string::npos);
    EXPECT_NE(mermaid.find("MF"), std::string::npos);
    EXPECT_NE(mermaid.find("0F02"), std::string::npos);
}

TEST(OutputFormatter, FormatAppletDocContainsSections)
{
    AppletInfo applet;
    applet.name = "Test Applet";
    applet.description = "A test applet";
    applet.aids = {{0xA0, 0x00, 0x01}};
    applet.aidNames = {"TEST"};
    applet.authentication = "None";
    applet.pluginName = "test";

    applet.rootNode.name = "MF";
    applet.rootNode.fidHi = 0x3F;
    applet.rootNode.fidLo = 0x00;
    applet.rootNode.isDir = true;

    FileNode ef;
    ef.name = "EF.Data";
    ef.fidHi = 0x0F;
    ef.fidLo = 0x02;
    ef.format = "TLV";
    applet.rootNode.children = {ef};

    DataFile df;
    df.name = "EF.Data";
    df.fidHi = 0x0F;
    df.fidLo = 0x02;
    df.tags = {{1546, "field_a", "Field A", "string", "example"}};
    applet.dataFiles = {df};

    std::string doc = formatAppletDoc(applet);

    // Check required sections
    EXPECT_NE(doc.find("# Test Applet"), std::string::npos);
    EXPECT_NE(doc.find("## Overview"), std::string::npos);
    EXPECT_NE(doc.find("A0 00 01"), std::string::npos);
    EXPECT_NE(doc.find("## File System Structure"), std::string::npos);
    EXPECT_NE(doc.find("### ASCII Tree"), std::string::npos);
    EXPECT_NE(doc.find("### Mermaid Diagram"), std::string::npos);
    EXPECT_NE(doc.find("## Data Elements"), std::string::npos);
    EXPECT_NE(doc.find("Field A"), std::string::npos);
    EXPECT_NE(doc.find("field_a"), std::string::npos);
    EXPECT_NE(doc.find("`test`"), std::string::npos);
}

TEST(OutputFormatter, FormatProfileDocContainsSections)
{
    ProfileInfo profile;
    profile.name = "Test Profile";
    profile.description = "A test card profile";
    profile.knownATRs = {"3B FF 94 xx"};
    profile.knownCards = {"Test Card"};
    profile.applets = {{"Test Applet", {0xA0, 0x00}, "../applets/test.md"}};
    profile.notes = "- Some note about this card\n";

    std::string doc = formatProfileDoc(profile);

    EXPECT_NE(doc.find("# Test Profile"), std::string::npos);
    EXPECT_NE(doc.find("## Overview"), std::string::npos);
    EXPECT_NE(doc.find("3B FF 94 xx"), std::string::npos);
    EXPECT_NE(doc.find("## Applets Present"), std::string::npos);
    EXPECT_NE(doc.find("Test Applet"), std::string::npos);
    EXPECT_NE(doc.find("A0 00"), std::string::npos);
    EXPECT_NE(doc.find("## Card-Specific Notes"), std::string::npos);
    EXPECT_NE(doc.find("Some note"), std::string::npos);
}

TEST(OutputFormatter, FormatAppletDocMultipleAIDs)
{
    AppletInfo applet;
    applet.name = "Multi-AID";
    applet.description = "Has multiple AIDs";
    applet.aids = {{0xA0}, {0xB0}};
    applet.aidNames = {"AID1", "AID2"};
    applet.authentication = "None";
    applet.pluginName = "multi";
    applet.rootNode.name = "MF";

    std::string doc = formatAppletDoc(applet);
    EXPECT_NE(doc.find("AID1"), std::string::npos);
    EXPECT_NE(doc.find("AID2"), std::string::npos);
}

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <smartcard/apdu.h>
#include <smartcard/tlv.h>
#include <smartcard/ber.h>

using namespace smartcard;

// --- APDU tests ---

TEST(APDUTest, VerifyPINCommand)
{
    auto cmd = smartcard::verifyPIN(0x01, {0x31, 0x32, 0x33, 0x34});
    auto bytes = cmd.toBytes();
    // CLA=0x00, INS=0x20, P1=0x00, P2=0x01, Lc=4, data=31323334, no Le
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x20);
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x01);
    EXPECT_EQ(bytes[4], 0x04); // Lc
    EXPECT_EQ(bytes[5], 0x31);
    EXPECT_EQ(bytes[6], 0x32);
    EXPECT_EQ(bytes[7], 0x33);
    EXPECT_EQ(bytes[8], 0x34);
    EXPECT_EQ(bytes.size(), 9u); // 4 header + 1 Lc + 4 data, no Le
}

TEST(APDUTest, VerifyPINStatusCommand)
{
    auto cmd = smartcard::verifyPINStatus(0x01);
    auto bytes = cmd.toBytes();
    // No data, no Le -> just 4 header bytes
    EXPECT_EQ(bytes.size(), 4u);
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x20);
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x01);
}

TEST(APDUTest, ChangeReferenceDataCommand)
{
    auto cmd = smartcard::changeReferenceData(0x01, {0x31, 0x32, 0x33, 0x34}, {0x35, 0x36, 0x37, 0x38});
    auto bytes = cmd.toBytes();
    EXPECT_EQ(bytes[0], 0x00);
    EXPECT_EQ(bytes[1], 0x24); // INS
    EXPECT_EQ(bytes[2], 0x00);
    EXPECT_EQ(bytes[3], 0x01);
    EXPECT_EQ(bytes[4], 0x08); // Lc = 4+4
    EXPECT_EQ(bytes[5], 0x31);
    EXPECT_EQ(bytes[9], 0x35);
    EXPECT_EQ(bytes.size(), 13u); // 4 header + 1 Lc + 8 data, no Le
}

// --- TLV tests ---

TEST(TLVTest, ParseEmptyData)
{
    auto fields = parseTLV(nullptr, 0);
    EXPECT_TRUE(fields.empty());
}

TEST(TLVTest, ParseSingleField)
{
    // Tag 0x0001 (LE: 01 00), Length 0x0003 (LE: 03 00), Value "abc"
    const uint8_t data[] = {0x01, 0x00, 0x03, 0x00, 'a', 'b', 'c'};
    auto fields = parseTLV(data, sizeof(data));
    ASSERT_EQ(fields.size(), 1u);
    EXPECT_EQ(fields[0].tag, 0x0001);
    EXPECT_EQ(fields[0].asString(), "abc");
}

TEST(TLVTest, ParseMultipleFields)
{
    // Field 1: tag=0x0001, len=2, value="hi"
    // Field 2: tag=0x0002, len=3, value="bye"
    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 'h', 'i', 0x02, 0x00, 0x03, 0x00, 'b', 'y', 'e'};
    auto fields = parseTLV(data, sizeof(data));
    ASSERT_EQ(fields.size(), 2u);
    EXPECT_EQ(fields[0].tag, 0x0001);
    EXPECT_EQ(fields[0].asString(), "hi");
    EXPECT_EQ(fields[1].tag, 0x0002);
    EXPECT_EQ(fields[1].asString(), "bye");
}

TEST(TLVTest, FindStringByTag)
{
    const uint8_t data[] = {0x01, 0x00, 0x02, 0x00, 'h', 'i', 0x02, 0x00, 0x03, 0x00, 'b', 'y', 'e'};
    auto fields = parseTLV(data, sizeof(data));
    EXPECT_EQ(findString(fields, 0x0002), "bye");
    EXPECT_EQ(findString(fields, 0x9999), "");
}

// --- BER-TLV tests ---

TEST(BERTest, ParseEmptyData)
{
    auto root = parseBER(nullptr, 0);
    EXPECT_TRUE(root.children.empty());
}

TEST(BERTest, ParsePrimitiveField)
{
    // Tag 0x81, Length 3, Value "abc"
    const uint8_t data[] = {0x81, 0x03, 'a', 'b', 'c'};
    auto root = parseBER(data, sizeof(data));
    ASSERT_EQ(root.children.size(), 1u);
    EXPECT_EQ(root.children[0].tag, 0x81u);
    EXPECT_EQ(root.children[0].asString(), "abc");
    EXPECT_FALSE(root.children[0].constructed);
}

TEST(BERTest, MergeBERTrees)
{
    const uint8_t data1[] = {0x81, 0x01, 'a'};
    const uint8_t data2[] = {0x82, 0x01, 'b'};
    auto tree1 = parseBER(data1, sizeof(data1));
    auto tree2 = parseBER(data2, sizeof(data2));
    mergeBER(tree1, tree2);
    ASSERT_EQ(tree1.children.size(), 2u);
    EXPECT_EQ(tree1.children[0].tag, 0x81u);
    EXPECT_EQ(tree1.children[1].tag, 0x82u);
}

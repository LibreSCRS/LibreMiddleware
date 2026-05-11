// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SmartCard/CardMap.h>

#include <gtest/gtest.h>

#include <vector>

using LibreSCRS::SmartCard::CardMap;
using LibreSCRS::SmartCard::CardMapEntry;

namespace {

CardMap::Key makeKey(const std::string& reader = "Mock Reader 0", const std::string& atrHex = "3B:9E:96:80:31:FE:45",
                     const std::string& serial = "ABCD1234")
{
    return CardMap::Key{reader, atrHex, serial};
}

CardMapEntry makeEntry(std::uint8_t p2 = 0x00, std::vector<std::uint8_t> path = {0x50, 0x15})
{
    CardMapEntry e;
    e.pkcs15Path = std::move(path);
    e.fileSelectP2 = p2;
    e.pinLabels = {"User PIN", "Sign PIN"};
    return e;
}

} // namespace

TEST(CardMapTest, GetOnEmptyReturnsNullopt)
{
    CardMap map;
    EXPECT_FALSE(map.get(makeKey()).has_value());
}

TEST(CardMapTest, PutThenGetRoundtrips)
{
    CardMap map;
    auto key = makeKey();
    map.put(key, makeEntry(0x0C, {0x3F, 0x00, 0x50, 0x15}));

    auto fetched = map.get(key);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(fetched->fileSelectP2, 0x0C);
    ASSERT_EQ(fetched->pkcs15Path.size(), 4u);
    EXPECT_EQ(fetched->pkcs15Path[2], 0x50);
    EXPECT_EQ(fetched->pkcs15Path[3], 0x15);
    EXPECT_EQ(fetched->pinLabels.size(), 2u);
}

TEST(CardMapTest, PutOverwritesExistingEntry)
{
    CardMap map;
    auto key = makeKey();
    map.put(key, makeEntry(0x0C));
    map.put(key, makeEntry(0x00, {0xAD, 0xF1}));

    auto fetched = map.get(key);
    ASSERT_TRUE(fetched.has_value());
    EXPECT_EQ(fetched->fileSelectP2, 0x00);
    ASSERT_EQ(fetched->pkcs15Path.size(), 2u);
    EXPECT_EQ(fetched->pkcs15Path[0], 0xAD);
}

TEST(CardMapTest, InvalidateRemovesKey)
{
    CardMap map;
    auto key = makeKey();
    map.put(key, makeEntry());
    ASSERT_TRUE(map.get(key).has_value());

    map.invalidate(key);
    EXPECT_FALSE(map.get(key).has_value());
}

TEST(CardMapTest, InvalidateOnAbsentKeyIsNoOp)
{
    CardMap map;
    // Must not throw / crash.
    map.invalidate(makeKey("no such reader"));
    EXPECT_FALSE(map.get(makeKey("no such reader")).has_value());
}

TEST(CardMapTest, KeyTupleDistinguishesReaders)
{
    CardMap map;
    auto keyA = makeKey("Reader A", "3B:9E:96:80", "AAAA");
    auto keyB = makeKey("Reader B", "3B:9E:96:80", "AAAA");
    map.put(keyA, makeEntry(0x0C, {0x50, 0x15}));
    map.put(keyB, makeEntry(0x00, {0xAD, 0xF1}));

    auto a = map.get(keyA);
    auto b = map.get(keyB);
    ASSERT_TRUE(a.has_value());
    ASSERT_TRUE(b.has_value());
    EXPECT_EQ(a->fileSelectP2, 0x0C);
    EXPECT_EQ(b->fileSelectP2, 0x00);
}

TEST(CardMapTest, KeyTupleDistinguishesAtrAndSerial)
{
    CardMap map;
    auto keyA = makeKey("Reader X", "3B:9E:96:80", "AAAA");
    auto keyB = makeKey("Reader X", "3B:DE:97:00", "AAAA");
    auto keyC = makeKey("Reader X", "3B:9E:96:80", "BBBB");
    map.put(keyA, makeEntry(0x0C));
    map.put(keyB, makeEntry(0x00, {0xAD, 0xF1}));
    map.put(keyC, makeEntry(0x0C, {0x50, 0x15, 0xEF, 0xC0}));

    EXPECT_EQ(map.get(keyA)->fileSelectP2, 0x0C);
    EXPECT_EQ(map.get(keyB)->fileSelectP2, 0x00);
    EXPECT_EQ(map.get(keyC)->pkcs15Path.size(), 4u);
}

TEST(CardMapTest, InvalidateAllDropsEverything)
{
    CardMap map;
    map.put(makeKey("R1"), makeEntry());
    map.put(makeKey("R2"), makeEntry());
    map.put(makeKey("R3"), makeEntry());
    ASSERT_TRUE(map.get(makeKey("R1")).has_value());

    map.invalidateAll();
    EXPECT_FALSE(map.get(makeKey("R1")).has_value());
    EXPECT_FALSE(map.get(makeKey("R2")).has_value());
    EXPECT_FALSE(map.get(makeKey("R3")).has_value());
}

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardData.h>

#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

using namespace LibreSCRS::Plugin;

TEST(CardFieldTest, TextFieldConstruction)
{
    CardField field{"given_name", "Given Name", FieldType::Text, {'J', 'o', 'h', 'n'}};
    EXPECT_EQ(field.key, "given_name");
    EXPECT_EQ(field.label, "Given Name");
    EXPECT_EQ(field.type, FieldType::Text);
    EXPECT_EQ(field.value, (std::vector<std::uint8_t>{'J', 'o', 'h', 'n'}));
}

TEST(CardFieldTest, PhotoFieldConstruction)
{
    std::vector<uint8_t> jpeg = {0xFF, 0xD8, 0xFF, 0xE0};
    CardField field{"photo", "Photo", FieldType::Photo, jpeg};
    EXPECT_EQ(field.type, FieldType::Photo);
    EXPECT_EQ(field.value, jpeg);
}

TEST(CardFieldTest, DateFieldConstruction)
{
    CardField field{"birth_date", "Date of Birth", FieldType::Date, {'1', '9', '9', '0', '0', '1', '0', '1'}};
    EXPECT_EQ(field.value.size(), 8u);
    EXPECT_EQ(field.value[0], static_cast<std::uint8_t>('1'));
}

TEST(CardFieldGroupTest, GroupWithFields)
{
    CardFieldGroup group;
    group.groupKey = "personal";
    group.groupLabel = "Personal Data";
    group.fields.push_back({"surname", "Surname", FieldType::Text, {'S', 'm', 'i', 't', 'h'}});
    group.fields.push_back({"given_name", "Given Name", FieldType::Text, {'J', 'o', 'h', 'n'}});

    EXPECT_EQ(group.fields.size(), 2u);
    EXPECT_EQ(group.fields[0].key, "surname");
}

TEST(CardDataTest, DefaultConstruction)
{
    CardData data;
    EXPECT_TRUE(data.cardType.empty());
    EXPECT_TRUE(data.groups.empty());
}

// addText now eagerly rejects an empty key per API-POLICY §5.1.
// A field without a stable key is unreachable to GUI widgets afterwards;
// silently returning the last existing field on an empty-key call hid
// this caller bug.
TEST(CardFieldGroupTest, AddTextThrowsOnEmptyKey)
{
    CardFieldGroup group;
    group.groupKey = "personal";
    group.fields.push_back({"existing", "Existing", FieldType::Text, {'X'}});

    EXPECT_THROW(group.addText("", "Label", "value"), std::invalid_argument);
    // No mutation on the failure path.
    EXPECT_EQ(group.fields.size(), 1u);
}

TEST(CardFieldGroupTest, AddTextEmptyValueOnEmptyVectorThrowsLogicError)
{
    CardFieldGroup group;
    // Returning a reference into an empty vector would be UB; the eager
    // logic_error converts the corner case into a catchable programmer
    // error and matches the documented contract.
    EXPECT_THROW(group.addText("k", "Label", ""), std::logic_error);
}

TEST(CardFieldGroupTest, AddTextEmptyValueWithPriorFieldReturnsLastNoInsert)
{
    CardFieldGroup group;
    auto& first = group.addText("first", "F", "v1");
    EXPECT_EQ(first.key, "first");
    auto& back = group.addText("second", "S", ""); // no insert; returns existing
    EXPECT_EQ(group.fields.size(), 1u);
    EXPECT_EQ(back.key, "first");
}

TEST(CardFieldGroupTest, AddTextNonEmptyInserts)
{
    CardFieldGroup group;
    auto& f = group.addText("name", "Name", "Ivan");
    EXPECT_EQ(group.fields.size(), 1u);
    EXPECT_EQ(f.key, "name");
    EXPECT_EQ(f.type, FieldType::Text);
    EXPECT_EQ(std::string(f.value.begin(), f.value.end()), "Ivan");
}

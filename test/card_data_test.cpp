// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <plugin/card_data.h>

using namespace plugin;

TEST(CardFieldTest, TextFieldConstruction)
{
    CardField field{"given_name", "Given Name", FieldType::Text, {'J', 'o', 'h', 'n'}};
    EXPECT_EQ(field.key, "given_name");
    EXPECT_EQ(field.label, "Given Name");
    EXPECT_EQ(field.type, FieldType::Text);
    EXPECT_EQ(field.asString(), "John");
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
    EXPECT_EQ(field.asString(), "19900101");
}

TEST(CardFieldGroupTest, GroupWithFields)
{
    CardFieldGroup group;
    group.groupKey = "personal";
    group.groupLabel = "Personal Data";
    group.fields.push_back({"surname", "Surname", FieldType::Text, {'S', 'm', 'i', 't', 'h'}});
    group.fields.push_back({"given_name", "Given Name", FieldType::Text, {'J', 'o', 'h', 'n'}});

    EXPECT_EQ(group.fields.size(), 2u);
    EXPECT_EQ(group.fields[0].asString(), "Smith");
}

TEST(CardDataTest, DefaultConstruction)
{
    CardData data;
    EXPECT_TRUE(data.cardType.empty());
    EXPECT_TRUE(data.groups.empty());
}

TEST(CardDataTest, FindGroupByKey)
{
    CardData data;
    data.cardType = "rs-eid";
    data.groups.push_back({"personal", "Personal Data", {}});
    data.groups.push_back({"document", "Document Data", {}});

    auto* group = data.findGroup("personal");
    ASSERT_NE(group, nullptr);
    EXPECT_EQ(group->groupLabel, "Personal Data");

    EXPECT_EQ(data.findGroup("nonexistent"), nullptr);
}

TEST(CardDataTest, FindFieldByKey)
{
    CardData data;
    data.cardType = "rs-eid";
    CardFieldGroup group;
    group.groupKey = "personal";
    group.groupLabel = "Personal Data";
    group.fields.push_back({"surname", "Surname", FieldType::Text, {'T', 'e', 's', 't'}});
    data.groups.push_back(std::move(group));

    auto* field = data.findField("surname");
    ASSERT_NE(field, nullptr);
    EXPECT_EQ(field->asString(), "Test");

    EXPECT_EQ(data.findField("nonexistent"), nullptr);
}

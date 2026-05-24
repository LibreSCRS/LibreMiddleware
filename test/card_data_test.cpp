// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <LibreSCRS/Plugin/CardData.h>
#include <LibreSCRS/Plugin/CardDataAccess.h>

#include <stdexcept>
#include <type_traits>
#include <utility>

using namespace LibreSCRS::Plugin;

TEST(CardFieldTest, TextFieldConstruction)
{
    CardField field{"given_name", "Given Name", FieldType::Text, {'J', 'o', 'h', 'n'}};
    EXPECT_EQ(field.key, "given_name");
    EXPECT_EQ(field.label, "Given Name");
    EXPECT_EQ(field.type, FieldType::Text);
    ASSERT_TRUE(field.textValue().has_value());
    EXPECT_EQ(*field.textValue(), "John");
}

TEST(CardFieldTest, PhotoFieldConstruction)
{
    std::vector<uint8_t> jpeg = {0xFF, 0xD8, 0xFF, 0xE0};
    CardField field{"photo", "Photo", FieldType::Photo, jpeg};
    EXPECT_EQ(field.type, FieldType::Photo);
    EXPECT_EQ(field.value, jpeg);
    // Photo/Binary fields must not be reinterpreted as UTF-8 text.
    EXPECT_FALSE(field.textValue().has_value());
}

TEST(CardFieldTest, BinaryFieldRefusesTextInterpretation)
{
    std::vector<uint8_t> bytes = {0x00, 0x01, 0x02, 0x7F, 0xFF};
    CardField field{"raw", "Raw", FieldType::Binary, bytes};
    EXPECT_EQ(field.type, FieldType::Binary);
    EXPECT_FALSE(field.textValue().has_value());
}

TEST(CardFieldTest, DateFieldConstruction)
{
    // textValue() is Text-only. Date fields return
    // nullopt so callers cannot rely on an implicit "dates are strings"
    // assumption that hides plugin-specific encodings (YYMMDD vs. raw BCD).
    // Consumers that need the raw bytes read `field.value` directly and
    // parse with a format-aware helper.
    CardField field{"birth_date", "Date of Birth", FieldType::Date, {'1', '9', '9', '0', '0', '1', '0', '1'}};
    EXPECT_FALSE(field.textValue().has_value());
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
    ASSERT_TRUE(group.fields[0].textValue().has_value());
    EXPECT_EQ(*group.fields[0].textValue(), "Smith");
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

    auto groupIdx = data.findGroup("personal");
    ASSERT_TRUE(groupIdx.has_value());
    EXPECT_EQ(data.groupAt(*groupIdx).groupLabel, "Personal Data");

    EXPECT_FALSE(data.findGroup("nonexistent").has_value());
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

    auto fieldIdx = data.findField("surname");
    ASSERT_TRUE(fieldIdx.has_value());
    ASSERT_TRUE(data.fieldAt(*fieldIdx).textValue().has_value());
    EXPECT_EQ(*data.fieldAt(*fieldIdx).textValue(), "Test");

    EXPECT_FALSE(data.findField("nonexistent").has_value());
}

// Pass-5 A6: addText now eagerly rejects an empty key per API-POLICY §5.1.
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
    ASSERT_TRUE(f.textValue().has_value());
    EXPECT_EQ(*f.textValue(), "Ivan");
}

TEST(CardDataBoundsTest, GroupAtThrowsOnOutOfRange)
{
    CardData data;
    data.groups.push_back(CardFieldGroup{"g0", "G0", {}});
    EXPECT_THROW((void)data.groupAt(1), std::out_of_range);
}

TEST(CardDataBoundsTest, FieldAtThrowsOnOutOfRangeGroup)
{
    CardData data;
    EXPECT_THROW((void)data.fieldAt(0, 0), std::out_of_range);
}

TEST(CardDataBoundsTest, FieldAtThrowsOnOutOfRangeField)
{
    CardData data;
    data.groups.push_back(CardFieldGroup{"g0", "G0", {}});
    EXPECT_THROW((void)data.fieldAt(0, 0), std::out_of_range);
}

TEST(CardDataBoundsTest, FieldAtPairThrowsOnOutOfRange)
{
    CardData data;
    data.groups.push_back(CardFieldGroup{"g0", "G0", {}});
    EXPECT_THROW((void)data.fieldAt(std::pair<std::size_t, std::size_t>{1, 0}), std::out_of_range);
}

TEST(CardDataBoundsTest, GroupAtUncheckedNoexcept)
{
    static_assert(noexcept(std::declval<CardData&>().groupAtUnchecked(0)),
                  "groupAtUnchecked must be noexcept on the hot-path");
    static_assert(noexcept(std::declval<const CardData&>().groupAtUnchecked(0)),
                  "const groupAtUnchecked must be noexcept on the hot-path");
}

TEST(CardDataBoundsTest, FieldAtUncheckedNoexcept)
{
    static_assert(noexcept(std::declval<CardData&>().fieldAtUnchecked(0, 0)),
                  "fieldAtUnchecked must be noexcept on the hot-path");
    static_assert(noexcept(std::declval<const CardData&>().fieldAtUnchecked(0, 0)),
                  "const fieldAtUnchecked must be noexcept on the hot-path");
}

// --- CardDataAccess.h convenience accessors (Wave 6 / 6.2) ---
//
// textValue(data, groupKey, fieldKey) collapses the "findGroup -> groupAt ->
// find field -> textValue" dance LC's carddatautils.h previously did by
// hand. The Qt-free LM helper lets the LC adapter become a thin QString
// wrapper. These tests cover the contract on the LM side.

namespace {
CardData makeSampleData()
{
    CardData data;
    data.cardType = "rs-eid";
    CardFieldGroup personal;
    personal.groupKey = "personal";
    personal.groupLabel = "Personal Data";
    personal.fields.push_back({"surname", "Surname", FieldType::Text, {'D', 'o', 'e'}});
    personal.fields.push_back({"given_name", "Given Name", FieldType::Text, {'J', 'a', 'n', 'e'}});
    personal.fields.push_back({"birth_date", "DOB", FieldType::Date, {'1', '9', '9', '0', '0', '1', '0', '1'}});
    personal.fields.push_back({"empty_text", "Empty", FieldType::Text, {}});
    data.groups.push_back(std::move(personal));
    CardFieldGroup document;
    document.groupKey = "document";
    document.groupLabel = "Document";
    document.fields.push_back({"serial", "Serial", FieldType::Text, {'A', 'B', 'C'}});
    data.groups.push_back(std::move(document));
    return data;
}
} // namespace

TEST(CardDataAccessTest, TextValueNormalCase)
{
    const auto data = makeSampleData();
    auto v = LibreSCRS::Plugin::textValue(data, "personal", "given_name");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "Jane");
}

TEST(CardDataAccessTest, TextValueMissingGroup)
{
    const auto data = makeSampleData();
    EXPECT_FALSE(LibreSCRS::Plugin::textValue(data, "nonexistent_group", "any").has_value());
}

TEST(CardDataAccessTest, TextValueMissingField)
{
    const auto data = makeSampleData();
    EXPECT_FALSE(LibreSCRS::Plugin::textValue(data, "personal", "nonexistent_field").has_value());
}

TEST(CardDataAccessTest, TextValueNonTextFieldReturnsNullopt)
{
    // Date field exists in the personal group; the accessor must NOT
    // reinterpret its bytes as text, matching CardField::textValue() behaviour.
    const auto data = makeSampleData();
    EXPECT_FALSE(LibreSCRS::Plugin::textValue(data, "personal", "birth_date").has_value());
}

TEST(CardDataAccessTest, TextValueEmptyTextFieldYieldsEmptyString)
{
    const auto data = makeSampleData();
    auto v = LibreSCRS::Plugin::textValue(data, "personal", "empty_text");
    ASSERT_TRUE(v.has_value()) << "empty Text value is still a Text value — must produce an engaged optional";
    EXPECT_TRUE(v->empty());
}

TEST(CardDataAccessTest, TextValueFirstMatchWinsOnDuplicateGroupKeys)
{
    // findGroup returns the FIRST match when multiple groups share a key;
    // the convenience accessor inherits that semantic.
    CardData data;
    CardFieldGroup g1;
    g1.groupKey = "personal";
    g1.fields.push_back({"name", "N", FieldType::Text, {'1'}});
    data.groups.push_back(std::move(g1));
    CardFieldGroup g2;
    g2.groupKey = "personal"; // duplicate
    g2.fields.push_back({"name", "N", FieldType::Text, {'2'}});
    data.groups.push_back(std::move(g2));

    auto v = LibreSCRS::Plugin::textValue(data, "personal", "name");
    ASSERT_TRUE(v.has_value());
    EXPECT_EQ(*v, "1") << "first-match semantics must mirror CardData::findGroup";

    // textValueAt with explicit index reaches the second group.
    auto v2 = LibreSCRS::Plugin::textValueAt(data, 1, "name");
    ASSERT_TRUE(v2.has_value());
    EXPECT_EQ(*v2, "2");
}

TEST(CardDataAccessTest, TextValueAtOutOfRangeReturnsNullopt)
{
    const auto data = makeSampleData();
    EXPECT_FALSE(LibreSCRS::Plugin::textValueAt(data, data.groups.size(), "any").has_value());
    EXPECT_FALSE(LibreSCRS::Plugin::textValueAt(data, 99, "any").has_value());
}

TEST(CardDataAccessTest, TextValueAccessorsAreNoexcept)
{
    static_assert(
        noexcept(LibreSCRS::Plugin::textValue(std::declval<const CardData&>(), std::string_view{}, std::string_view{})),
        "textValue must be noexcept per API-POLICY public-boundary rule");
    static_assert(
        noexcept(LibreSCRS::Plugin::textValueAt(std::declval<const CardData&>(), std::size_t{0}, std::string_view{})),
        "textValueAt must be noexcept per API-POLICY public-boundary rule");
    SUCCEED();
}

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <data_group.h>

using namespace emrtd;

TEST(MRZParseTest, TD3Passport)
{
    std::string mrz = "P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n"
                      "L898902C<5UTO7407272F1207146ZE184226B<<<<<10";

    auto parsed = parseMRZ(mrz);
    EXPECT_EQ(parsed.documentCode, "P");
    EXPECT_EQ(parsed.issuingState, "UTO");
    EXPECT_EQ(parsed.surname, "ERIKSSON");
    EXPECT_EQ(parsed.givenNames, "ANNA MARIA");
    EXPECT_EQ(parsed.documentNumber, "L898902C");
    EXPECT_EQ(parsed.nationality, "UTO");
    EXPECT_EQ(parsed.dateOfBirth, "740727");
    EXPECT_EQ(parsed.sex, "F");
    EXPECT_EQ(parsed.dateOfExpiry, "120714");
}

TEST(MRZParseTest, TD1IDCard)
{
    std::string mrz = "I<UTOD231458907<<<<<<<<<<<<<<<\n"
                      "7408122F1204159UTO<<<<<<<<<<<6\n"
                      "ERIKSSON<<ANNA<MARIA<<<<<<<<<<";

    auto parsed = parseMRZ(mrz);
    EXPECT_EQ(parsed.documentCode, "I");
    EXPECT_EQ(parsed.surname, "ERIKSSON");
    EXPECT_EQ(parsed.givenNames, "ANNA MARIA");
    EXPECT_EQ(parsed.documentNumber, "D23145890");
}

TEST(MRZParseTest, NameWithFillers)
{
    std::string mrz = "P<UTOSMITH<<JOHN<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n"
                      "AB12345675UTO8001014M2501017<<<<<<<<<<<<<<04";

    auto parsed = parseMRZ(mrz);
    EXPECT_EQ(parsed.surname, "SMITH");
    EXPECT_EQ(parsed.givenNames, "JOHN");
}

TEST(MRZParseTest, TD2Visa)
{
    // TD2 format: 2 lines x 36 chars
    std::string mrz = "I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<\n"
                      "D231458907UTO7408122F1204159<<<<<<<6";

    auto parsed = parseMRZ(mrz);
    EXPECT_EQ(parsed.documentCode, "I");
    EXPECT_EQ(parsed.issuingState, "UTO");
    EXPECT_EQ(parsed.surname, "ERIKSSON");
    EXPECT_EQ(parsed.givenNames, "ANNA MARIA");
    EXPECT_EQ(parsed.documentNumber, "D23145890");
}

TEST(MRZParseTest, EmptyMRZ)
{
    auto parsed = parseMRZ("");
    EXPECT_TRUE(parsed.documentCode.empty());
}

// =============================================================================
// MRZ date formatting.
//
// ICAO 9303 allows the filler character `<` wherever a component of the date of
// birth is unknown, so these are conformant document contents, not corruption.
// =============================================================================

#include <mrz_date.h>

TEST(MRZDateFormat, FullDateIsReformatted)
{
    EXPECT_EQ(formatMRZDate("740727"), "27.07.1974");
}

TEST(MRZDateFormat, ExpiryUsesTheFutureWindow)
{
    EXPECT_EQ(formatMRZDate("300101", true), "01.01.2030");
}

// The whole read used to come back as a failure for this input: the conversion
// threw, the throw left the plugin, and the portrait and the authenticity
// result that had already been read correctly went with it.
TEST(MRZDateFormat, UnknownYearIsReturnedAsItCameOffTheCard)
{
    EXPECT_EQ(formatMRZDate("<<0101"), "<<0101");
}

TEST(MRZDateFormat, PartiallyUnknownYearIsReturnedAsItCameOffTheCard)
{
    EXPECT_EQ(formatMRZDate("9<0101"), "9<0101");
}

TEST(MRZDateFormat, UnknownMonthAndDayAreReturnedAsTheyCameOffTheCard)
{
    EXPECT_EQ(formatMRZDate("74<<27"), "74<<27");
}

TEST(MRZDateFormat, WrongLengthIsUnchanged)
{
    EXPECT_EQ(formatMRZDate(""), "");
    EXPECT_EQ(formatMRZDate("74072"), "74072");
}

// The conversion accepts a leading minus, so a six-character input with one in
// it produced a formatted date instead of being returned as it came off the
// card. The MRZ character set is A-Z, 0-9 and the filler, so no conformant
// document carries this -- but the bytes come from the chip, and the function's
// contract says six digits or nothing.
TEST(MRZDateFormat, ASignIsNotADigit)
{
    EXPECT_EQ(formatMRZDate("-10101"), "-10101");
    EXPECT_EQ(formatMRZDate("74-127"), "74-127");
    EXPECT_EQ(formatMRZDate("7401-1"), "7401-1");
}

// Whitespace is not a digit either: from_chars skips none, but a plus sign is
// the other thing a numeric conversion tends to take.
TEST(MRZDateFormat, APlusIsNotADigit)
{
    EXPECT_EQ(formatMRZDate("+10101"), "+10101");
}

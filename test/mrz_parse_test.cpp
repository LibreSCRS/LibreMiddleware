// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>
#include <emrtd/data_group.h>

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

// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include <gtest/gtest.h>
#include <eidcard/eidtypes.h>

using namespace eidcard;

TEST(EIdTypesTest, DocumentDataDefaultConstruction) {
    DocumentData doc;
    EXPECT_TRUE(doc.docRegNo.empty());
    EXPECT_TRUE(doc.documentType.empty());
    EXPECT_TRUE(doc.documentSerialNumber.empty());
    EXPECT_TRUE(doc.issuingDate.empty());
    EXPECT_TRUE(doc.expiryDate.empty());
    EXPECT_TRUE(doc.issuingAuthority.empty());
    EXPECT_TRUE(doc.chipSerialNumber.empty());
}

TEST(EIdTypesTest, FixedPersonalDataDefaultConstruction) {
    FixedPersonalData fp;
    EXPECT_TRUE(fp.personalNumber.empty());
    EXPECT_TRUE(fp.surname.empty());
    EXPECT_TRUE(fp.givenName.empty());
    EXPECT_TRUE(fp.parentGivenName.empty());
    EXPECT_TRUE(fp.sex.empty());
    EXPECT_TRUE(fp.placeOfBirth.empty());
    EXPECT_TRUE(fp.dateOfBirth.empty());
    EXPECT_TRUE(fp.nationalityFull.empty());
    EXPECT_TRUE(fp.statusOfForeigner.empty());
}

TEST(EIdTypesTest, VariablePersonalDataDefaultConstruction) {
    VariablePersonalData vp;
    EXPECT_TRUE(vp.state.empty());
    EXPECT_TRUE(vp.community.empty());
    EXPECT_TRUE(vp.place.empty());
    EXPECT_TRUE(vp.street.empty());
    EXPECT_TRUE(vp.houseNumber.empty());
    EXPECT_TRUE(vp.addressDate.empty());
}

TEST(EIdTypesTest, FieldAssignment) {
    FixedPersonalData fp;
    fp.surname = "Petrović";
    fp.givenName = "Marko";
    fp.dateOfBirth = "15.03.1990";
    EXPECT_EQ(fp.surname, "Petrović");
    EXPECT_EQ(fp.givenName, "Marko");
    EXPECT_EQ(fp.dateOfBirth, "15.03.1990");
}

TEST(EIdTypesTest, CardTypeValues) {
    EXPECT_EQ(static_cast<int>(CardType::Unknown), 0);
    EXPECT_EQ(static_cast<int>(CardType::Apollo2008), 1);
    EXPECT_EQ(static_cast<int>(CardType::Gemalto2014), 2);
    EXPECT_EQ(static_cast<int>(CardType::ForeignerIF2020), 3);
}

TEST(EIdTypesTest, PhotoDataIsVector) {
    PhotoData photo = {0xFF, 0xD8, 0xFF, 0xE0};
    ASSERT_EQ(photo.size(), 4u);
    EXPECT_EQ(photo[0], 0xFF);
    EXPECT_EQ(photo[1], 0xD8);
}

TEST(EIdTypesTest, CertificateData) {
    CertificateData cert;
    cert.label = "Auth Certificate";
    cert.derBytes = {0x30, 0x82, 0x01, 0x00};
    EXPECT_EQ(cert.label, "Auth Certificate");
    ASSERT_EQ(cert.derBytes.size(), 4u);
}

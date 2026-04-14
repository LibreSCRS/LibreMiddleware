// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pdf_parser.h"

#include <gtest/gtest.h>
#include <cstdint>
#include <format>
#include <string>
#include <vector>

using namespace libresign;

namespace {

// Build a minimal valid PDF with known structure for testing.
// Objects:
//   1 0 obj — Catalog (/Type /Catalog /Pages 2 0 R)
//   2 0 obj — Pages   (/Type /Pages /Kids [3 0 R] /Count 1)
//   3 0 obj — Page    (/Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]
//                       /Contents 4 0 R /Resources << /Font << >> >> /Rotate 90)
//   4 0 obj — Content stream placeholder
std::vector<uint8_t> buildMinimalPdf()
{
    std::string pdf;

    pdf += "%PDF-1.4\n";

    // Object 1: Catalog
    size_t obj1Off = pdf.size();
    pdf += "1 0 obj\n";
    pdf += "<< /Type /Catalog /Pages 2 0 R >>\n";
    pdf += "endobj\n";

    // Object 2: Pages
    size_t obj2Off = pdf.size();
    pdf += "2 0 obj\n";
    pdf += "<< /Type /Pages /Kids [3 0 R] /Count 1 >>\n";
    pdf += "endobj\n";

    // Object 3: Page with all common attributes
    size_t obj3Off = pdf.size();
    pdf += "3 0 obj\n";
    pdf += "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792]\n";
    pdf += "   /Contents 4 0 R /Resources << /Font << >> >> /Rotate 90 >>\n";
    pdf += "endobj\n";

    // Object 4: Content stream
    size_t obj4Off = pdf.size();
    pdf += "4 0 obj\n";
    pdf += "<< /Length 44 >>\n";
    pdf += "stream\n";
    pdf += "BT /F1 12 Tf 100 700 Td (Hello) Tj ET\n";
    pdf += "endstream\n";
    pdf += "endobj\n";

    // xref table
    size_t xrefOff = pdf.size();
    pdf += "xref\n";
    pdf += "0 5\n";
    pdf += std::format("{:010} 65535 f \n", 0);
    pdf += std::format("{:010} 00000 n \n", obj1Off);
    pdf += std::format("{:010} 00000 n \n", obj2Off);
    pdf += std::format("{:010} 00000 n \n", obj3Off);
    pdf += std::format("{:010} 00000 n \n", obj4Off);

    // trailer
    pdf += "trailer\n";
    pdf += "<< /Size 5 /Root 1 0 R >>\n";
    pdf += "startxref\n";
    pdf += std::to_string(xrefOff) + "\n";
    pdf += "%%EOF\n";

    return {pdf.begin(), pdf.end()};
}

} // namespace

TEST(PdfParserTest, ParseMinimalPdf)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto& trailer = parser.trailer();
    ASSERT_EQ(trailer.type(), PdfValueType::Dict);

    auto root = trailer.get("Root");
    ASSERT_EQ(root.type(), PdfValueType::Ref);
    EXPECT_EQ(root.asRef().objNum, 1);

    auto size = trailer.get("Size");
    ASSERT_EQ(size.type(), PdfValueType::Int);
    EXPECT_EQ(size.asInt(), 5);
}

TEST(PdfParserTest, ReadCatalogObject)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto catalog = parser.readObject(1);
    ASSERT_EQ(catalog.type(), PdfValueType::Dict);

    auto type = catalog.get("Type");
    ASSERT_EQ(type.type(), PdfValueType::Name);
    EXPECT_EQ(type.asName(), "Catalog");

    auto pages = catalog.get("Pages");
    ASSERT_EQ(pages.type(), PdfValueType::Ref);
    EXPECT_EQ(pages.asRef().objNum, 2);
}

TEST(PdfParserTest, ReadPagesObject)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto pages = parser.readObject(2);
    ASSERT_EQ(pages.type(), PdfValueType::Dict);

    auto type = pages.get("Type");
    ASSERT_EQ(type.type(), PdfValueType::Name);
    EXPECT_EQ(type.asName(), "Pages");

    auto kids = pages.get("Kids");
    ASSERT_EQ(kids.type(), PdfValueType::Array);
    EXPECT_EQ(kids.asArray().size(), 1u);

    auto count = pages.get("Count");
    ASSERT_EQ(count.type(), PdfValueType::Int);
    EXPECT_EQ(count.asInt(), 1);
}

TEST(PdfParserTest, ReadPageObject)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto page = parser.readObject(3);
    ASSERT_EQ(page.type(), PdfValueType::Dict);

    auto type = page.get("Type");
    ASSERT_EQ(type.type(), PdfValueType::Name);
    EXPECT_EQ(type.asName(), "Page");

    // /MediaBox
    auto mediaBox = page.get("MediaBox");
    ASSERT_EQ(mediaBox.type(), PdfValueType::Array);
    EXPECT_EQ(mediaBox.asArray().size(), 4u);

    // /Contents
    auto contents = page.get("Contents");
    ASSERT_EQ(contents.type(), PdfValueType::Ref);
    EXPECT_EQ(contents.asRef().objNum, 4);

    // /Resources
    auto resources = page.get("Resources");
    ASSERT_EQ(resources.type(), PdfValueType::Dict);

    // /Rotate
    auto rotate = page.get("Rotate");
    ASSERT_EQ(rotate.type(), PdfValueType::Int);
    EXPECT_EQ(rotate.asInt(), 90);
}

TEST(PdfParserTest, PageObjectByIndex)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto page = parser.pageObject(0);
    ASSERT_EQ(page.type(), PdfValueType::Dict);

    auto type = page.get("Type");
    ASSERT_EQ(type.type(), PdfValueType::Name);
    EXPECT_EQ(type.asName(), "Page");

    // Verify it has the same attributes as direct object read
    auto rotate = page.get("Rotate");
    ASSERT_EQ(rotate.type(), PdfValueType::Int);
    EXPECT_EQ(rotate.asInt(), 90);
}

TEST(PdfParserTest, PageObjectOutOfRange)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    EXPECT_THROW(parser.pageObject(1), std::runtime_error);
    EXPECT_THROW(parser.pageObject(99), std::runtime_error);
}

// pageObjectNumber — returns the indirect object number of the N-th page.
// The minimal PDF built above has a single page whose /Kids entry refers
// to object 4 (the Page dict). Out-of-range must throw.
TEST(PdfParserTest, PageObjectNumberFirst)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    int objNum = parser.pageObjectNumber(0);
    EXPECT_GT(objNum, 0);

    // Verify it resolves to the same page dict as pageObject(0)
    auto pageViaIndex = parser.pageObject(0);
    auto pageViaObjNum = parser.readObject(objNum);
    ASSERT_EQ(pageViaIndex.type(), PdfValueType::Dict);
    ASSERT_EQ(pageViaObjNum.type(), PdfValueType::Dict);
    EXPECT_EQ(pageViaIndex.get("Type").asName(), pageViaObjNum.get("Type").asName());
}

TEST(PdfParserTest, PageObjectNumberOutOfRange)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    EXPECT_THROW(parser.pageObjectNumber(1), std::runtime_error);
    EXPECT_THROW(parser.pageObjectNumber(99), std::runtime_error);
}

TEST(PdfParserTest, SerializeRoundTrip)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto page = parser.readObject(3);
    ASSERT_EQ(page.type(), PdfValueType::Dict);

    // Serialize and re-parse
    std::string serialized = page.serialize();
    EXPECT_FALSE(serialized.empty());

    // The serialized form should contain our known keys
    EXPECT_NE(serialized.find("/Type"), std::string::npos);
    EXPECT_NE(serialized.find("/Page"), std::string::npos);
    EXPECT_NE(serialized.find("/MediaBox"), std::string::npos);
    EXPECT_NE(serialized.find("/Contents"), std::string::npos);
    EXPECT_NE(serialized.find("/Rotate"), std::string::npos);

    // Build a mini PDF with the serialized dict as an object
    std::string roundTrip = "%PDF-1.4\n";
    size_t objOff = roundTrip.size();
    roundTrip += "1 0 obj\n" + serialized + "\nendobj\n";

    size_t xrefOff = roundTrip.size();
    roundTrip += "xref\n0 2\n";
    roundTrip += std::format("{:010} 65535 f \n", 0);
    roundTrip += std::format("{:010} 00000 n \n", objOff);
    roundTrip += "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n";
    roundTrip += std::to_string(xrefOff) + "\n%%EOF\n";

    std::vector<uint8_t> rtData(roundTrip.begin(), roundTrip.end());
    PdfParser parser2(rtData);
    ASSERT_TRUE(parser2.parse());

    auto reparsed = parser2.readObject(1);
    ASSERT_EQ(reparsed.type(), PdfValueType::Dict);

    // Verify same keys present
    EXPECT_EQ(reparsed.get("Type").asName(), "Page");
    EXPECT_EQ(reparsed.get("Rotate").asInt(), 90);
    EXPECT_EQ(reparsed.get("Contents").asRef().objNum, 4);
}

TEST(PdfParserTest, BooleanValues)
{
    // Build a PDF with a boolean value in a dict
    std::string pdf = "%PDF-1.4\n";
    size_t objOff = pdf.size();
    pdf += "1 0 obj\n<< /Flag true /Other false >>\nendobj\n";
    size_t xrefOff = pdf.size();
    pdf += "xref\n0 2\n";
    pdf += std::format("{:010} 65535 f \n", 0);
    pdf += std::format("{:010} 00000 n \n", objOff);
    pdf += "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n";
    pdf += std::to_string(xrefOff) + "\n%%EOF\n";

    std::vector<uint8_t> data(pdf.begin(), pdf.end());
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto obj = parser.readObject(1);
    ASSERT_EQ(obj.type(), PdfValueType::Dict);
    EXPECT_TRUE(obj.get("Flag").asBool());
    EXPECT_FALSE(obj.get("Other").asBool());
}

TEST(PdfParserTest, HexString)
{
    std::string pdf = "%PDF-1.4\n";
    size_t objOff = pdf.size();
    pdf += "1 0 obj\n<< /Data <48656C6C6F> >>\nendobj\n";
    size_t xrefOff = pdf.size();
    pdf += "xref\n0 2\n";
    pdf += std::format("{:010} 65535 f \n", 0);
    pdf += std::format("{:010} 00000 n \n", objOff);
    pdf += "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n";
    pdf += std::to_string(xrefOff) + "\n%%EOF\n";

    std::vector<uint8_t> data(pdf.begin(), pdf.end());
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto obj = parser.readObject(1);
    EXPECT_EQ(obj.get("Data").asString(), "Hello");
}

TEST(PdfParserTest, NestedArray)
{
    std::string pdf = "%PDF-1.4\n";
    size_t objOff = pdf.size();
    pdf += "1 0 obj\n<< /Nested [[1 2] [3 4]] >>\nendobj\n";
    size_t xrefOff = pdf.size();
    pdf += "xref\n0 2\n";
    pdf += std::format("{:010} 65535 f \n", 0);
    pdf += std::format("{:010} 00000 n \n", objOff);
    pdf += "trailer\n<< /Size 2 /Root 1 0 R >>\nstartxref\n";
    pdf += std::to_string(xrefOff) + "\n%%EOF\n";

    std::vector<uint8_t> data(pdf.begin(), pdf.end());
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto obj = parser.readObject(1);
    auto nested = obj.get("Nested");
    ASSERT_EQ(nested.type(), PdfValueType::Array);
    ASSERT_EQ(nested.asArray().size(), 2u);

    auto inner0 = nested.asArray()[0];
    ASSERT_EQ(inner0.type(), PdfValueType::Array);
    ASSERT_EQ(inner0.asArray().size(), 2u);
    EXPECT_EQ(inner0.asArray()[0].asInt(), 1);
    EXPECT_EQ(inner0.asArray()[1].asInt(), 2);
}

TEST(PdfParserTest, NonExistentObject)
{
    auto data = buildMinimalPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto obj = parser.readObject(999);
    EXPECT_EQ(obj.type(), PdfValueType::Null);
}

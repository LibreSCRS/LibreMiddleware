// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pdf_parser.h"

#include <gtest/gtest.h>
#include <cstdint>
#include <cstring>
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

// ---------------------------------------------------------------------------
// Xref stream tests
// ---------------------------------------------------------------------------

namespace {

// Helper: write a big-endian unsigned integer of `width` bytes into buf.
void writeBE(std::vector<uint8_t>& buf, int64_t val, int width)
{
    for (int i = width - 1; i >= 0; --i)
        buf.push_back(static_cast<uint8_t>((val >> (i * 8)) & 0xFF));
}

// Build a minimal PDF using an xref stream (no classic xref table).
// Objects:
//   1 0 obj — Catalog (/Type /Catalog /Pages 2 0 R)
//   2 0 obj — Pages   (/Type /Pages /Kids [3 0 R] /Count 1)
//   3 0 obj — Page    (/Type /Page /Parent 2 0 R /MediaBox [0 0 612 792])
//   4 0 obj — Xref stream
std::vector<uint8_t> buildXrefStreamPdf()
{
    std::string pdf;
    pdf += "%PDF-1.7\n";

    size_t obj1Off = pdf.size();
    pdf += "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

    size_t obj2Off = pdf.size();
    pdf += "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";

    size_t obj3Off = pdf.size();
    pdf += "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n";

    size_t obj4Off = pdf.size();

    // Build uncompressed xref stream data.
    // W = [1 3 1]: 1 byte type, 3 bytes offset, 1 byte gen/index
    // Entries for objects 0-4 (5 entries):
    //   0: type=0 (free), offset=0, gen=255
    //   1: type=1 (uncompressed), offset=obj1Off, gen=0
    //   2: type=1, offset=obj2Off, gen=0
    //   3: type=1, offset=obj3Off, gen=0
    //   4: type=1, offset=obj4Off, gen=0
    std::vector<uint8_t> streamData;
    // obj 0: free
    writeBE(streamData, 0, 1);
    writeBE(streamData, 0, 3);
    writeBE(streamData, 255, 1);
    // obj 1
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj1Off), 3);
    writeBE(streamData, 0, 1);
    // obj 2
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj2Off), 3);
    writeBE(streamData, 0, 1);
    // obj 3
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj3Off), 3);
    writeBE(streamData, 0, 1);
    // obj 4 (xref stream itself)
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj4Off), 3);
    writeBE(streamData, 0, 1);

    // Build the xref stream object (uncompressed — no /Filter)
    std::string xrefObj;
    xrefObj += "4 0 obj\n";
    xrefObj += "<< /Type /XRef /Size 5 /W [1 3 1] /Root 1 0 R";
    xrefObj += " /Length " + std::to_string(streamData.size());
    xrefObj += " >>\nstream\n";

    pdf += xrefObj;
    // Append binary stream data
    std::vector<uint8_t> result(pdf.begin(), pdf.end());
    result.insert(result.end(), streamData.begin(), streamData.end());

    std::string tail = "\nendstream\nendobj\n";
    tail += "startxref\n";
    tail += std::to_string(obj4Off) + "\n";
    tail += "%%EOF\n";
    result.insert(result.end(), tail.begin(), tail.end());

    return result;
}

// Build a PDF with xref stream containing a type-2 (compressed) entry.
// Object 5 is stored compressed in object stream 10.
std::vector<uint8_t> buildXrefStreamWithCompressedEntry()
{
    std::string pdf;
    pdf += "%PDF-1.7\n";

    size_t obj1Off = pdf.size();
    pdf += "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

    size_t obj2Off = pdf.size();
    pdf += "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n";

    size_t obj3Off = pdf.size();
    pdf += "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n";

    size_t obj4Off = pdf.size();

    // W = [1 2 1]: 1 byte type, 2 bytes field2, 1 byte field3
    // 5 entries (0-4) + 1 compressed entry (obj 5, compressed in stream obj 10, index 2)
    std::vector<uint8_t> streamData;
    // obj 0: free
    writeBE(streamData, 0, 1);
    writeBE(streamData, 0, 2);
    writeBE(streamData, 0, 1);
    // obj 1
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj1Off), 2);
    writeBE(streamData, 0, 1);
    // obj 2
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj2Off), 2);
    writeBE(streamData, 0, 1);
    // obj 3
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj3Off), 2);
    writeBE(streamData, 0, 1);
    // obj 4 (xref stream itself)
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj4Off), 2);
    writeBE(streamData, 0, 1);
    // obj 5: type=2, compressed in obj 10, index 2
    writeBE(streamData, 2, 1);
    writeBE(streamData, 10, 2);
    writeBE(streamData, 2, 1);

    std::string xrefObj;
    xrefObj += "4 0 obj\n";
    xrefObj += "<< /Type /XRef /Size 6 /W [1 2 1] /Root 1 0 R";
    xrefObj += " /Length " + std::to_string(streamData.size());
    xrefObj += " >>\nstream\n";

    pdf += xrefObj;
    std::vector<uint8_t> result(pdf.begin(), pdf.end());
    result.insert(result.end(), streamData.begin(), streamData.end());

    std::string tail = "\nendstream\nendobj\n";
    tail += "startxref\n";
    tail += std::to_string(obj4Off) + "\n";
    tail += "%%EOF\n";
    result.insert(result.end(), tail.begin(), tail.end());

    return result;
}

} // namespace

TEST(PdfParserTest, XrefStreamBasic)
{
    auto data = buildXrefStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Trailer should be the xref stream dict
    auto& trailer = parser.trailer();
    ASSERT_EQ(trailer.type(), PdfValueType::Dict);

    auto root = trailer.get("Root");
    ASSERT_EQ(root.type(), PdfValueType::Ref);
    EXPECT_EQ(root.asRef().objNum, 1);

    auto size = trailer.get("Size");
    ASSERT_EQ(size.type(), PdfValueType::Int);
    EXPECT_EQ(size.asInt(), 5);
}

TEST(PdfParserTest, XrefStreamReadObjects)
{
    auto data = buildXrefStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Read catalog
    auto catalog = parser.readObject(1);
    ASSERT_EQ(catalog.type(), PdfValueType::Dict);
    EXPECT_EQ(catalog.get("Type").asName(), "Catalog");

    // Read pages
    auto pages = parser.readObject(2);
    ASSERT_EQ(pages.type(), PdfValueType::Dict);
    EXPECT_EQ(pages.get("Type").asName(), "Pages");
    EXPECT_EQ(pages.get("Count").asInt(), 1);

    // Read page
    auto page = parser.readObject(3);
    ASSERT_EQ(page.type(), PdfValueType::Dict);
    EXPECT_EQ(page.get("Type").asName(), "Page");
}

TEST(PdfParserTest, XrefStreamPageTraversal)
{
    auto data = buildXrefStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    auto page = parser.pageObject(0);
    ASSERT_EQ(page.type(), PdfValueType::Dict);
    EXPECT_EQ(page.get("Type").asName(), "Page");

    EXPECT_THROW(parser.pageObject(1), std::runtime_error);
}

TEST(PdfParserTest, XrefStreamCompressedEntries)
{
    auto data = buildXrefStreamWithCompressedEntry();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Uncompressed objects should still be readable
    auto catalog = parser.readObject(1);
    ASSERT_EQ(catalog.type(), PdfValueType::Dict);
    EXPECT_EQ(catalog.get("Type").asName(), "Catalog");

    // Object 5 is compressed but its stream object (10) doesn't exist in this PDF,
    // so readObject should throw when trying to resolve it
    EXPECT_THROW(parser.readObject(5), std::runtime_error);

    // But it should be in compressedObjects
    auto& compressed = parser.compressedObjectRefs();
    ASSERT_TRUE(compressed.count(5));
    EXPECT_EQ(compressed.at(5).streamObjNum, 10);
    EXPECT_EQ(compressed.at(5).indexInStream, 2);
}

TEST(PdfParserTest, XrefStreamWithIndexArray)
{
    // Build a PDF with an /Index array that specifies non-contiguous subsections
    std::string pdf;
    pdf += "%PDF-1.7\n";

    size_t obj10Off = pdf.size();
    pdf += "10 0 obj\n<< /Type /Catalog /Pages 20 0 R >>\nendobj\n";

    size_t obj20Off = pdf.size();
    pdf += "20 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n";

    size_t obj30Off = pdf.size();

    // W = [1 2 0]: 1 byte type, 2 bytes offset, 0 bytes field3
    // Index = [10 2 20 2]: objects 10,11 then 20,21
    // But obj 11 and 21 are free
    std::vector<uint8_t> streamData;
    // obj 10: type=1, offset=obj10Off
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj10Off), 2);
    // obj 11: type=0, free
    writeBE(streamData, 0, 1);
    writeBE(streamData, 0, 2);
    // obj 20: type=1, offset=obj20Off
    writeBE(streamData, 1, 1);
    writeBE(streamData, static_cast<int64_t>(obj20Off), 2);
    // obj 21: type=0, free
    writeBE(streamData, 0, 1);
    writeBE(streamData, 0, 2);

    std::string xrefObj;
    xrefObj += "30 0 obj\n";
    xrefObj += "<< /Type /XRef /Size 22 /W [1 2 0]";
    xrefObj += " /Index [10 2 20 2]";
    xrefObj += " /Root 10 0 R";
    xrefObj += " /Length " + std::to_string(streamData.size());
    xrefObj += " >>\nstream\n";

    pdf += xrefObj;
    std::vector<uint8_t> result(pdf.begin(), pdf.end());
    result.insert(result.end(), streamData.begin(), streamData.end());

    std::string tail = "\nendstream\nendobj\n";
    tail += "startxref\n";
    tail += std::to_string(obj30Off) + "\n";
    tail += "%%EOF\n";
    result.insert(result.end(), tail.begin(), tail.end());

    PdfParser parser(result);
    ASSERT_TRUE(parser.parse());

    // Objects 10 and 20 should be readable
    auto cat = parser.readObject(10);
    ASSERT_EQ(cat.type(), PdfValueType::Dict);
    EXPECT_EQ(cat.get("Type").asName(), "Catalog");

    auto pages = parser.readObject(20);
    ASSERT_EQ(pages.type(), PdfValueType::Dict);
    EXPECT_EQ(pages.get("Type").asName(), "Pages");

    // Objects 11 and 21 are free — should not be found
    EXPECT_EQ(parser.readObject(11).type(), PdfValueType::Null);
    EXPECT_EQ(parser.readObject(21).type(), PdfValueType::Null);

    // Non-existent object
    EXPECT_EQ(parser.readObject(1).type(), PdfValueType::Null);
}

TEST(PdfParserTest, XrefStreamDefaultTypeWhenW0IsZero)
{
    // When W[0] == 0, the default type is 1 (uncompressed)
    std::string pdf;
    pdf += "%PDF-1.7\n";

    size_t obj1Off = pdf.size();
    pdf += "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

    size_t obj2Off = pdf.size();
    pdf += "2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n";

    size_t obj3Off = pdf.size();

    // W = [0 2 0]: no type field (default=1), 2 bytes offset, no gen
    std::vector<uint8_t> streamData;
    // obj 0: offset=0 (free, but type defaults to 1 — this is by spec,
    // producers that use W[0]=0 don't include free entries)
    writeBE(streamData, 0, 2);
    // obj 1: offset=obj1Off
    writeBE(streamData, static_cast<int64_t>(obj1Off), 2);
    // obj 2: offset=obj2Off
    writeBE(streamData, static_cast<int64_t>(obj2Off), 2);
    // obj 3: offset=obj3Off (xref stream)
    writeBE(streamData, static_cast<int64_t>(obj3Off), 2);

    std::string xrefObj;
    xrefObj += "3 0 obj\n";
    xrefObj += "<< /Type /XRef /Size 4 /W [0 2 0] /Root 1 0 R";
    xrefObj += " /Length " + std::to_string(streamData.size());
    xrefObj += " >>\nstream\n";

    pdf += xrefObj;
    std::vector<uint8_t> result(pdf.begin(), pdf.end());
    result.insert(result.end(), streamData.begin(), streamData.end());

    std::string tail = "\nendstream\nendobj\n";
    tail += "startxref\n";
    tail += std::to_string(obj3Off) + "\n";
    tail += "%%EOF\n";
    result.insert(result.end(), tail.begin(), tail.end());

    PdfParser parser(result);
    ASSERT_TRUE(parser.parse());

    auto cat = parser.readObject(1);
    ASSERT_EQ(cat.type(), PdfValueType::Dict);
    EXPECT_EQ(cat.get("Type").asName(), "Catalog");
}

// ---------------------------------------------------------------------------
// Object stream tests (type-2 xref entry resolution)
// ---------------------------------------------------------------------------

namespace {

// Build a PDF where some objects live inside an object stream (ObjStm).
// Layout:
//   1 0 obj — Catalog (/Type /Catalog /Pages 2 0 R)  [uncompressed]
//   2 0 obj — Pages   (/Type /Pages /Kids [5 0 R] /Count 1)  [uncompressed]
//   3 0 obj — Object stream containing objects 5 and 6:
//       5 = Page dict (/Type /Page /Parent 2 0 R /MediaBox [0 0 595 842])
//       6 = Font dict (/Type /Font /Subtype /Type1 /BaseFont /Helvetica)
//   4 0 obj — Xref stream
std::vector<uint8_t> buildObjStreamPdf()
{
    std::string pdf;
    pdf += "%PDF-1.7\n";

    // Object 1: Catalog (uncompressed)
    size_t obj1Off = pdf.size();
    pdf += "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n";

    // Object 2: Pages (uncompressed)
    size_t obj2Off = pdf.size();
    pdf += "2 0 obj\n<< /Type /Pages /Kids [5 0 R] /Count 1 >>\nendobj\n";

    // Object 3: Object stream containing objects 5 and 6
    // Object stream format: header is "objNum1 offset1 objNum2 offset2 ..."
    // followed by the actual object values starting at /First offset.
    //
    // Object 5 value: << /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>
    // Object 6 value: << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
    std::string obj5Data = "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] >>";
    std::string obj6Data = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>";

    // Header: "5 0 6 <offset of obj6>"
    // obj5 starts at offset 0 relative to /First
    // obj6 starts at offset obj5Data.size() + 1 (space separator) relative to /First
    size_t obj6Offset = obj5Data.size() + 1; // +1 for space between objects
    std::string header = "5 0 6 " + std::to_string(obj6Offset);
    size_t firstOffset = header.size() + 1; // +1 for space after header

    std::string objStreamContent = header + " " + obj5Data + " " + obj6Data;

    size_t obj3Off = pdf.size();
    std::string obj3Dict;
    obj3Dict += "3 0 obj\n";
    obj3Dict += "<< /Type /ObjStm /N 2 /First " + std::to_string(firstOffset);
    obj3Dict += " /Length " + std::to_string(objStreamContent.size());
    obj3Dict += " >>\nstream\n";

    pdf += obj3Dict;
    pdf += objStreamContent;
    pdf += "\nendstream\nendobj\n";

    // Object 4: Xref stream
    size_t obj4Off = pdf.size();

    // W = [1 2 1]: type(1), field2(2), field3(1)
    // Entries: 0(free), 1(uncomp), 2(uncomp), 3(uncomp), 4(uncomp), 5(compressed in 3, idx 0), 6(compressed in 3, idx 1)
    std::vector<uint8_t> xrefData;
    // obj 0: free
    writeBE(xrefData, 0, 1); writeBE(xrefData, 0, 2); writeBE(xrefData, 0, 1);
    // obj 1: uncompressed
    writeBE(xrefData, 1, 1); writeBE(xrefData, static_cast<int64_t>(obj1Off), 2); writeBE(xrefData, 0, 1);
    // obj 2: uncompressed
    writeBE(xrefData, 1, 1); writeBE(xrefData, static_cast<int64_t>(obj2Off), 2); writeBE(xrefData, 0, 1);
    // obj 3: uncompressed (the object stream itself)
    writeBE(xrefData, 1, 1); writeBE(xrefData, static_cast<int64_t>(obj3Off), 2); writeBE(xrefData, 0, 1);
    // obj 4: uncompressed (xref stream)
    writeBE(xrefData, 1, 1); writeBE(xrefData, static_cast<int64_t>(obj4Off), 2); writeBE(xrefData, 0, 1);
    // obj 5: compressed in stream obj 3, index 0
    writeBE(xrefData, 2, 1); writeBE(xrefData, 3, 2); writeBE(xrefData, 0, 1);
    // obj 6: compressed in stream obj 3, index 1
    writeBE(xrefData, 2, 1); writeBE(xrefData, 3, 2); writeBE(xrefData, 1, 1);

    std::string xrefObj;
    xrefObj += "4 0 obj\n";
    xrefObj += "<< /Type /XRef /Size 7 /W [1 2 1] /Root 1 0 R";
    xrefObj += " /Length " + std::to_string(xrefData.size());
    xrefObj += " >>\nstream\n";

    pdf += xrefObj;
    std::vector<uint8_t> result(pdf.begin(), pdf.end());
    result.insert(result.end(), xrefData.begin(), xrefData.end());

    std::string tail = "\nendstream\nendobj\n";
    tail += "startxref\n";
    tail += std::to_string(obj4Off) + "\n";
    tail += "%%EOF\n";
    result.insert(result.end(), tail.begin(), tail.end());

    return result;
}

} // namespace

TEST(PdfParserTest, ObjStreamReadCompressedObject)
{
    auto data = buildObjStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Object 5 is compressed in object stream 3 — should be readable
    auto page = parser.readObject(5);
    ASSERT_EQ(page.type(), PdfValueType::Dict);
    EXPECT_EQ(page.get("Type").asName(), "Page");

    auto mediaBox = page.get("MediaBox");
    ASSERT_EQ(mediaBox.type(), PdfValueType::Array);
    EXPECT_EQ(mediaBox.asArray().size(), 4u);

    auto parent = page.get("Parent");
    ASSERT_EQ(parent.type(), PdfValueType::Ref);
    EXPECT_EQ(parent.asRef().objNum, 2);
}

TEST(PdfParserTest, ObjStreamReadSecondCompressedObject)
{
    auto data = buildObjStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Object 6 is the second object in the stream (index 1)
    auto font = parser.readObject(6);
    ASSERT_EQ(font.type(), PdfValueType::Dict);
    EXPECT_EQ(font.get("Type").asName(), "Font");
    EXPECT_EQ(font.get("Subtype").asName(), "Type1");
    EXPECT_EQ(font.get("BaseFont").asName(), "Helvetica");
}

TEST(PdfParserTest, ObjStreamPageTreeTraversal)
{
    auto data = buildObjStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Page 0 is object 5, stored in an object stream — page tree traversal must resolve it
    auto page = parser.pageObject(0);
    ASSERT_EQ(page.type(), PdfValueType::Dict);
    EXPECT_EQ(page.get("Type").asName(), "Page");

    auto mediaBox = page.get("MediaBox");
    ASSERT_EQ(mediaBox.type(), PdfValueType::Array);
    EXPECT_EQ(mediaBox.asArray().size(), 4u);
}

TEST(PdfParserTest, ObjStreamUncompressedStillWork)
{
    auto data = buildObjStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Uncompressed objects 1 and 2 should still work fine
    auto catalog = parser.readObject(1);
    ASSERT_EQ(catalog.type(), PdfValueType::Dict);
    EXPECT_EQ(catalog.get("Type").asName(), "Catalog");

    auto pages = parser.readObject(2);
    ASSERT_EQ(pages.type(), PdfValueType::Dict);
    EXPECT_EQ(pages.get("Type").asName(), "Pages");
    EXPECT_EQ(pages.get("Count").asInt(), 1);
}

TEST(PdfParserTest, ObjStreamCaching)
{
    auto data = buildObjStreamPdf();
    PdfParser parser(data);
    ASSERT_TRUE(parser.parse());

    // Read both objects from the same stream — second read should use cache
    auto obj5 = parser.readObject(5);
    ASSERT_EQ(obj5.type(), PdfValueType::Dict);

    auto obj6 = parser.readObject(6);
    ASSERT_EQ(obj6.type(), PdfValueType::Dict);

    // Both should have correct values (verifies cache doesn't corrupt)
    EXPECT_EQ(obj5.get("Type").asName(), "Page");
    EXPECT_EQ(obj6.get("Type").asName(), "Font");
}

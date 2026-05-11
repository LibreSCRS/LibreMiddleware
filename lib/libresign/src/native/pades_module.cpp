// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/pades_module.h"
#include "native/cades_module.h"
#include "native/pkcs11_token.h"
#include "native/revocation_client.h"
#include "native_utils.h"

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <algorithm>
#include <ranges>
#include <array>
#include <cstring>
#include <format>
#include <memory>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string_view>
#include <unordered_set>

#include "pdf_parser.h"
#include "pdf_font.h"
#include "ttf_subset.h"
#include "liberation_sans_data.h"

#include <LibreSCRS/Signing/VisualSignatureLayout.h>

namespace libresign {

namespace {

using namespace libresign::native_utils;

// PDF resource tag for the embedded Liberation Sans Type0 font in the
// visual signature appearance. /F1 follows PDF convention and is what
// the appearance content stream's `/F1 N Tf` operator references; the
// XObject Resources dict binds it to the Type0 font object.
//
// Typed as std::string_view for clean interop with std::format / stream
// output without C-string truncation hazards.
constexpr std::string_view kAppearanceFontTag = "F1";

// Signature widget annotation flags per PDF 32000-1:2008 §12.5.3 Table 165:
//   bit 3 (4)   = Print     — annotation should print with the page
//   bit 8 (128) = Locked    — annotation cannot be deleted/modified by UI
// Combined: 4 + 128 = 132. Standard for digital signature widgets.
constexpr int kSigFieldAnnotFlags = 132;

// PDF text rendering parameters for the visual signature appearance
// come from the public layout API
// (LibreSCRS::Signing::layoutVisualSignature). The algorithm picks
// font size / leading / left margin per signing call, with the
// floor / ceiling / margin / leading sentinels exposed as public
// `kAppearance*` constants in <LibreSCRS/Signing/VisualSignatureLayout.h>.

// ---- Hex encoding ----
//
// kHexChars lives in native_utils.h (libresign::native_utils::kHexChars) so
// the same nibble-to-ASCII table is shared across PAdES / XAdES / any
// future internal hex emitter without duplicating the 16-byte literal.

std::string hexEncode(const std::vector<uint8_t>& data)
{
    using libresign::native_utils::kHexChars;
    std::string result;
    result.reserve(data.size() * 2);
    for (uint8_t b : data) {
        result.push_back(kHexChars[(b >> 4) & 0x0F]);
        result.push_back(kHexChars[b & 0x0F]);
    }
    return result;
}

// ---- PDF date formatting (ISO 32000-2 sec. 7.9.4) ----

std::string pdfDate()
{
    auto t = utcNow();
    return std::format("D:{:04}{:02}{:02}{:02}{:02}{:02}+00'00'", t.year, t.month, t.day, t.hour, t.min, t.sec);
}

// Write a number as a zero-padded 10-digit xref offset string.
std::string xrefOffset(size_t offset)
{
    return std::format("{:010}", offset);
}

// Size of the /Contents hex placeholder.
//
// Indexed by SignatureLevel enumerator value so a future enumerator addition
// triggers a compile error at the static_assert below — preferable to the
// pre-4.0 switch + silent 2 MB default which had no signal-out for "I added
// a new level and forgot to size its Contents block".
//
// Sizing rationale:
//   - B-B / B-T: signing certificate + CMS structure ≈ 8 KB; the 32 KB / 64
//     KB allotments give ~4× headroom.
//   - B-LT: full chain + LTV revocation material (CRL fragments, OCSP
//     responses) up to ~1.5 MB observed for some SR-issuing CAs; 2 MB
//     covers them with margin.
//   - B-LTA: archive timestamp adds another nested structure; 4 MB matches
//     observed worst case + DSS dictionary growth.
inline constexpr std::array<size_t, 4> kContentsAllocByLevel = {{
    32768,   // B_B   —  32 KB
    65536,   // B_T   —  64 KB
    2097152, // B_LT  —   2 MB
    4194304, // B_LTA —   4 MB
}};
static_assert(static_cast<size_t>(libresign::SignatureLevel::B_LTA) + 1 == kContentsAllocByLevel.size(),
              "kContentsAllocByLevel must be sized to match libresign::SignatureLevel — "
              "add an entry above when SignatureLevel grows.");

size_t contentsAllocForLevel(libresign::SignatureLevel level)
{
    return kContentsAllocByLevel[static_cast<size_t>(level)];
}
// These are set per-invocation, not constexpr
// (see contentsAllocForLevel above)

// ByteRange placeholder: 4 numbers each padded to allow in-place overwrite.
// Format: [0 XXXXXXXXXX XXXXXXXXXX XXXXXXXXXX]
// Each placeholder is 10 chars wide + spaces.
constexpr size_t kByteRangePlaceholderWidth = 10;

// Decode one UTF-8 codepoint starting at @p i in @p line. Returns the
// codepoint and the number of bytes consumed. Invalid sequences yield
// U+FFFD with 1 byte consumed; truncated trailing sequences consume to
// end-of-string with U+FFFD.
std::pair<char32_t, size_t> decodeUtf8At(std::string_view line, size_t i)
{
    if (i >= line.size())
        return {0, 0};
    unsigned char c = static_cast<unsigned char>(line[i]);
    char32_t cp = 0;
    size_t n = 1;
    if ((c & 0x80) == 0x00) {
        cp = c;
        n = 1;
    } else if ((c & 0xE0) == 0xC0) {
        cp = c & 0x1F;
        n = 2;
    } else if ((c & 0xF0) == 0xE0) {
        cp = c & 0x0F;
        n = 3;
    } else if ((c & 0xF8) == 0xF0) {
        cp = c & 0x07;
        n = 4;
    } else {
        return {0xFFFD, 1};
    }
    if (i + n > line.size())
        return {0xFFFD, line.size() - i};
    for (size_t k = 1; k < n; ++k)
        cp = (cp << 6) | (static_cast<unsigned char>(line[i + k]) & 0x3F);
    return {cp, n};
}

} // namespace

// ---- createAppearanceStream ----

AppearanceData PAdESModule::createAppearanceStream(const VisualSignatureParams& visual) const
{
    // 1. Compute the auto-fit layout via the public LM layout API.
    //    Single source of truth — LC preview consumes the same function.
    LibreSCRS::Signing::Rect box{0, 0, static_cast<int>(visual.width), static_cast<int>(visual.height)};
    auto layout = LibreSCRS::Signing::layoutVisualSignature(visual.text, box);

    // 2. Collect used codepoints across all wrapped lines via UTF-8 decode.
    //    The wrapped lines may differ from the input (trailing whitespace
    //    trimmed, paragraphs split, etc.), so codepoint collection runs
    //    on the layout output rather than the raw input.
    std::unordered_set<char32_t> codepoints;
    for (const auto& line : layout.lines) {
        for (size_t i = 0; i < line.size();) {
            auto [cp, n] = decodeUtf8At(line, i);
            if (n == 0)
                break;
            codepoints.insert(cp);
            i += n;
        }
    }

    // 3. Subset the bundled font for exactly these codepoints.
    std::span<const uint8_t> fullTtf{LiberationSansRegular, LiberationSansRegularSize};
    TtfSubset subset = subsetTtf(fullTtf, codepoints);

    // 4. Emit the content stream:
    //      q                                 push graphics state
    //      [<x0 y0 w h> re W n]              optional clipping path when
    //                                        layout.clipped == true
    //      BT                                begin text
    //      /<font> <fontSize> Tf             pick the auto-fit font size
    //      <lineHeight> TL                   set leading (Tj-aware T*)
    //      1 0 0 1 <mx> <topY> Tm            position first baseline
    //      <hex> Tj                          draw line[0]
    //      T*  <hex> Tj                      draw line[i] (i >= 1)
    //      ET                                end text
    //      Q                                 restore state
    const float fontSize = layout.fontSize;
    const float lineHeight = layout.lineHeight;
    const float margin = LibreSCRS::Signing::kAppearanceTextMargin;
    const float topBaselineY = static_cast<float>(visual.height) - margin - fontSize;

    std::ostringstream cs;
    cs << "q\n";
    if (layout.clipped) {
        // Clip to the entire annotation rect (origin 0,0 since the
        // appearance form XObject's BBox is [0 0 w h]).
        cs << std::format("0 0 {} {} re W n\n", visual.width, visual.height);
    }
    cs << "BT\n";
    cs << std::format("/{} {:.2f} Tf\n", kAppearanceFontTag, fontSize);
    cs << std::format("{:.2f} TL\n", lineHeight);
    cs << std::format("1 0 0 1 {:.2f} {:.2f} Tm\n", margin, topBaselineY);

    bool firstLine = true;
    for (const auto& line : layout.lines) {
        if (!firstLine)
            cs << "T*\n";
        firstLine = false;
        cs << "<";
        for (size_t i = 0; i < line.size();) {
            auto [cp, n] = decodeUtf8At(line, i);
            if (n == 0)
                break;
            auto it = subset.gidForCodepoint.find(cp);
            NewGid gid = (it == subset.gidForCodepoint.end()) ? NewGid{0} : it->second;
            cs << std::format("{:04X}", gid.raw());
            i += n;
        }
        cs << "> Tj\n";
    }
    cs << "ET\nQ\n";

    auto content = cs.str();
    return AppearanceData{
        .contentStream = std::vector<uint8_t>(content.begin(), content.end()),
        .subset = std::move(subset),
    };
}

// ---- preparePdf ----

PAdESModule::PreparedPdf PAdESModule::preparePdf(const std::vector<uint8_t>& pdfData,
                                                 const VisualSignatureParams& visual, size_t contentsAllocBytes)
{
    // 1. Parse PDF structure using PdfParser
    PdfParser parser(pdfData);
    if (!parser.parse())
        throw std::runtime_error("PAdES: failed to parse input PDF");

    // Use the xref offset that parse() actually resolved (may differ from the
    // stored startxref value when the Adobe-compatible fallback scan kicked
    // in — we must point /Prev at the real table, not the stale value).
    size_t oldStartXref = parser.resolvedXrefOffset();
    size_t nextObjNum = static_cast<size_t>(parser.trailer().get("Size").asInt());

    auto rootRefVal = parser.trailer().get("Root").asRef();
    auto catalog = parser.readObject(rootRefVal.objNum);
    auto pagesRefVal = catalog.get("Pages").asRef();
    std::string pagesRef = std::format("{} {} R", pagesRefVal.objNum, pagesRefVal.genNum);

    // Resolve page index (visual.page: 1-based, -1=last)
    int pageIndex;
    if (visual.page <= 0) {
        auto pagesObj = parser.readObject(pagesRefVal.objNum);
        int count = static_cast<int>(pagesObj.get("Count").asInt());
        pageIndex = count - 1;
    } else {
        pageIndex = visual.page - 1;
    }
    int origPageObjNum = parser.pageObjectNumber(pageIndex);
    std::string pageRef = std::format("{} 0 R", origPageObjNum);

    // 2. Allocate object numbers
    //    New objects: sigDict, sigField, catalog, [appearance + 6 font objects]
    //    The page object reuses the original page's object number (incremental update).
    size_t sigDictObj = nextObjNum;
    size_t sigFieldObj = nextObjNum + 1;
    size_t catalogObj = nextObjNum + 2;
    size_t appearanceObj = nextObjNum + 3;
    // Six font objects, emitted by emitPdfFontObjects:
    //   Type0, CIDFontType2, FontDescriptor, ToUnicode CMap, FontFile2, CIDSet
    size_t type0Obj = nextObjNum + 4;
    size_t cidFontObj = nextObjNum + 5;
    size_t fontDescriptorObj = nextObjNum + 6;
    size_t toUnicodeObj = nextObjNum + 7;
    size_t fontFile2Obj = nextObjNum + 8;
    size_t cidSetObj = nextObjNum + 9;

    bool hasVisual = visual.enabled;
    size_t numNewObjs = hasVisual ? 10 : 3;

    // 3. Build the incremental update
    std::ostringstream incr;
    incr << "\n"; // separator from original PDF

    // Track byte offsets of each new object (relative to start of incr string).
    // We'll add the base offset (pdfData.size()) later.
    std::vector<std::pair<size_t, size_t>> objOffsets; // (objNum, offset_in_incr)

    // -- Signature dictionary --
    objOffsets.push_back({sigDictObj, 0}); // will fix up

    std::string dateStr = pdfDate();

    // We write the sig dict with placeholders for ByteRange.
    // The /Contents hex string placeholder is filled with zeros.
    std::ostringstream sigDict;
    sigDict << sigDictObj << " 0 obj\n";
    sigDict << "<< /Type /Sig\n";
    sigDict << "   /Filter /Adobe.PPKLite\n";
    sigDict << "   /SubFilter /ETSI.CAdES.detached\n";
    // ByteRange placeholder: [0 <10chars> <10chars> <10chars>]
    // We pad with spaces so we can overwrite in-place later.
    sigDict << "   /ByteRange [0 ";
    sigDict << std::string(kByteRangePlaceholderWidth, ' ') << " ";
    sigDict << std::string(kByteRangePlaceholderWidth, ' ') << " ";
    sigDict << std::string(kByteRangePlaceholderWidth, ' ') << "]\n";
    sigDict << "   /Contents <";
    sigDict << std::string((contentsAllocBytes * 2), '0');
    sigDict << ">\n";
    sigDict << "   /M (" << dateStr << ")\n";
    // F21: escapeStringForPdf returns a complete PDF string token (either
    // "(escaped)" for ASCII or "<FEFFhex>" for input containing any
    // non-ASCII byte). Do not wrap with literal "(...)" — that would
    // double-wrap the parenthesised form and corrupt the hex form.
    if (!visual.reason.empty())
        sigDict << "   /Reason " << PdfParser::escapeStringForPdf(visual.reason) << "\n";
    if (!visual.location.empty())
        sigDict << "   /Location " << PdfParser::escapeStringForPdf(visual.location) << "\n";
    if (!visual.contactInfo.empty())
        sigDict << "   /ContactInfo " << PdfParser::escapeStringForPdf(visual.contactInfo) << "\n";
    sigDict << ">>\nendobj\n";

    objOffsets.back().second = incr.str().size();
    incr << sigDict.str();

    // -- Signature field / widget annotation --
    size_t sigFieldStart = incr.str().size();
    objOffsets.push_back({sigFieldObj, sigFieldStart});

    std::ostringstream sigField;
    sigField << sigFieldObj << " 0 obj\n";
    sigField << "<< /Type /Annot\n";
    sigField << "   /Subtype /Widget\n";
    sigField << "   /FT /Sig\n";
    sigField << "   /T (LibreSCRS_Sig)\n";
    sigField << "   /V " << sigDictObj << " 0 R\n";

    if (hasVisual) {
        sigField << "   /Rect [" << visual.x << " " << visual.y << " " << (visual.x + visual.width) << " "
                 << (visual.y + visual.height) << "]\n";
        sigField << "   /AP << /N " << appearanceObj << " 0 R >>\n";
    } else {
        sigField << "   /Rect [0 0 0 0]\n";
    }

    sigField << "   /P " << pageRef << "\n";
    sigField << "   /F " << kSigFieldAnnotFlags << "\n";
    sigField << ">>\nendobj\n";

    incr << sigField.str();

    // -- Appearance XObject (if visual) --
    if (hasVisual) {
        objOffsets.push_back({appearanceObj, incr.str().size()});

        auto appearance = createAppearanceStream(visual);
        std::ostringstream apObj;
        apObj << appearanceObj << " 0 obj\n";
        apObj << "<< /Type /XObject\n";
        apObj << "   /Subtype /Form\n";
        apObj << "   /BBox [0 0 " << visual.width << " " << visual.height << "]\n";
        apObj << "   /Resources << /Font << /" << kAppearanceFontTag << " " << type0Obj << " 0 R >> >>\n";
        apObj << "   /Length " << appearance.contentStream.size() << "\n";
        apObj << ">>\nstream\n";
        apObj << std::string(appearance.contentStream.begin(), appearance.contentStream.end());
        apObj << "\nendstream\nendobj\n";

        incr << apObj.str();

        // -- Font objects: Type0 + CIDFontType2 + FontDescriptor + ToUnicode + FontFile2 + CIDSet --
        PdfFontObjects fontObjs;
        emitPdfFontObjects(appearance.subset, static_cast<uint32_t>(type0Obj), fontObjs);

        auto emitObj = [&](size_t objNum, std::string_view body) {
            objOffsets.push_back({objNum, incr.str().size()});
            std::ostringstream o;
            o << objNum << " 0 obj\n" << body << "\nendobj\n";
            incr << o.str();
        };
        auto emitStreamObj = [&](size_t objNum, std::string_view dictPrefix, std::span<const uint8_t> body) {
            objOffsets.push_back({objNum, incr.str().size()});
            std::ostringstream o;
            o << objNum << " 0 obj\n"
              << "<< " << dictPrefix << " /Length " << body.size() << " >>\n"
              << "stream\n";
            incr << o.str();
            incr.write(reinterpret_cast<const char*>(body.data()), static_cast<std::streamsize>(body.size()));
            incr << "\nendstream\nendobj\n";
        };

        // Type0
        emitObj(type0Obj, fontObjs.type0Dict);
        // CIDFontType2
        emitObj(cidFontObj, fontObjs.cidFontDict);
        // FontDescriptor
        emitObj(fontDescriptorObj, fontObjs.fontDescriptorDict);
        // ToUnicode — CMap stream (ASCII)
        std::span<const uint8_t> toUniBytes(reinterpret_cast<const uint8_t*>(fontObjs.toUnicodeStream.data()),
                                            fontObjs.toUnicodeStream.size());
        emitStreamObj(toUnicodeObj, "", toUniBytes);
        // FontFile2 — the TTF subset bytes
        emitStreamObj(fontFile2Obj, "/Length1 " + std::to_string(fontObjs.fontFile2Stream.size()),
                      fontObjs.fontFile2Stream);
        // CIDSet bitmap stream — PDF/A-2/3 conformance (FontDescriptor /CIDSet)
        emitStreamObj(cidSetObj, "", fontObjs.cidSetStream);
    }

    // -- Updated catalog with /AcroForm (ISO 32000-2 §12.7) --
    // Preserve ALL original catalog properties (Names, Outlines, Metadata, etc.)
    // and only add/override /AcroForm for the signature.
    objOffsets.push_back({catalogObj, incr.str().size()});
    {
        PdfValue::DictType catDict;
        if (catalog.type() == PdfValueType::Dict)
            catDict = catalog.asDict();

        // Ensure required entries are present
        if (catDict.find("Type") == catDict.end())
            catDict["Type"] = PdfValue::name("Catalog");
        if (catDict.find("Pages") == catDict.end())
            catDict["Pages"] = PdfValue::ref(pagesRefVal.objNum, pagesRefVal.genNum);

        // Build /AcroForm, preserving existing fields from original AcroForm
        PdfValue::ArrayType fields;
        auto existingAcroForm = catalog.get("AcroForm");
        if (existingAcroForm.type() == PdfValueType::Dict) {
            auto existingFields = existingAcroForm.get("Fields");
            if (existingFields.type() == PdfValueType::Array)
                fields = existingFields.asArray();
        }
        fields.push_back(PdfValue::ref(static_cast<int>(sigFieldObj)));

        PdfValue::DictType acroForm;
        // Copy existing AcroForm entries (DR, DA, etc.)
        if (existingAcroForm.type() == PdfValueType::Dict) {
            acroForm = existingAcroForm.asDict();
        }
        acroForm["Fields"] = PdfValue::array(std::move(fields));
        acroForm["SigFlags"] = PdfValue::integer(3);

        catDict["AcroForm"] = PdfValue::dict(std::move(acroForm));

        auto serialized = PdfValue::dict(std::move(catDict)).serialize();

        std::ostringstream cat;
        cat << catalogObj << " 0 obj\n";
        cat << serialized << "\n";
        cat << "endobj\n";
        incr << cat.str();
    }

    // -- Updated page with /Annots array (preserves all original attributes) --
    {
        objOffsets.push_back({static_cast<size_t>(origPageObjNum), incr.str().size()});

        // Get the full original page dictionary via PdfParser
        auto pageDict = parser.readObject(origPageObjNum);
        PdfValue::DictType modifiedDict;
        if (pageDict.type() == PdfValueType::Dict)
            modifiedDict = pageDict.asDict();

        // Ensure /Type /Page and /Parent are present
        if (modifiedDict.find("Type") == modifiedDict.end())
            modifiedDict["Type"] = PdfValue::name("Page");
        if (modifiedDict.find("Parent") == modifiedDict.end())
            modifiedDict["Parent"] = PdfValue::ref(pagesRefVal.objNum, pagesRefVal.genNum);
        if (modifiedDict.find("MediaBox") == modifiedDict.end())
            modifiedDict["MediaBox"] = PdfValue::array(
                {PdfValue::integer(0), PdfValue::integer(0), PdfValue::integer(612), PdfValue::integer(792)});

        // Add signature annotation to /Annots, preserving existing annotations
        PdfValue::ArrayType annotsArr;
        auto existingAnnots = pageDict.get("Annots");
        if (existingAnnots.type() == PdfValueType::Array) {
            annotsArr = existingAnnots.asArray();
        } else if (existingAnnots.type() == PdfValueType::Ref) {
            auto resolved = parser.readObject(existingAnnots.asRef().objNum);
            if (resolved.type() == PdfValueType::Array)
                annotsArr = resolved.asArray();
        }
        annotsArr.push_back(PdfValue::ref(static_cast<int>(sigFieldObj)));
        modifiedDict["Annots"] = PdfValue::array(std::move(annotsArr));

        // Serialize the full modified page dictionary
        auto serialized = PdfValue::dict(std::move(modifiedDict)).serialize();

        std::ostringstream pg;
        pg << origPageObjNum << " 0 obj\n";
        pg << serialized << "\n";
        pg << "endobj\n";
        incr << pg.str();
    }

    // -- New xref table --
    // The xref must have separate subsections for non-contiguous object numbers.
    // The page object reuses the original page's object number, while the rest
    // are new objects in a contiguous range starting at sigDictObj.
    size_t xrefStart = incr.str().size();
    size_t baseOffset = pdfData.size(); // objects are appended after original PDF

    // Sort objOffsets by object number to build proper xref subsections
    std::ranges::sort(objOffsets, {}, &std::pair<size_t, size_t>::first);

    // Group into contiguous subsections
    std::ostringstream xrefTable;
    xrefTable << "xref\n";
    xrefTable << "0 1\n";
    xrefTable << "0000000000 65535 f \n";

    size_t i = 0;
    while (i < objOffsets.size()) {
        size_t startObj = objOffsets[i].first;
        size_t count = 1;
        // Find contiguous run
        while (i + count < objOffsets.size() && objOffsets[i + count].first == startObj + count)
            ++count;

        xrefTable << startObj << " " << count << "\n";
        for (size_t j = 0; j < count; ++j) {
            xrefTable << xrefOffset(baseOffset + objOffsets[i + j].second) << " 00000 n \n";
        }
        i += count;
    }

    // -- Trailer --
    // /Root points to the new catalog object which includes /AcroForm
    // /Size must account for all objects (original + new), using max obj number + 1
    size_t maxObjNum = 0;
    for (const auto& [objNum, _] : objOffsets)
        maxObjNum = std::max(maxObjNum, objNum);
    size_t newSize = std::max(nextObjNum + numNewObjs, maxObjNum + 1);

    xrefTable << "trailer\n";
    xrefTable << "<< /Size " << newSize << " /Prev " << oldStartXref << " /Root " << catalogObj << " 0 R >>\n";
    xrefTable << "startxref\n";
    xrefTable << (baseOffset + xrefStart) << "\n";
    xrefTable << "%%EOF\n";

    incr << xrefTable.str();

    // 4. Combine original PDF + incremental update
    auto incrStr = incr.str();
    std::vector<uint8_t> result;
    result.reserve(pdfData.size() + incrStr.size());
    result.insert(result.end(), pdfData.begin(), pdfData.end());
    result.insert(result.end(), incrStr.begin(), incrStr.end());

    // 5. Find the /Contents hex string position in the result
    //    Search for the pattern "/Contents <0000" in the appended section.
    std::string_view resultView(reinterpret_cast<const char*>(result.data()), result.size());
    size_t contentsTagPos = resultView.find("/Contents <", baseOffset);
    if (contentsTagPos == std::string_view::npos)
        throw std::runtime_error("PAdES: cannot find /Contents in prepared PDF");

    size_t hexStart = contentsTagPos + 11;               // position of first '0' after '<'
    size_t hexEnd = hexStart + (contentsAllocBytes * 2); // position of '>'

    // 6. Fix ByteRange placeholders
    //    ByteRange = [0, hexStart-1, hexEnd+1, totalLen-(hexEnd+1)]
    //    hexStart-1 is the position of '<', hexEnd+1 is position after '>'
    size_t contentsOpenBracket = hexStart - 1; // '<'
    size_t contentsCloseBracket = hexEnd;      // '>'
    size_t afterClose = contentsCloseBracket + 1;
    size_t totalLen = result.size();

    // The ByteRange values:
    //   [0, contentsOpenBracket, afterClose, totalLen - afterClose]
    std::string br1 = std::format("{}", contentsOpenBracket);
    std::string br2 = std::format("{}", afterClose);
    std::string br3 = std::format("{}", totalLen - afterClose);

    // Explicit overflow guard: each placeholder is kByteRangePlaceholderWidth
    // (10) digits wide, supporting offsets up to ~10 GiB. Fail loudly with a
    // diagnostic instead of silently truncating the value into the PDF.
    if (br1.size() > kByteRangePlaceholderWidth || br2.size() > kByteRangePlaceholderWidth ||
        br3.size() > kByteRangePlaceholderWidth) {
        throw std::runtime_error(
            "PAdES: PDF too large: ByteRange value exceeds 10-digit placeholder width (~10 GiB upper bound)");
    }

    // Pad each to kByteRangePlaceholderWidth
    while (br1.size() < kByteRangePlaceholderWidth)
        br1.push_back(' ');
    while (br2.size() < kByteRangePlaceholderWidth)
        br2.push_back(' ');
    while (br3.size() < kByteRangePlaceholderWidth)
        br3.push_back(' ');

    // Find "/ByteRange [0 " and overwrite the placeholders
    std::string_view rv2(reinterpret_cast<const char*>(result.data()), result.size());
    size_t brPos = rv2.find("/ByteRange [0 ", baseOffset);
    if (brPos == std::string_view::npos)
        throw std::runtime_error("PAdES: cannot find /ByteRange in prepared PDF");

    size_t writePos = brPos + 14; // after "/ByteRange [0 "
    std::memcpy(result.data() + writePos, br1.data(), kByteRangePlaceholderWidth);
    writePos += kByteRangePlaceholderWidth + 1; // +1 for space
    std::memcpy(result.data() + writePos, br2.data(), kByteRangePlaceholderWidth);
    writePos += kByteRangePlaceholderWidth + 1;
    std::memcpy(result.data() + writePos, br3.data(), kByteRangePlaceholderWidth);

    return PreparedPdf{
        .bytes = std::move(result),
        .contentsHexStart = hexStart,
        .contentsHexLen = contentsAllocBytes,
    };
}

// ---- sign ----

SigningResult PAdESModule::sign(const std::vector<uint8_t>& pdfDataIn, Pkcs11Token& token, SignatureLevel level,
                                const TSAConfig& tsa, const VisualSignatureParams& visual)
{
    try {
        if (pdfDataIn.size() < 5)
            return {false, {}, "Input PDF is too small"};

        // Adobe Acrobat Implementation Notes §H.3: tolerate up to 1024 bytes of
        // non-PDF prefix before the "%PDF-" header (e.g. multipart/form-data
        // wrappers from web-form uploads), and strip trailing junk after the
        // last "%%EOF". This matches Acrobat, Foxit, qpdf, pdfinfo behavior.
        //
        // We work on a local copy so the caller's input is never mutated.
        const std::string_view kPdfMagic = "%PDF-";
        constexpr size_t kHeaderScanWindow = 1024;

        size_t prefixLen = 0;
        {
            size_t scanLen = std::min(pdfDataIn.size(), kHeaderScanWindow);
            std::string_view scan(reinterpret_cast<const char*>(pdfDataIn.data()), scanLen);
            auto found = scan.find(kPdfMagic);
            if (found == std::string_view::npos)
                return {false, {}, "Input is not a valid PDF (missing %PDF- header)"};
            prefixLen = found;
        }

        std::vector<uint8_t> pdfData(pdfDataIn.begin() + static_cast<long>(prefixLen), pdfDataIn.end());

        // Strip trailing data after the last "%%EOF". Keep an optional single
        // trailing CR/LF. If no "%%EOF" is present the PDF is structurally
        // broken; leave the buffer as-is and let the parser surface the error.
        {
            const std::string_view kEof = "%%EOF";
            std::string_view view(reinterpret_cast<const char*>(pdfData.data()), pdfData.size());
            auto eofPos = view.rfind(kEof);
            if (eofPos != std::string_view::npos) {
                size_t keep = eofPos + kEof.size();
                // Preserve one optional CR/LF / CRLF after %%EOF so consumers
                // that expect a line-terminated marker still see one.
                if (keep < pdfData.size() && pdfData[keep] == '\r')
                    ++keep;
                if (keep < pdfData.size() && pdfData[keep] == '\n')
                    ++keep;
                if (keep < pdfData.size())
                    pdfData.resize(keep);
            }
        }

        // Verify PDF magic at start of the normalized buffer (sanity check).
        std::string_view header(reinterpret_cast<const char*>(pdfData.data()), 5);
        if (header != "%PDF-")
            return {false, {}, "Input is not a valid PDF (missing %PDF- header)"};

        // 1. Prepare the PDF with incremental update (sig dict, field, visual)
        size_t contentsAllocBytes = contentsAllocForLevel(level);
        auto prepared = preparePdf(pdfData, visual, contentsAllocBytes);

        // 2. Compute SHA-256 hash over the byte ranges
        //    ByteRange = [0, contentsHexStart-1, contentsHexStart-1+contentsHexChars+2, ...]
        //    The signed data is everything EXCEPT the hex content between < and >
        size_t hexStart = prepared.contentsHexStart;
        size_t hexEnd = hexStart + (contentsAllocBytes * 2);
        size_t totalLen = prepared.bytes.size();

        // Defensive: hexStart, hexEnd, and the resulting byte ranges all
        // come from internal preparePdf() and should be in-bounds, but a
        // bug there would otherwise produce an OOB read at insert(). Bail
        // explicitly with a clear error before doing the iterator math.
        // Also reject the empty / inverted range case (hexEnd <= hexStart)
        // which would silently produce a zero-byte signed range.
        if (hexStart == 0 || hexStart >= totalLen || hexEnd >= totalLen || hexEnd <= hexStart) {
            return {false, {}, "Internal error: invalid /Contents byte range from PDF preparation"};
        }
        size_t contentsOpen = hexStart - 1; // '<'
        size_t contentsClose = hexEnd;      // '>'
        size_t afterClose = contentsClose + 1;
        if (afterClose > totalLen) {
            return {false, {}, "Internal error: /Contents close offset past end of prepared PDF"};
        }

        // Concatenate the two byte ranges for hashing
        std::vector<uint8_t> signedData;
        signedData.reserve(contentsOpen + (totalLen - afterClose));
        signedData.insert(signedData.end(), prepared.bytes.begin(),
                          prepared.bytes.begin() + static_cast<long>(contentsOpen));
        signedData.insert(signedData.end(), prepared.bytes.begin() + static_cast<long>(afterClose),
                          prepared.bytes.end());

        // 3. Create CAdES detached signature over the byte range data.
        //    CAdESModule::signBB hashes the data internally, which is what we want:
        //    it computes SHA-256(signedData) and creates CMS SignedData with that digest.
        CAdESModule cades;
        auto cms = cades.signBB(signedData, token);
        if (cms.empty())
            return {false, {}, "CAdES B-B signing produced empty output"};

        // 4. Upgrade to requested level
        if (level >= SignatureLevel::B_T) {
            cms = cades.addTimestamp(cms, tsa);
        }

        if (level >= SignatureLevel::B_LT) {
            auto revData = collectRevocationData(token, tsa);
            cms = cades.addRevocationData(cms, revData);
        }

        if (level >= SignatureLevel::B_LTA) {
            cms = cades.addArchiveTimestamp(cms, tsa);
        }

        // 5. Verify CMS fits in the allocated space
        if (cms.size() > contentsAllocBytes)
            return {false,
                    {},
                    std::format("CMS signature ({} bytes) exceeds allocated space ({} bytes)", cms.size(),
                                contentsAllocBytes)};

        // 6. Hex-encode the CMS and embed into /Contents
        std::string hex = hexEncode(cms);
        // Pad with '0' to fill the placeholder
        while (hex.size() < (contentsAllocBytes * 2))
            hex.push_back('0');

        // Write hex into the prepared PDF bytes
        std::memcpy(prepared.bytes.data() + hexStart, hex.data(), (contentsAllocBytes * 2));

        return {true, std::move(prepared.bytes), {}};

    } catch (const std::exception& e) {
        return {false, {}, std::string("PAdES error: ") + e.what()};
    }
}

} // namespace libresign

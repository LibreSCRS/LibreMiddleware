// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/pades_module.h"
#include "native/cades_module.h"
#include "native/pdf_doc_timestamp.h"
#include "utf8.h"
#include "native/pdf_dss.h"
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

// hexEncode lives in native_utils (libresign::native_utils::hexEncode) and
// is reachable here via the `using namespace libresign::native_utils;` line
// above.

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
            auto [cp, n] = ::libresign::utf8::decodeAt(line, i);
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
            auto [cp, n] = ::libresign::utf8::decodeAt(line, i);
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
    // PAdES multi-sign: every signature field MUST carry a unique /T
    // name. DSS (and Adobe Acrobat) group signatures by field name; reusing
    // "LibreSCRS_Sig" across incremental updates causes the second sig to
    // be treated as a re-signing of the first, and the validator only
    // reports one. Count prior sig fields in the existing AcroForm and
    // suffix accordingly (LibreSCRS_Sig_1, _2, …) — the bare base name is
    // kept for the first signature so existing PAdES single-sign outputs
    // stay byte-compatible.
    int priorSigFieldCount = 0;
    if (catalog.type() == PdfValueType::Dict) {
        auto existingAcroForm = catalog.get("AcroForm");
        if (existingAcroForm.type() == PdfValueType::Dict) {
            auto existingFields = existingAcroForm.get("Fields");
            if (existingFields.type() == PdfValueType::Array) {
                for (const auto& f : existingFields.asArray()) {
                    if (f.type() == PdfValueType::Ref) {
                        auto fieldObj = parser.readObject(f.asRef().objNum);
                        if (fieldObj.type() == PdfValueType::Dict) {
                            auto ft = fieldObj.get("FT");
                            if (ft.type() == PdfValueType::Name && ft.asName() == "Sig")
                                ++priorSigFieldCount;
                        }
                    }
                }
            }
        }
    }
    std::string sigFieldName = "LibreSCRS_Sig";
    if (priorSigFieldCount > 0)
        sigFieldName += "_" + std::to_string(priorSigFieldCount + 1);
    sigField << "   /T (" << sigFieldName << ")\n";
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
            incr << std::format("{} 0 obj\n{}\nendobj\n", objNum, body);
        };
        auto emitStreamObj = [&](size_t objNum, std::string_view dictPrefix, std::span<const uint8_t> body) {
            objOffsets.push_back({objNum, incr.str().size()});
            incr << std::format("{} 0 obj\n<< {} /Length {} >>\nstream\n", objNum, dictPrefix, body.size());
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
        incr << std::format("{} 0 obj\n{}\nendobj\n", catalogObj, serialized);
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
            return makeFailure(SignFailureKind::InvalidInput, "Input PDF is too small");

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
                return makeFailure(SignFailureKind::InvalidInput, "Input is not a valid PDF (missing %PDF- header)");
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
            return makeFailure(SignFailureKind::InvalidInput, "Input is not a valid PDF (missing %PDF- header)");

        // 1. Prepare the PDF with the SIGNATURE incremental update (sig
        //    dict, field, visual). DSS material is appended later in a
        //    SECOND incremental update so its bytes sit outside the signed
        //    /ByteRange — VRI keying requires knowing the final CMS bytes,
        //    so the DSS must be emitted post-sign.
        //
        // For B-LT+ we still collect the cert chain + revocation material
        // up front: the same RevocationData feeds both
        // CAdESModule::addRevocationData (CMS-side embedding) and the DSS
        // dictionary (PDF-side LTV anchor), so we pay one CRL/OCSP fetch.
        PdfDssMaterial dssMat;
        RevocationData revData;
        const bool wantsLT = (level >= SignatureLevel::B_LT);
        if (wantsLT) {
            dssMat.certs = token.certificateChain();
            revData = collectRevocationData(token, tsa);
            if (auto failure = revocationFailClosed(revData))
                return *failure;
            dssMat.crls = revData.crls;
            dssMat.ocspResponses = revData.ocspResponses;
        }

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
            return makeFailure(SignFailureKind::PdfPreparationError,
                               "Internal error: invalid /Contents byte range from PDF preparation");
        }
        size_t contentsOpen = hexStart - 1; // '<'
        size_t contentsClose = hexEnd;      // '>'
        size_t afterClose = contentsClose + 1;
        if (afterClose > totalLen) {
            return makeFailure(SignFailureKind::PdfPreparationError,
                               "Internal error: /Contents close offset past end of prepared PDF");
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
            return makeFailure(SignFailureKind::OpensslError, "CAdES B-B signing produced empty output");

        // 4. Upgrade to requested level
        if (level >= SignatureLevel::B_T) {
            cms = cades.addTimestamp(cms, tsa);
        }

        if (wantsLT) {
            // revData already collected pre-preparePdf for the DSS dictionary;
            // reuse it here to avoid a redundant CRL/OCSP network round-trip.
            cms = cades.addRevocationData(cms, revData);
        }

        // PAdES B-LTA does NOT embed a CAdES archive-timestamp; instead a
        // second /DocTimeStamp incremental update is layered AFTER the B-LT
        // pipeline below (ETSI EN 319 142-1 §5.5). Handled at the end.

        // 5. Verify CMS fits in the allocated space
        if (cms.size() > contentsAllocBytes)
            return makeFailure(SignFailureKind::PdfPreparationError,
                               std::format("CMS signature ({} bytes) exceeds allocated space ({} bytes)", cms.size(),
                                           contentsAllocBytes));

        // 6. Hex-encode the CMS and embed into /Contents
        std::string hex = hexEncode(cms);
        // Pad with '0' to fill the placeholder
        while (hex.size() < (contentsAllocBytes * 2))
            hex.push_back('0');

        // Write hex into the prepared PDF bytes
        std::memcpy(prepared.bytes.data() + hexStart, hex.data(), (contentsAllocBytes * 2));

        // 7. Append a SECOND incremental update with the Document Security
        //    Store (ETSI EN 319 142-1 §5.4.2 / ISO 32000-2 §12.8.4.3) for
        //    B-LT+. This sits outside the signed /ByteRange — Adobe's
        //    "Add LTV information" flow uses the same shape — so the
        //    signature hash stays valid.
        if (wantsLT) {
            // Re-parse the now-signed PDF to discover the post-signature
            // object-number counter and the catalog reference. Cheaper than
            // threading state out of preparePdf and immune to drift if the
            // signature-update layout changes shape.
            PdfParser sigParser(prepared.bytes);
            if (!sigParser.parse())
                return makeFailure(SignFailureKind::PdfPreparationError,
                                   "DSS: failed to re-parse signed PDF for incremental update");

            const size_t sigStartXref = sigParser.resolvedXrefOffset();
            const size_t nextObj = static_cast<size_t>(sigParser.trailer().get("Size").asInt());
            auto rootRefVal = sigParser.trailer().get("Root").asRef();
            const size_t rootObjNum = rootRefVal.objNum;
            const size_t rootGenNum = rootRefVal.genNum;
            auto sigCatalog = sigParser.readObject(rootObjNum);

            // ISO 32000-2 §12.8.4.3 VRI key: lowercase-hex SHA-1 of the
            // signed /Contents bytes (raw CMS DER octets, not the hex
            // envelope). iText / eu.europa.ec.dss / Adobe Acrobat all hash
            // the binary CMS here.
            auto sha1 = native_utils::sha1(cms);
            std::string vriKey;
            vriKey.reserve(sha1.size() * 2);
            static constexpr char kHexLower[] = "0123456789abcdef";
            for (auto b : sha1) {
                vriKey.push_back(kHexLower[(b >> 4) & 0x0F]);
                vriKey.push_back(kHexLower[b & 0x0F]);
            }

            // Allocate object numbers: DSS dict at nextObj, streams follow,
            // catalog override at the very end so the xref subsections stay
            // compact.
            const size_t dssObj = nextObj;
            const size_t streamCount = dssMat.certs.size() + dssMat.crls.size() + dssMat.ocspResponses.size();
            const size_t newCatalogObj = dssObj + 1 + streamCount;

            std::size_t dssObjNumOut = 0;
            auto dssBytes = buildDssBlock(dssMat, dssObj, vriKey, dssObjNumOut);
            // Empty DSS (no certs / no revocation) — skip the second update
            // entirely; the signature is still a valid B-T-ish artefact.
            if (!dssBytes.empty()) {
                std::ostringstream incr2;
                incr2 << "\n";
                std::vector<std::pair<size_t, size_t>> objs2; // (objNum, offset_in_incr2)

                const size_t dssBlockOffset = incr2.str().size();
                // Stream object offsets, in textual order of buildDssBlock
                // (certs, then CRLs, then OCSPs, then DSS dict).
                std::string_view dssView(reinterpret_cast<const char*>(dssBytes.data()), dssBytes.size());
                auto findObjStart = [&](std::size_t objNum) -> std::size_t {
                    if (dssView.starts_with(std::format("{} 0 obj\n", objNum)))
                        return 0;
                    auto needle = std::format("\n{} 0 obj\n", objNum);
                    auto p = dssView.find(needle);
                    if (p == std::string_view::npos)
                        throw std::runtime_error("DSS: object " + std::to_string(objNum) + " missing from block");
                    return p + 1;
                };
                for (std::size_t i = 0; i < streamCount; ++i) {
                    std::size_t objNum = dssObj + 1 + i;
                    objs2.push_back({objNum, dssBlockOffset + findObjStart(objNum)});
                }
                objs2.push_back({dssObj, dssBlockOffset + findObjStart(dssObj)});
                incr2.write(reinterpret_cast<const char*>(dssBytes.data()),
                            static_cast<std::streamsize>(dssBytes.size()));

                // Catalog override: copy existing catalog dictionary and
                // splice in /DSS <ref>. Preserves AcroForm, Pages, Names,
                // Outlines, etc. from the post-signature catalog.
                {
                    objs2.push_back({newCatalogObj, incr2.str().size()});
                    PdfValue::DictType catDict;
                    if (sigCatalog.type() == PdfValueType::Dict)
                        catDict = sigCatalog.asDict();
                    catDict["DSS"] = PdfValue::ref(static_cast<int>(dssObj));
                    auto serialized = PdfValue::dict(std::move(catDict)).serialize();
                    incr2 << std::format("{} 0 obj\n{}\nendobj\n", newCatalogObj, serialized);
                }

                // xref + trailer for incr2.
                const size_t xref2Start = incr2.str().size();
                const size_t baseOffset2 = prepared.bytes.size();
                std::ranges::sort(objs2, {}, &std::pair<size_t, size_t>::first);

                std::ostringstream xref2;
                xref2 << "xref\n";
                xref2 << "0 1\n0000000000 65535 f \n";
                size_t k = 0;
                while (k < objs2.size()) {
                    size_t startObj = objs2[k].first;
                    size_t count = 1;
                    while (k + count < objs2.size() && objs2[k + count].first == startObj + count)
                        ++count;
                    xref2 << startObj << " " << count << "\n";
                    for (size_t j = 0; j < count; ++j)
                        xref2 << xrefOffset(baseOffset2 + objs2[k + j].second) << " 00000 n \n";
                    k += count;
                }

                size_t maxObj2 = 0;
                for (const auto& [o, _] : objs2)
                    maxObj2 = std::max(maxObj2, o);
                size_t newSize2 = std::max(nextObj + 1 + streamCount + 1, maxObj2 + 1);

                xref2 << "trailer\n<< /Size " << newSize2 << " /Prev " << sigStartXref << " /Root " << newCatalogObj
                      << " " << rootGenNum << " R >>\nstartxref\n"
                      << (baseOffset2 + xref2Start) << "\n%%EOF\n";
                incr2 << xref2.str();

                auto incr2Str = incr2.str();
                prepared.bytes.insert(prepared.bytes.end(), incr2Str.begin(), incr2Str.end());
            }
        }

        // 8. PAdES B-LTA: layer a /DocTimeStamp second incremental update
        //    over the now-complete B-LT PDF per ETSI EN 319 142-1 §5.5.
        //    The TSA chain DSS material is empty for now — the resulting
        //    document carries a valid /DocTimeStamp but a strict validator
        //    may classify it as B-LT if it cannot independently build the
        //    TSA chain. Revisit when TSAClient exposes the chain.
        if (level >= SignatureLevel::B_LTA) {
            try {
                PdfDssMaterial tsaMat;
                auto docTsBlock = libresign::appendDocTimeStamp(prepared.bytes, tsa, tsaMat);
                prepared.bytes.insert(prepared.bytes.end(), docTsBlock.begin(), docTsBlock.end());
            } catch (const std::runtime_error& e) {
                std::string what = e.what();
                // appendDocTimeStamp prefixes TSA transport failures with
                // "appendDocTimeStamp: TSA failed:" (see pdf_doc_timestamp.cpp);
                // every other throw is a parse / oversize / internal error.
                if (what.find("TSA failed:") != std::string::npos ||
                    what.find("TSA returned empty") != std::string::npos)
                    return makeFailure(SignFailureKind::TsaUnreachable, std::string{"DocTimeStamp: "} + what);
                return makeFailure(SignFailureKind::EngineError, std::string{"DocTimeStamp: "} + what);
            }
        }

        return makeSuccess(std::move(prepared.bytes));

    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("PAdES error: ") + e.what());
    }
}

SigningResult PAdESModule::appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                        Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa,
                                        const VisualSignatureParams& visual)
{
    // The PAdES incremental-update model lets sign() handle a prior-signed PDF
    // transparently: the new signature occupies a fresh incremental update
    // layered on top of the prior /Contents region. originalDoc is recoverable
    // from the prior PDF's signed byte range, so when supplied it is currently
    // informational only.
    (void)originalDoc;
    return sign(std::vector<uint8_t>(prior.begin(), prior.end()), token, level, tsa, visual);
}

} // namespace libresign

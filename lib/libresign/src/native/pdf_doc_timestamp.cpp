// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/pdf_doc_timestamp.h"
#include "native/native_utils.h"
#include "native/pdf_parser.h"
#include "native/tsa_client.h"

#include <algorithm>
#include <cstring>
#include <format>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <string_view>

namespace libresign {

namespace {

// /Contents placeholder size for the RFC 3161 TimeStampToken. The TST
// is a PKCS#7 SignedData carrying TSTInfo plus the TSA's signing cert
// (and frequently the issuing CA — most TSAs include the full chain
// inside `certs` of the SignedData per RFC 3161 §2.4.2 recommendation).
// Observed sizes across DigiCert / Sectigo / Entrust / mit.gov.rs:
// 3.5 – 7 KiB. 16 KiB gives ~2× headroom for chains with multiple
// intermediates or future post-quantum signature blowup without inflating
// every B-LTA document by megabytes the way the regular signature path's
// 4 MiB allocation would.
constexpr std::size_t kDocTimestampContentsAlloc = 16384;

// ByteRange placeholder: 4 numbers each padded to allow in-place
// overwrite. Format: [0 XXXXXXXXXX XXXXXXXXXX XXXXXXXXXX]. Each
// placeholder is 10 chars wide + spaces. Matches the regular signature
// path's kByteRangePlaceholderWidth (10 digits → ~10 GiB upper bound).
constexpr std::size_t kByteRangePlaceholderWidth = 10;

// SHA-1 lowercase-hex VRI key placeholder: 40 '0' characters, patched
// after the TST is acquired (since the VRI key is sha1(tst) per
// ISO 32000-2 §12.8.4.3). 40 chars is fixed regardless of input —
// SHA-1 always outputs 20 bytes = 40 hex chars — so the placeholder
// size never drifts.
constexpr std::size_t kVriKeyHexLen = 40;

// Signature widget annotation flags per PDF 32000-1:2008 §12.5.3
// Table 165: Print (4) + Locked (128) = 132. Matches the regular
// signature path; DocTimeStamp widgets follow the same conventions.
constexpr int kSigFieldAnnotFlags = 132;

// Write a number as a zero-padded 10-digit xref offset string.
std::string xrefOffset(std::size_t offset)
{
    return std::format("{:010}", offset);
}

void appendCStr(std::vector<std::uint8_t>& out, std::string_view s)
{
    out.insert(out.end(), s.begin(), s.end());
}

} // namespace

std::vector<std::uint8_t> appendDocTimeStamp(const std::vector<std::uint8_t>& bltPdf, const TSAConfig& tsa,
                                             const PdfDssMaterial& tsaChainMat)
{
    // 1. Parse the B-LT PDF to discover the post-DSS object counter,
    //    the prior xref offset (for /Prev), and the existing catalog
    //    (we copy its dict and splice in an extended /AcroForm).
    PdfParser parser(bltPdf);
    if (!parser.parse())
        throw std::runtime_error("appendDocTimeStamp: failed to parse input B-LT PDF");

    const std::size_t prevStartXref = parser.resolvedXrefOffset();
    const std::size_t nextObj = static_cast<std::size_t>(parser.trailer().get("Size").asInt());
    auto rootRefVal = parser.trailer().get("Root").asRef();
    const int rootObjGen = rootRefVal.genNum;
    auto catalog = parser.readObject(rootRefVal.objNum);

    // 2. Allocate object numbers. Layout:
    //      sigDictObj                                 — /Type /DocTimeStamp
    //      sigFieldObj                                — /FT /Sig + widget
    //      dssObj  (if tsaChainMat non-empty)         — top-level DSS dict
    //      dssObj+1 ... dssObj+streamCount-1          — cert/CRL/OCSP streams
    //      newCatalogObj                              — catalog override
    const std::size_t sigDictObj = nextObj;
    const std::size_t sigFieldObj = nextObj + 1;

    const std::size_t streamCount =
        tsaChainMat.certs.size() + tsaChainMat.crls.size() + tsaChainMat.ocspResponses.size();
    const bool emitDss = streamCount > 0;
    const std::size_t dssObj = emitDss ? (nextObj + 2) : 0;
    const std::size_t newCatalogObj = nextObj + 2 + (emitDss ? (1 + streamCount) : 0);

    // 3. Build the incremental block, with placeholders for /Contents,
    //    /ByteRange and (if emitDss) the VRI key. Object offsets are
    //    captured relative to the start of the block; we'll add
    //    baseOffset = bltPdf.size() when emitting the xref table.
    std::vector<std::uint8_t> incr;
    incr.reserve(64 * 1024); // typical block is sig dict (~16K hex) + DSS streams + xref
    appendCStr(incr, "\n");

    std::vector<std::pair<std::size_t, std::size_t>> objOffsets; // (objNum, offset)

    // -- DocTimeStamp signature dictionary --
    // No /M entry: per ETSI EN 319 142-1 §5.5, the canonical time of a
    // DocTimeStamp lives inside the TSTInfo of the embedded TimeStampToken
    // (genTime + accuracy + TSA identity, attested by the TSA). The /M
    // entry on a regular sig dict is signer-local wall clock and would
    // be redundant / misleading here.
    {
        objOffsets.push_back({sigDictObj, incr.size()});
        std::ostringstream sigDict;
        sigDict << sigDictObj << " 0 obj\n";
        sigDict << "<< /Type /DocTimeStamp\n";
        sigDict << "   /Filter /Adobe.PPKLite\n";
        sigDict << "   /SubFilter /ETSI.RFC3161\n";
        sigDict << "   /ByteRange [0 ";
        sigDict << std::string(kByteRangePlaceholderWidth, ' ') << " ";
        sigDict << std::string(kByteRangePlaceholderWidth, ' ') << " ";
        sigDict << std::string(kByteRangePlaceholderWidth, ' ') << "]\n";
        sigDict << "   /Contents <";
        sigDict << std::string(kDocTimestampContentsAlloc * 2, '0');
        sigDict << ">\n";
        sigDict << ">>\nendobj\n";
        appendCStr(incr, sigDict.str());
    }

    // -- Signature field + invisible widget annotation --
    // /T must be unique within AcroForm.Fields (PDF 32000-1 §12.7.3.1);
    // "LibreSCRS_DocTS" disambiguates from the regular signature's
    // "LibreSCRS_Sig" field. Rect [0 0 0 0] = invisible (DocTimeStamps
    // carry no visible mark per ETSI conventions). /P (page reference)
    // is omitted: invisible widgets without page anchoring are explicitly
    // permitted by ISO 32000-2 §12.5.6.19 and avoid having to mutate the
    // page object in a third incremental update.
    {
        objOffsets.push_back({sigFieldObj, incr.size()});
        std::ostringstream sigField;
        sigField << sigFieldObj << " 0 obj\n";
        sigField << "<< /Type /Annot\n";
        sigField << "   /Subtype /Widget\n";
        sigField << "   /FT /Sig\n";
        sigField << "   /T (LibreSCRS_DocTS)\n";
        sigField << "   /V " << sigDictObj << " 0 R\n";
        sigField << "   /Rect [0 0 0 0]\n";
        sigField << "   /F " << kSigFieldAnnotFlags << "\n";
        sigField << ">>\nendobj\n";
        appendCStr(incr, sigField.str());
    }

    // -- Optional embedded /DSS for TSA chain --
    // VRI key is sha1(tst) per ISO 32000-2 §12.8.4.3 — but the TST is
    // not yet acquired. Build the DSS block with a 40-'0' placeholder
    // and patch it after the TSA roundtrip. The DSS block's BYTE LAYOUT
    // is independent of the key contents because SHA-1 always produces
    // exactly 40 hex characters, so /ByteRange computed against this
    // placeholder block remains correct after patching.
    std::size_t vriPlaceholderOffsetInIncr = 0; // absolute offset of the 40-'0' in `incr`
    if (emitDss) {
        std::size_t dssObjNumOut = 0;
        const std::string vriPlaceholder(kVriKeyHexLen, '0');
        auto dssBytes = buildDssBlock(tsaChainMat, dssObj, vriPlaceholder, dssObjNumOut);
        if (dssBytes.empty())
            throw std::runtime_error("appendDocTimeStamp: buildDssBlock returned empty bytes for non-empty material");

        // Record object offsets, in textual order of buildDssBlock
        // (streams first in cert/CRL/OCSP order, then the DSS dict).
        std::string_view dssView(reinterpret_cast<const char*>(dssBytes.data()), dssBytes.size());
        auto findObjStart = [&](std::size_t objNum) -> std::size_t {
            if (dssView.starts_with(std::format("{} 0 obj\n", objNum)))
                return 0;
            auto needle = std::format("\n{} 0 obj\n", objNum);
            auto p = dssView.find(needle);
            if (p == std::string_view::npos)
                throw std::runtime_error("appendDocTimeStamp: DSS object " + std::to_string(objNum) + " missing");
            return p + 1;
        };
        const std::size_t dssBlockOffset = incr.size();
        for (std::size_t i = 0; i < streamCount; ++i) {
            std::size_t objNum = dssObj + 1 + i;
            objOffsets.push_back({objNum, dssBlockOffset + findObjStart(objNum)});
        }
        objOffsets.push_back({dssObj, dssBlockOffset + findObjStart(dssObj)});

        // Resolve VRI placeholder offset inside the DSS bytes before
        // we splice them in — easier to search the small buffer than
        // the assembled block.
        auto vriRelative = dssView.find(vriPlaceholder);
        if (vriRelative == std::string_view::npos)
            throw std::runtime_error("appendDocTimeStamp: VRI key placeholder not found in DSS bytes");
        vriPlaceholderOffsetInIncr = dssBlockOffset + vriRelative;

        incr.insert(incr.end(), dssBytes.begin(), dssBytes.end());
    }

    // -- Catalog override --
    // Copy the existing catalog dict (preserves Pages, Names, Outlines,
    // Metadata and the prior /DSS from the B-LT step) and extend the
    // /AcroForm.Fields array with the new sigFieldObj. If the prior
    // catalog already carries a /DSS, leave it pointing at the prior
    // dict — the TSA chain's DSS material is a SEPARATE dict object
    // here (Adobe layered DSS pattern). When @p tsaChainMat is empty
    // we don't touch /DSS at all.
    {
        objOffsets.push_back({newCatalogObj, incr.size()});

        PdfValue::DictType catDict;
        if (catalog.type() == PdfValueType::Dict)
            catDict = catalog.asDict();

        // Extend AcroForm.Fields.
        PdfValue::DictType acroForm;
        auto existingAcroForm = catalog.get("AcroForm");
        if (existingAcroForm.type() == PdfValueType::Dict)
            acroForm = existingAcroForm.asDict();

        PdfValue::ArrayType fields;
        auto existingFields = existingAcroForm.get("Fields");
        if (existingFields.type() == PdfValueType::Array)
            fields = existingFields.asArray();
        fields.push_back(PdfValue::ref(static_cast<int>(sigFieldObj)));
        acroForm["Fields"] = PdfValue::array(std::move(fields));
        // SigFlags = 3 (SignaturesExist | AppendOnly) — preserve if
        // already 3, force-set if absent to keep AcroForm well-formed.
        acroForm["SigFlags"] = PdfValue::integer(3);

        catDict["AcroForm"] = PdfValue::dict(std::move(acroForm));

        // Layered /DSS: when we emit a TSA-chain DSS dict in this
        // update, point /DSS at it. The prior DSS bytes remain in
        // the file (incremental updates never delete), but readers
        // follow the most recent catalog's /DSS ref. iText / Adobe
        // accept this layering; conformant validators MUST merge
        // material across DSS dicts via the VRI keys, which this
        // path supports correctly.
        if (emitDss)
            catDict["DSS"] = PdfValue::ref(static_cast<int>(dssObj));

        auto serialized = PdfValue::dict(std::move(catDict)).serialize();
        appendCStr(incr, std::format("{} 0 obj\n{}\nendobj\n", newCatalogObj, serialized));
    }

    // -- xref + trailer --
    const std::size_t baseOffset = bltPdf.size();
    const std::size_t xrefStart = incr.size();

    std::ranges::sort(objOffsets, {}, &std::pair<std::size_t, std::size_t>::first);

    std::ostringstream xrefTable;
    xrefTable << "xref\n";
    xrefTable << "0 1\n0000000000 65535 f \n";
    std::size_t i = 0;
    while (i < objOffsets.size()) {
        std::size_t startObj = objOffsets[i].first;
        std::size_t count = 1;
        while (i + count < objOffsets.size() && objOffsets[i + count].first == startObj + count)
            ++count;
        xrefTable << startObj << " " << count << "\n";
        for (std::size_t j = 0; j < count; ++j)
            xrefTable << xrefOffset(baseOffset + objOffsets[i + j].second) << " 00000 n \n";
        i += count;
    }

    std::size_t maxObjNum = 0;
    for (const auto& [o, _] : objOffsets)
        maxObjNum = std::max(maxObjNum, o);
    const std::size_t newSize = maxObjNum + 1;

    xrefTable << "trailer\n<< /Size " << newSize << " /Prev " << prevStartXref << " /Root " << newCatalogObj << " "
              << rootObjGen << " R >>\nstartxref\n"
              << (baseOffset + xrefStart) << "\n%%EOF\n";
    appendCStr(incr, xrefTable.str());

    // 4. Concatenate bltPdf + incr so we can compute the signed byte
    //    range over the FINAL document.
    std::vector<std::uint8_t> full;
    full.reserve(bltPdf.size() + incr.size());
    full.insert(full.end(), bltPdf.begin(), bltPdf.end());
    full.insert(full.end(), incr.begin(), incr.end());

    // 5. Locate /Contents in the appended section, compute byte range,
    //    and patch the /ByteRange placeholder in-place.
    std::string_view fullView(reinterpret_cast<const char*>(full.data()), full.size());
    std::size_t contentsTagPos = fullView.find("/Contents <", baseOffset);
    if (contentsTagPos == std::string_view::npos)
        throw std::runtime_error("appendDocTimeStamp: cannot find /Contents placeholder in assembled block");

    const std::size_t hexStart = contentsTagPos + 11;                       // first '0' after '<'
    const std::size_t hexEnd = hexStart + (kDocTimestampContentsAlloc * 2); // position of '>'
    const std::size_t contentsOpen = hexStart - 1;                          // '<'
    const std::size_t afterClose = hexEnd + 1;                              // after '>'
    const std::size_t totalLen = full.size();

    if (afterClose > totalLen)
        throw std::runtime_error("appendDocTimeStamp: /Contents close offset past end of assembled block");

    // ByteRange = [0, contentsOpen, afterClose, totalLen - afterClose]
    std::string br1 = std::format("{}", contentsOpen);
    std::string br2 = std::format("{}", afterClose);
    std::string br3 = std::format("{}", totalLen - afterClose);

    if (br1.size() > kByteRangePlaceholderWidth || br2.size() > kByteRangePlaceholderWidth ||
        br3.size() > kByteRangePlaceholderWidth) {
        throw std::runtime_error(
            "appendDocTimeStamp: PDF too large for 10-digit ByteRange placeholder (~10 GiB upper bound)");
    }
    while (br1.size() < kByteRangePlaceholderWidth)
        br1.push_back(' ');
    while (br2.size() < kByteRangePlaceholderWidth)
        br2.push_back(' ');
    while (br3.size() < kByteRangePlaceholderWidth)
        br3.push_back(' ');

    std::size_t brPos = fullView.find("/ByteRange [0 ", baseOffset);
    if (brPos == std::string_view::npos)
        throw std::runtime_error("appendDocTimeStamp: cannot find /ByteRange placeholder in assembled block");
    std::size_t writePos = brPos + 14; // after "/ByteRange [0 "
    std::memcpy(full.data() + writePos, br1.data(), kByteRangePlaceholderWidth);
    writePos += kByteRangePlaceholderWidth + 1;
    std::memcpy(full.data() + writePos, br2.data(), kByteRangePlaceholderWidth);
    writePos += kByteRangePlaceholderWidth + 1;
    std::memcpy(full.data() + writePos, br3.data(), kByteRangePlaceholderWidth);

    // 6. Hash the byte range and request the TST.
    std::vector<std::uint8_t> signedData;
    signedData.reserve(contentsOpen + (totalLen - afterClose));
    signedData.insert(signedData.end(), full.begin(), full.begin() + static_cast<long>(contentsOpen));
    signedData.insert(signedData.end(), full.begin() + static_cast<long>(afterClose), full.end());

    auto hash = native_utils::sha256(signedData);
    TSAClient client;
    auto tsaResult = client.timestamp(hash, toTsaRequest(tsa));
    if (!tsaResult.success)
        throw std::runtime_error(std::string("appendDocTimeStamp: TSA failed: ") + tsaResult.errorMessage);
    const auto& tst = tsaResult.token;
    if (tst.empty())
        throw std::runtime_error("appendDocTimeStamp: TSA returned empty TimeStampToken");
    if (tst.size() > kDocTimestampContentsAlloc) {
        throw std::runtime_error(std::format(
            "appendDocTimeStamp: RFC 3161 TimeStampToken ({} bytes) exceeds /Contents allocation ({} bytes); "
            "raise kDocTimestampContentsAlloc",
            tst.size(), kDocTimestampContentsAlloc));
    }

    // 7. Hex-embed the TST into the /Contents placeholder, pad to alloc.
    std::string tstHex = native_utils::hexEncode(tst, /*lowercase=*/true);
    while (tstHex.size() < (kDocTimestampContentsAlloc * 2))
        tstHex.push_back('0');
    std::memcpy(full.data() + hexStart, tstHex.data(), kDocTimestampContentsAlloc * 2);

    // 8. Patch the VRI key placeholder (if a DSS block was emitted).
    //    VRI key per ISO 32000-2 §12.8.4.3 = lowercase-hex SHA-1 of the
    //    signed /Contents bytes. For a DocTimeStamp these bytes are the
    //    DER TimeStampToken itself.
    if (emitDss) {
        auto tstSha1 = native_utils::sha1(tst);
        std::string vriKeyHex = native_utils::hexEncode(tstSha1, /*lowercase=*/true);
        if (vriKeyHex.size() != kVriKeyHexLen)
            throw std::runtime_error("appendDocTimeStamp: VRI key SHA-1 hex length mismatch");
        const std::size_t vriAbsoluteOffset = baseOffset + vriPlaceholderOffsetInIncr;
        if (vriAbsoluteOffset + kVriKeyHexLen > full.size())
            throw std::runtime_error("appendDocTimeStamp: VRI placeholder offset out of bounds");
        std::memcpy(full.data() + vriAbsoluteOffset, vriKeyHex.data(), kVriKeyHexLen);
    }

    // 9. Return only the new incremental block (caller appends to bltPdf).
    //    full == bltPdf + incr, so the tail starting at baseOffset is the
    //    patched incremental update.
    return std::vector<std::uint8_t>(full.begin() + static_cast<long>(baseOffset), full.end());
}

} // namespace libresign

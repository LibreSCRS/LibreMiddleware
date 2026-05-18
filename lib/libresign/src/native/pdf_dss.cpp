// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/pdf_dss.h"

#include <format>
#include <sstream>
#include <string_view>

namespace libresign {

namespace {

void appendCStr(std::vector<std::uint8_t>& out, std::string_view s)
{
    out.insert(out.end(), s.begin(), s.end());
}

void appendStreamObj(std::vector<std::uint8_t>& out, std::size_t objNum, const std::vector<std::uint8_t>& bytes)
{
    // Emit `N 0 obj << /Length L >> stream\n<bytes>\nendstream\nendobj\n`.
    // No /Filter: PDF/A permits uncompressed streams and the payloads here
    // (DER cert / CRL / OCSP) are already compact binary — avoiding Flate
    // keeps the appended block deterministic and trivially diffable for
    // the oracle smoke test downstream.
    appendCStr(out, std::format("{} 0 obj\n<< /Length {} >>\nstream\n", objNum, bytes.size()));
    out.insert(out.end(), bytes.begin(), bytes.end());
    appendCStr(out, "\nendstream\nendobj\n");
}

} // namespace

std::vector<std::uint8_t> buildDssBlock(const PdfDssMaterial& material, std::size_t firstObjNum,
                                        const std::string& sigContentsHex, std::size_t& dssObjNum)
{
    // Empty-material short-circuit: with no certs, CRLs or OCSP responses
    // the DSS dictionary would carry no validation data at all. Returning
    // an empty buffer lets the caller skip both the appended bytes and the
    // /DSS catalog entry, which is the cleanest "no LT data" outcome.
    if (material.certs.empty() && material.crls.empty() && material.ocspResponses.empty()) {
        dssObjNum = firstObjNum;
        return {};
    }

    // Contiguous object-number range:
    //   firstObjNum                     -> DSS dictionary
    //   certBase ... certBase+N-1       -> cert streams
    //   crlBase  ... crlBase+M-1        -> CRL  streams
    //   ocspBase ... ocspBase+K-1       -> OCSP streams
    dssObjNum = firstObjNum;
    const std::size_t certBase = firstObjNum + 1;
    const std::size_t crlBase = certBase + material.certs.size();
    const std::size_t ocspBase = crlBase + material.crls.size();

    std::vector<std::uint8_t> out;

    // Indirect-object streams come first; the DSS dictionary that
    // references them follows. Ordering inside an incremental update is
    // immaterial to PDF readers (xref entries point by byte offset), but
    // streams-then-dict matches the textual order in ISO 32000-2 §12.8.4.3
    // examples and keeps human inspection easier.
    for (std::size_t i = 0; i < material.certs.size(); ++i)
        appendStreamObj(out, certBase + i, material.certs[i]);
    for (std::size_t i = 0; i < material.crls.size(); ++i)
        appendStreamObj(out, crlBase + i, material.crls[i]);
    for (std::size_t i = 0; i < material.ocspResponses.size(); ++i)
        appendStreamObj(out, ocspBase + i, material.ocspResponses[i]);

    // The DSS dictionary itself.
    std::ostringstream dss;
    dss << dssObjNum << " 0 obj\n<<\n  /Type /DSS\n";

    auto emitArray = [&](const char* name, std::size_t base, std::size_t count) {
        if (count == 0)
            return;
        dss << "  /" << name << " [";
        for (std::size_t i = 0; i < count; ++i)
            dss << (base + i) << " 0 R ";
        dss << "]\n";
    };
    emitArray("Certs", certBase, material.certs.size());
    emitArray("CRLs", crlBase, material.crls.size());
    emitArray("OCSPs", ocspBase, material.ocspResponses.size());

    // VRI sub-dictionary keyed by lowercase-hex SHA-1 of the signed
    // /Contents bytes. The inner /Cert /CRL /OCSP arrays re-use the same
    // indirect references as the top-level Certs/CRLs/OCSPs entries — VRI
    // is an index into already-embedded material, not a second copy.
    dss << "  /VRI << /" << sigContentsHex << " <<\n";
    auto emitVriArray = [&](const char* name, std::size_t base, std::size_t count) {
        if (count == 0)
            return;
        dss << "    /" << name << " [";
        for (std::size_t i = 0; i < count; ++i)
            dss << (base + i) << " 0 R ";
        dss << "]\n";
    };
    emitVriArray("Cert", certBase, material.certs.size());
    emitVriArray("CRL", crlBase, material.crls.size());
    emitVriArray("OCSP", ocspBase, material.ocspResponses.size());
    dss << "  >> >>\n>>\nendobj\n";

    appendCStr(out, dss.str());

    return out;
}

} // namespace libresign

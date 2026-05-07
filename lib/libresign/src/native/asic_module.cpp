// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/asic_module.h"
#include "native/cades_module.h"
#include "native/pkcs11_token.h"
#include "native_utils.h"

#include "miniz.h"

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <functional>

namespace libresign {

namespace {

struct ScopeGuard
{
    std::function<void()> fn;
    ~ScopeGuard()
    {
        if (fn)
            fn();
    }
};

using namespace libresign::native_utils;

void appendLE16(std::vector<uint8_t>& v, uint16_t val)
{
    v.push_back(static_cast<uint8_t>(val & 0xFF));
    v.push_back(static_cast<uint8_t>(val >> 8));
}

void appendLE32(std::vector<uint8_t>& v, uint32_t val)
{
    v.push_back(static_cast<uint8_t>(val & 0xFF));
    v.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
    v.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
    v.push_back(static_cast<uint8_t>(val >> 24));
}

// Build the mimetype ZIP entry by hand — ETSI EN 319 162-1 §5.2.1 requires:
// STORED (no compression), no extra field, no data descriptor, CRC/sizes in
// the local header. miniz heap mode always uses data descriptors, so we bypass it.
std::vector<uint8_t> buildMimetypeEntry()
{
    const char* name = "mimetype";
    const char* content = "application/vnd.etsi.asic-e+zip";
    auto nameLen = static_cast<uint16_t>(std::strlen(name));
    auto contentLen = static_cast<uint32_t>(std::strlen(content));
    uint32_t crc = mz_crc32(MZ_CRC32_INIT, reinterpret_cast<const uint8_t*>(content), contentLen);

    std::vector<uint8_t> entry;
    entry.reserve(30 + nameLen + contentLen);

    // Local file header (ZIP spec APPNOTE 4.3.7)
    appendLE32(entry, 0x04034b50); // signature
    appendLE16(entry, 20);         // version needed (2.0)
    appendLE16(entry, 0);          // flags: no UTF-8, no data descriptor
    appendLE16(entry, 0);          // compression: STORED
    appendLE16(entry, 0);          // mod time
    appendLE16(entry, 0);          // mod date
    appendLE32(entry, crc);
    appendLE32(entry, contentLen); // compressed size
    appendLE32(entry, contentLen); // uncompressed size
    appendLE16(entry, nameLen);
    appendLE16(entry, 0); // extra field length

    // File name
    entry.insert(entry.end(), name, name + nameLen);
    // File data
    entry.insert(entry.end(), content, content + contentLen);

    return entry;
}

// Build mimetype central directory entry matching the local header above.
std::vector<uint8_t> buildMimetypeCDEntry()
{
    const char* name = "mimetype";
    const char* content = "application/vnd.etsi.asic-e+zip";
    auto nameLen = static_cast<uint16_t>(std::strlen(name));
    auto contentLen = static_cast<uint32_t>(std::strlen(content));
    uint32_t crc = mz_crc32(MZ_CRC32_INIT, reinterpret_cast<const uint8_t*>(content), contentLen);

    std::vector<uint8_t> entry;
    entry.reserve(46 + nameLen);

    appendLE32(entry, 0x02014b50); // central dir signature
    appendLE16(entry, 20);         // version made by
    appendLE16(entry, 20);         // version needed
    appendLE16(entry, 0);          // flags
    appendLE16(entry, 0);          // compression: STORED
    appendLE16(entry, 0);          // mod time
    appendLE16(entry, 0);          // mod date
    appendLE32(entry, crc);
    appendLE32(entry, contentLen); // compressed
    appendLE32(entry, contentLen); // uncompressed
    appendLE16(entry, nameLen);
    appendLE16(entry, 0); // extra field length
    appendLE16(entry, 0); // comment length
    appendLE16(entry, 0); // disk number
    appendLE16(entry, 0); // internal attrs
    appendLE32(entry, 0); // external attrs
    appendLE32(entry, 0); // local header offset (always 0 — first entry)

    entry.insert(entry.end(), name, name + nameLen);
    return entry;
}

// Escape XML special characters for use in attribute values.
std::string xmlEscape(const std::string& s)
{
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
        case '&':
            out += "&amp;";
            break;
        case '<':
            out += "&lt;";
            break;
        case '>':
            out += "&gt;";
            break;
        case '"':
            out += "&quot;";
            break;
        case '\'':
            out += "&apos;";
            break;
        default:
            out += c;
            break;
        }
    }
    return out;
}

// Build ETSI EN 319 162 ASiCManifest XML matching DSS 6.4 format.
std::string buildASiCManifest(const std::string& fileName, const std::vector<uint8_t>& data)
{
    std::string digest = native_utils::sha256Base64(data);
    return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
           "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">"
           "<asic:SigReference MimeType=\"application/pkcs7-signature\" "
           "URI=\"META-INF/signature001.p7s\"/>"
           "<asic:DataObjectReference URI=\"" +
           xmlEscape(fileName) +
           "\">"
           "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" "
           "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>"
           "<ds:DigestValue xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
           digest +
           "</ds:DigestValue>"
           "</asic:DataObjectReference>"
           "</asic:ASiCManifest>";
}

} // namespace

SigningResult ASiCModule::signWithCAdES(const std::vector<uint8_t>& data, const std::string& fileName,
                                        Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa)
{
    // 1. Build ASiCManifest (contains document digest)
    std::string asicManifest = buildASiCManifest(fileName, data);
    std::vector<uint8_t> manifestBytes(asicManifest.begin(), asicManifest.end());

    // 2. Create CAdES detached signature over the ASiCManifest (NOT the document).
    //    Per ETSI EN 319 162-1, the CAdES signature covers the manifest which
    //    in turn references the document with its own digest.
    CAdESModule cades;
    auto cadesResult = cades.sign(manifestBytes, token, level, tsa);
    if (!cadesResult.success)
        return cadesResult;

    // 3. Build the mimetype entry by hand (ASiC compliance)
    auto mimetypeEntry = buildMimetypeEntry();
    auto mimetypeCDEntry = buildMimetypeCDEntry();
    auto mimetypeLocalSize = static_cast<uint32_t>(mimetypeEntry.size());

    // 4. Use miniz for remaining entries (document + signature)
    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    if (!mz_zip_writer_init_heap(&zip, 0, 0))
        return {false, {}, "Failed to initialize ZIP writer"};

    ScopeGuard zipGuard{[&zip] { mz_zip_writer_end(&zip); }};

    // Defense in depth: callers (LibreCelik) already pass QFileInfo::fileName()
    // which strips path components, but enforce here too so the library is
    // robust against direct callers. A path component in a ZIP entry would
    // bite anyone extracting the ASiC archive (zip-slip). NUL bytes are also
    // rejected — std::string can hold them, and miniz would silently
    // truncate the entry name at the first NUL.
    if (fileName.empty() || fileName.find('/') != std::string::npos || fileName.find('\\') != std::string::npos ||
        fileName.find('\0') != std::string::npos || fileName.find("..") != std::string::npos) {
        return {false, {}, "Invalid filename for ASiC entry"};
    }

    if (!mz_zip_writer_add_mem(&zip, fileName.c_str(), data.data(), data.size(), MZ_DEFAULT_COMPRESSION))
        return {false, {}, "Failed to add document entry"};

    if (!mz_zip_writer_add_mem(&zip, "META-INF/signature001.p7s", cadesResult.signedDocument.data(),
                               cadesResult.signedDocument.size(), MZ_DEFAULT_COMPRESSION))
        return {false, {}, "Failed to add signature entry"};

    if (!mz_zip_writer_add_mem(&zip, "META-INF/ASiCManifest001.xml", asicManifest.c_str(), asicManifest.size(),
                               MZ_DEFAULT_COMPRESSION))
        return {false, {}, "Failed to add ASiC manifest entry"};

    void* buf = nullptr;
    size_t bufSize = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &buf, &bufSize))
        return {false, {}, "Failed to finalize ZIP archive"};

    // 5. Assemble final archive: hand-built mimetype + miniz entries (with adjusted offsets)
    ScopeGuard bufGuard{[&buf] {
        if (buf)
            mz_free(buf);
    }};
    auto minizData = std::span(static_cast<const uint8_t*>(buf), bufSize);

    // Parse miniz output to find central directory location.
    // EOCD is at the end: scan backwards for PK\x05\x06.
    if (bufSize < 22)
        return {false, {}, "ASiC-E: archive too small for EOCD"};
    size_t eocdOff = 0;
    bool eocdFound = false;
    // Scan from (bufSize - 22) down to 0 inclusive. Use signed loop to avoid
    // size_t underflow at i == 0.
    for (ptrdiff_t i = static_cast<ptrdiff_t>(bufSize) - 22; i >= 0; --i) {
        if (minizData[i] == 0x50 && minizData[i + 1] == 0x4B && minizData[i + 2] == 0x05 && minizData[i + 3] == 0x06) {
            eocdOff = static_cast<size_t>(i);
            eocdFound = true;
            break;
        }
    }
    if (!eocdFound)
        return {false, {}, "ASiC-E: EOCD record not found in archive"};

    // Read EOCD fields
    uint16_t cdEntries =
        static_cast<uint16_t>(minizData[eocdOff + 10]) | static_cast<uint16_t>(minizData[eocdOff + 11] << 8);
    uint32_t cdSize =
        static_cast<uint32_t>(minizData[eocdOff + 12]) | (static_cast<uint32_t>(minizData[eocdOff + 13]) << 8) |
        (static_cast<uint32_t>(minizData[eocdOff + 14]) << 16) | (static_cast<uint32_t>(minizData[eocdOff + 15]) << 24);
    uint32_t cdOff =
        static_cast<uint32_t>(minizData[eocdOff + 16]) | (static_cast<uint32_t>(minizData[eocdOff + 17]) << 8) |
        (static_cast<uint32_t>(minizData[eocdOff + 18]) << 16) | (static_cast<uint32_t>(minizData[eocdOff + 19]) << 24);

    // Bounds-check cdOff + cdSize against the archive size before subspan.
    // miniz output is trusted, but a defensive check costs nothing and
    // prevents a subspan out-of-range throw (or UB in release) if miniz
    // ever produces a malformed archive or if this path accepts
    // attacker-supplied ZIPs in the future.
    if (cdOff > bufSize || cdSize > bufSize - cdOff)
        return {false, {}, "ASiC-E: malformed EOCD (cdOff/cdSize exceed archive size)"};

    // Local file entries from miniz (before central directory)
    auto localEntries = minizData.subspan(0, cdOff);
    // Central directory entries from miniz
    auto cdEntryData = minizData.subspan(cdOff, cdSize);

    // Build result: mimetype local + miniz locals (offset-shifted) + mimetype CD +
    //               miniz CD (offset-shifted) + new EOCD
    std::vector<uint8_t> result;
    result.reserve(mimetypeEntry.size() + localEntries.size() + mimetypeCDEntry.size() + cdEntryData.size() + 22);

    // A. Mimetype local file entry
    result.insert(result.end(), mimetypeEntry.begin(), mimetypeEntry.end());

    // B. Miniz local file entries (shifted by mimetypeLocalSize)
    result.insert(result.end(), localEntries.begin(), localEntries.end());

    // C. Central directory: mimetype first
    auto newCdOff = static_cast<uint32_t>(result.size());
    result.insert(result.end(), mimetypeCDEntry.begin(), mimetypeCDEntry.end());

    // D. Miniz central directory entries — adjust local header offsets by +mimetypeLocalSize
    for (size_t i = 0; i < cdSize;) {
        if (i + 46 > cdSize)
            break;
        // Read filename length, extra length, comment length to compute entry size
        uint16_t fnLen = static_cast<uint16_t>(cdEntryData[i + 28]) | static_cast<uint16_t>(cdEntryData[i + 29] << 8);
        uint16_t exLen = static_cast<uint16_t>(cdEntryData[i + 30]) | static_cast<uint16_t>(cdEntryData[i + 31] << 8);
        uint16_t cmLen = static_cast<uint16_t>(cdEntryData[i + 32]) | static_cast<uint16_t>(cdEntryData[i + 33] << 8);
        size_t entrySize = 46 + fnLen + exLen + cmLen;
        // Defensive: cdEntryData is generated by miniz so this should always
        // hold, but a malformed buffer would otherwise let us read past the
        // end of the span. Stop walking and emit whatever we already copied.
        if (i + entrySize > cdSize)
            break;

        // Copy the entry
        size_t insertPos = result.size();
        result.insert(result.end(), cdEntryData.begin() + static_cast<ptrdiff_t>(i),
                      cdEntryData.begin() + static_cast<ptrdiff_t>(i + entrySize));

        // Patch local header offset at +42 from entry start
        size_t offPos = insertPos + 42;
        uint32_t lhOff = static_cast<uint32_t>(result[offPos]) | (static_cast<uint32_t>(result[offPos + 1]) << 8) |
                         (static_cast<uint32_t>(result[offPos + 2]) << 16) |
                         (static_cast<uint32_t>(result[offPos + 3]) << 24);
        lhOff += mimetypeLocalSize;
        result[offPos] = static_cast<uint8_t>(lhOff & 0xFF);
        result[offPos + 1] = static_cast<uint8_t>((lhOff >> 8) & 0xFF);
        result[offPos + 2] = static_cast<uint8_t>((lhOff >> 16) & 0xFF);
        result[offPos + 3] = static_cast<uint8_t>(lhOff >> 24);

        i += entrySize;
    }

    // E. End of central directory record. The ZIP EOCD stores CD size /
    // offset as 32-bit. Archives > 4 GiB would require ZIP64, which we do
    // not emit — refuse loudly instead of silently truncating and writing
    // a corrupt archive that later tools will misread.
    const size_t newCdSizeBytes = result.size() - newCdOff;
    if (newCdSizeBytes > UINT32_MAX || newCdOff > UINT32_MAX)
        return {false, {}, "ASiC-E: archive exceeds 4 GiB (ZIP64 not supported)"};
    const auto newCdSize = static_cast<uint32_t>(newCdSizeBytes);
    const auto newCdOff32 = static_cast<uint32_t>(newCdOff);
    uint16_t totalEntries = cdEntries + 1; // add mimetype
    appendLE32(result, 0x06054b50);        // EOCD signature
    appendLE16(result, 0);                 // disk number
    appendLE16(result, 0);                 // disk with CD
    appendLE16(result, totalEntries);
    appendLE16(result, totalEntries);
    appendLE32(result, newCdSize);
    appendLE32(result, newCdOff32);
    appendLE16(result, 0); // comment length

    return {true, std::move(result), {}};
}

} // namespace libresign

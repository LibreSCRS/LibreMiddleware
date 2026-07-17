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
#include <charconv>
#include <cstdio>
#include <cstring>
#include <functional>
#include <optional>
#include <string_view>
#include <system_error>
#include <utility>

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

// ASiC URI attributes carry directory paths inside the ZIP, so '/' must
// pass through verbatim. Delegates to native_utils::percentEncode with
// preserveSlash=true.

// Build ETSI EN 319 162 ASiCManifest XML matching DSS 6.4 format. The
// SigReference URI points to the matching signature entry — multi-sign
// flows pass "META-INF/signatureNNN.p7s" with NNN > 001.
std::string buildASiCManifest(const std::string& fileName, const std::vector<uint8_t>& data,
                              const std::string& sigEntryName)
{
    std::string digest = native_utils::sha256Base64(data);
    // URI attributes carry the percent-encoded form (RFC 3986); the result
    // is then XML-escaped, which is a no-op on percent-encoded text since
    // all bytes after percent-encoding are unreserved URI characters.
    return "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>"
           "<asic:ASiCManifest xmlns:asic=\"http://uri.etsi.org/02918/v1.2.1#\">"
           "<asic:SigReference MimeType=\"application/pkcs7-signature\" "
           "URI=\"" +
           percentEncode(sigEntryName, true) +
           "\"/>"
           "<asic:DataObjectReference URI=\"" +
           percentEncode(fileName, true) +
           "\">"
           "<ds:DigestMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#sha256\" "
           "xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"/>"
           "<ds:DigestValue xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\">" +
           digest +
           "</ds:DigestValue>"
           "</asic:DataObjectReference>"
           "</asic:ASiCManifest>";
}

// ---- ASiC-E multi-sign parsing ----
//
// ETSI EN 319 162-1 §A.4 parallel-sequential multi-sign: existing ASiC-E
// containers carry one or more signatureNNN.p7s + ASiCManifestNNN.xml pairs
// under META-INF/. Adding a signature means writing a NEW pair with the next
// free NNN into the SAME container, leaving every prior entry byte-for-byte
// intact and signing the SAME data file every prior signer already signed.

struct AsicEntry
{
    std::string name;
    std::vector<uint8_t> data;
};

struct ParsedAsic
{
    std::string dataFileName;             // first non-META-INF, non-mimetype entry
    std::vector<uint8_t> dataFileBytes;   // its content
    std::vector<AsicEntry> preservedMeta; // every META-INF/* entry (sigs + manifests + anything else)
    int nextSigNum = 1;                   // max existing signatureNNN/ASiCManifestNNN + 1
};

// Resource caps for tryParseAsic — defend against zip-bomb / heap-exhaustion
// inputs reachable on every re-sign request via attacker-supplied ASiC
// candidates. Numbers picked to comfortably hold realistic multi-signer
// documents (a typical signed PDF + a handful of CAdES sigs fits in well
// under 64 MiB per entry / 256 MiB total) while rejecting central-directory
// bombs that declare GiB-scale uncompressed sizes from KB-scale inputs.
inline constexpr mz_uint kMaxAsicEntries = 1024;
inline constexpr size_t kMaxAsicEntrySize = 64ULL * 1024 * 1024;   // 64 MiB
inline constexpr size_t kMaxAsicTotalBytes = 256ULL * 1024 * 1024; // 256 MiB
inline constexpr size_t kMaxAsicEntryNameLen = 1024;

// Validate a ZIP entry name against zip-slip / NUL / backslash / "..".
// Used both for the data file (writer-side, single entry from the caller)
// and for every preserved META-INF entry (reader-side, attacker-controlled
// in multi-sign mode). Returning a single helper keeps the validation
// surface consistent — drift here is a security-class change.
bool isValidAsicEntryName(std::string_view name)
{
    if (name.empty() || name.size() > kMaxAsicEntryNameLen)
        return false;
    if (name.find('/') != std::string_view::npos && name.starts_with("META-INF/")) {
        // Allowed: META-INF/<name> with at most that one slash and no traversal
        if (name.find('/', std::string_view("META-INF/").size()) != std::string_view::npos)
            return false;
    } else if (name.find('/') != std::string_view::npos) {
        // Non-META-INF entries must not contain slashes
        return false;
    }
    return name.find('\\') == std::string_view::npos && name.find('\0') == std::string_view::npos &&
           name.find("..") == std::string_view::npos;
}

// Returns a ParsedAsic when @p data is a well-formed ASiC-E container with
// exactly one data file and at least one prior signature/manifest pair.
// Returns nullopt for anything else (non-ZIP input, ZIP with the wrong
// mimetype, ZIP with zero or multiple data files, mimetype-only ZIP,
// entries failing zip-slip / size-cap validation) — the caller then
// falls back to the fresh single-sign path.
std::optional<ParsedAsic> tryParseAsic(const std::vector<uint8_t>& data)
{
    if (data.size() < 30 || data[0] != 'P' || data[1] != 'K' || data[2] != 0x03 || data[3] != 0x04)
        return std::nullopt;

    mz_zip_archive zip;
    std::memset(&zip, 0, sizeof(zip));
    if (!mz_zip_reader_init_mem(&zip, data.data(), data.size(), 0))
        return std::nullopt;
    ScopeGuard zg{[&zip] { mz_zip_reader_end(&zip); }};

    const mz_uint n = mz_zip_reader_get_num_files(&zip);
    if (n > kMaxAsicEntries)
        return std::nullopt;

    int mtIdx = mz_zip_reader_locate_file(&zip, "mimetype", nullptr, 0);
    if (mtIdx < 0)
        return std::nullopt;
    {
        size_t mtSize = 0;
        void* mtBuf = mz_zip_reader_extract_to_heap(&zip, static_cast<mz_uint>(mtIdx), &mtSize, 0);
        if (!mtBuf)
            return std::nullopt;
        std::string mtContent(static_cast<char*>(mtBuf), mtSize);
        mz_free(mtBuf);
        if (mtContent != "application/vnd.etsi.asic-e+zip")
            return std::nullopt;
    }

    ParsedAsic parsed;
    int dataFilesFound = 0;
    int maxSigNum = 0;
    size_t totalExtracted = 0;
    for (mz_uint i = 0; i < n; ++i) {
        mz_zip_archive_file_stat st;
        if (!mz_zip_reader_file_stat(&zip, i, &st))
            return std::nullopt;
        std::string name(st.m_filename);
        if (name == "mimetype")
            continue;

        // Validate name BEFORE allocating: zip-slip / NUL / backslash / "..".
        // Reject anything that would write outside the archive root or
        // smuggle a non-META-INF entry through the preserved-bag path.
        if (!isValidAsicEntryName(name))
            return std::nullopt;

        // Cap declared uncompressed size before allocating heap for it,
        // and refuse if the running total exceeds the budget. m_uncomp_size
        // is attacker-controlled (it's read straight from the central
        // directory) — without the cap a 1 KB malicious candidate can
        // declare GiB-scale entries and OOM the signing service.
        if (st.m_uncomp_size > kMaxAsicEntrySize)
            return std::nullopt;
        if (st.m_uncomp_size > kMaxAsicTotalBytes - totalExtracted)
            return std::nullopt;

        size_t sz = 0;
        void* buf = mz_zip_reader_extract_to_heap(&zip, i, &sz, 0);
        if (!buf)
            return std::nullopt;
        // Re-check actual extracted size against the cap — miniz could in
        // principle decompress to more than m_uncomp_size declared.
        if (sz > kMaxAsicEntrySize || sz > kMaxAsicTotalBytes - totalExtracted) {
            mz_free(buf);
            return std::nullopt;
        }
        std::vector<uint8_t> bytes(static_cast<uint8_t*>(buf), static_cast<uint8_t*>(buf) + sz);
        mz_free(buf);
        totalExtracted += sz;

        constexpr std::string_view kMetaPrefix = "META-INF/";
        constexpr std::string_view kSigPrefix = "META-INF/signature";
        constexpr std::string_view kManifestPrefix = "META-INF/ASiCManifest";

        if (std::string_view(name).starts_with(kMetaPrefix)) {
            // Scan for "signatureNNN.p7s" or "ASiCManifestNNN.xml" — these
            // carry the NNN we need to advance past. Other META-INF entries
            // (e.g. manifest.xml from an ODF wrapper) are preserved as-is.
            std::string_view numPart;
            if (std::string_view(name).starts_with(kSigPrefix) && std::string_view(name).ends_with(".p7s")) {
                numPart = std::string_view(name).substr(kSigPrefix.size());
                numPart.remove_suffix(4);
            } else if (std::string_view(name).starts_with(kManifestPrefix) &&
                       std::string_view(name).ends_with(".xml")) {
                numPart = std::string_view(name).substr(kManifestPrefix.size());
                numPart.remove_suffix(4);
            }
            if (!numPart.empty()) {
                int v = 0;
                auto [p, ec] = std::from_chars(numPart.data(), numPart.data() + numPart.size(), v);
                if (ec == std::errc{} && p == numPart.data() + numPart.size() && v > maxSigNum)
                    maxSigNum = v;
            }
            parsed.preservedMeta.push_back({std::move(name), std::move(bytes)});
        } else {
            if (++dataFilesFound > 1)
                return std::nullopt; // multi-data ASiC out of scope for re-sign
            parsed.dataFileName = std::move(name);
            parsed.dataFileBytes = std::move(bytes);
        }
    }
    if (dataFilesFound != 1 || parsed.preservedMeta.empty())
        return std::nullopt;
    parsed.nextSigNum = maxSigNum + 1;
    return parsed;
}

// Format the three-digit sig number suffix used in entry names (signatureNNN /
// ASiCManifestNNN). Matches the convention DSS / ETSI test bench expect.
std::string formatSigSuffix(int n)
{
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%03d", n);
    return std::string(buf);
}

} // namespace

SigningResult ASiCModule::signWithCAdES(const std::vector<uint8_t>& data, const std::string& fileName,
                                        Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa)
{
    // ---- Multi-sign branch (ETSI EN 319 162-1 §A.4) ----
    //
    // When the input is itself an ASiC-E container, we add a new signature
    // alongside the existing ones rather than wrapping the prior ZIP as a
    // fresh data file. The data being signed must be the SAME bytes every
    // prior signer signed — read those from the existing container, ignore
    // the caller's data/fileName, and emit signature{maxNNN+1}.p7s with a
    // matching ASiCManifest{maxNNN+1}.xml in the SAME ZIP.
    std::optional<ParsedAsic> prior = tryParseAsic(data);

    // ETSI EN 319 162-1 §A.4 covers re-signing only when the prior container
    // holds exactly one data file. If the input is a recognisably ASiC-E
    // container (mimetype matches) but tryParseAsic rejected it for carrying
    // multiple data files at the root, reject explicitly with a diagnostic
    // that names the violation instead of silently falling through to the
    // fresh-sign branch (which would wrap the whole prior zip as a new
    // generic data file — confusing for both callers and downstream
    // validators). Recognition uses the same "mimetype entry contains the
    // ETSI MIME literal" gate the parser uses, so non-ASiC inputs (PDFs,
    // generic blobs) keep falling through to fresh-sign as before.
    if (!prior) {
        mz_zip_archive probe;
        std::memset(&probe, 0, sizeof(probe));
        if (mz_zip_reader_init_mem(&probe, data.data(), data.size(), 0)) {
            ScopeGuard pg{[&probe] { mz_zip_reader_end(&probe); }};
            int mtIdx = mz_zip_reader_locate_file(&probe, "mimetype", nullptr, 0);
            if (mtIdx >= 0) {
                size_t mtSize = 0;
                void* mtBuf = mz_zip_reader_extract_to_heap(&probe, static_cast<mz_uint>(mtIdx), &mtSize, 0);
                if (mtBuf) {
                    std::string mt(static_cast<char*>(mtBuf), mtSize);
                    mz_free(mtBuf);
                    if (mt == "application/vnd.etsi.asic-e+zip") {
                        int rootDataFiles = 0;
                        const mz_uint pn = mz_zip_reader_get_num_files(&probe);
                        for (mz_uint i = 0; i < pn; ++i) {
                            mz_zip_archive_file_stat ps;
                            if (!mz_zip_reader_file_stat(&probe, i, &ps))
                                break;
                            std::string nm(ps.m_filename);
                            if (nm == "mimetype")
                                continue;
                            if (std::string_view(nm).starts_with("META-INF/"))
                                continue;
                            ++rootDataFiles;
                        }
                        if (rootDataFiles > 1)
                            return makeFailure(SignFailureKind::InvalidDocument,
                                               "ASiC-E re-sign rejects containers with multiple root data files (ETSI "
                                               "EN 319 162-1 §A.4 supports only one data file per container)");
                    }
                }
            }
        }
    }

    const std::string realFileName = prior ? prior->dataFileName : fileName;
    const std::vector<uint8_t>& realData = prior ? prior->dataFileBytes : data;
    const int sigNum = prior ? prior->nextSigNum : 1;

    const std::string sigSuffix = formatSigSuffix(sigNum);
    const std::string sigEntryName = "META-INF/signature" + sigSuffix + ".p7s";
    const std::string manifestEntryName = "META-INF/ASiCManifest" + sigSuffix + ".xml";

    // 1. Build ASiCManifest (contains document digest)
    std::string asicManifest = buildASiCManifest(realFileName, realData, sigEntryName);
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
        return makeFailure(SignFailureKind::ZipBuildError, "Failed to initialize ZIP writer");

    ScopeGuard zipGuard{[&zip] { mz_zip_writer_end(&zip); }};

    // Defense in depth: callers (LibreCelik) already pass QFileInfo::fileName()
    // which strips path components, but enforce here too so the library is
    // robust against direct callers. Shared zip-slip / NUL / backslash /
    // ".." rejection lives in `isValidAsicEntryName` — both the reader
    // (multi-sign preserved entries) and the writer go through the same
    // helper so drift here is a security-class change.
    if (!isValidAsicEntryName(realFileName))
        return makeFailure(SignFailureKind::InvalidInput, "Invalid filename for ASiC entry");

    if (!mz_zip_writer_add_mem(&zip, realFileName.c_str(), realData.data(), realData.size(), MZ_DEFAULT_COMPRESSION))
        return makeFailure(SignFailureKind::ZipBuildError, "Failed to add document entry");

    // Multi-sign: preserve every prior META-INF entry (signatures + manifests
    // + anything else) byte-for-byte BEFORE writing the new pair, so the
    // ordering inside the central directory remains stable across re-signs.
    if (prior) {
        for (const auto& e : prior->preservedMeta) {
            if (!mz_zip_writer_add_mem(&zip, e.name.c_str(), e.data.data(), e.data.size(), MZ_DEFAULT_COMPRESSION))
                return makeFailure(SignFailureKind::ZipBuildError, "Failed to copy prior META-INF entry: " + e.name);
        }
    }

    if (!mz_zip_writer_add_mem(&zip, sigEntryName.c_str(), cadesResult.signedDocument.data(),
                               cadesResult.signedDocument.size(), MZ_DEFAULT_COMPRESSION))
        return makeFailure(SignFailureKind::ZipBuildError, "Failed to add signature entry");

    if (!mz_zip_writer_add_mem(&zip, manifestEntryName.c_str(), asicManifest.c_str(), asicManifest.size(),
                               MZ_DEFAULT_COMPRESSION))
        return makeFailure(SignFailureKind::ZipBuildError, "Failed to add ASiC manifest entry");

    void* buf = nullptr;
    size_t bufSize = 0;
    if (!mz_zip_writer_finalize_heap_archive(&zip, &buf, &bufSize))
        return makeFailure(SignFailureKind::ZipBuildError, "Failed to finalize ZIP archive");

    // 5. Assemble final archive: hand-built mimetype + miniz entries (with adjusted offsets)
    ScopeGuard bufGuard{[&buf] {
        if (buf)
            mz_free(buf);
    }};
    auto minizData = std::span(static_cast<const uint8_t*>(buf), bufSize);

    // Parse miniz output to find central directory location.
    // EOCD is at the end: scan backwards for PK\x05\x06.
    if (bufSize < 22)
        return makeFailure(SignFailureKind::ZipBuildError, "ASiC-E: archive too small for EOCD");
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
        return makeFailure(SignFailureKind::ZipBuildError, "ASiC-E: EOCD record not found in archive");

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
        return makeFailure(SignFailureKind::ZipBuildError, "ASiC-E: malformed EOCD (cdOff/cdSize exceed archive size)");

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
        return makeFailure(SignFailureKind::ZipBuildError, "ASiC-E: archive exceeds 4 GiB (ZIP64 not supported)");
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

    return makeSuccess(std::move(result));
}

SigningResult ASiCModule::appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                       Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa)
{
    if (prior.empty())
        return makeFailure(SignFailureKind::InvalidDocument, "ASiC-E appendSigner: empty prior container");

    // ETSI EN 319 162-1 §A.4: signWithCAdES already detects an ASiC-E prior
    // via tryParseAsic, then appends signature{maxNNN+1}.p7s + matching
    // ASiCManifest{maxNNN+1}.xml to the same container while preserving every
    // prior META-INF entry byte-for-byte and signing the same data file the
    // prior signers signed. The fileName argument is ignored on that path
    // (overridden from the parsed container).
    //
    // originalDoc is currently informational only — the new signer signs
    // whatever bytes are in the container's data file.
    (void)originalDoc;
    return signWithCAdES(std::vector<uint8_t>(prior.begin(), prior.end()), std::string(), token, level, tsa);
}

} // namespace libresign

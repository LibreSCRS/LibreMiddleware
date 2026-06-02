// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native_utils.h"

#include "native/pkcs11_token.h"
#include "native/revocation_client.h"
#include "types.h"

#include <miniz.h>

#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <libxml/parser.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <format>
#include <limits>
#include <mutex>
#include <span>
#include <stdexcept>

namespace libresign::native_utils {

void ensureXmlInitialized()
{
    static std::once_flag flag;
    std::call_once(flag, [] { xmlInitParser(); });
}

std::string opensslError()
{
    std::string result;
    char buf[256];
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        ERR_error_string_n(err, buf, sizeof(buf));
        if (!result.empty())
            result += "; ";
        result += buf;
    }
    return result.empty() ? "unknown OpenSSL error" : result;
}

// ---- SHA-1 ----

std::vector<uint8_t> sha1(const uint8_t* data, size_t len)
{
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha1()));
    unsigned int hashLen = 0;
    if (!EVP_Digest(data, len, hash.data(), &hashLen, EVP_sha1(), nullptr))
        throw std::runtime_error("EVP_Digest SHA-1 failed: " + opensslError());
    hash.resize(hashLen);
    return hash;
}

std::vector<uint8_t> sha1(const std::vector<uint8_t>& data)
{
    return sha1(data.data(), data.size());
}

std::vector<uint8_t> sha1(const std::string& data)
{
    return sha1(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ---- SHA-256 ----

std::vector<uint8_t> sha256(const uint8_t* data, size_t len)
{
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha256()));
    unsigned int hashLen = 0;
    if (!EVP_Digest(data, len, hash.data(), &hashLen, EVP_sha256(), nullptr))
        throw std::runtime_error("EVP_Digest SHA-256 failed: " + opensslError());
    hash.resize(hashLen);
    return hash;
}

std::vector<uint8_t> sha256(const std::vector<uint8_t>& data)
{
    return sha256(data.data(), data.size());
}

std::vector<uint8_t> sha256(const std::string& data)
{
    return sha256(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ---- SHA-384 ----

std::vector<uint8_t> sha384(const uint8_t* data, size_t len)
{
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha384()));
    unsigned int hashLen = 0;
    if (!EVP_Digest(data, len, hash.data(), &hashLen, EVP_sha384(), nullptr))
        throw std::runtime_error("EVP_Digest SHA-384 failed: " + opensslError());
    hash.resize(hashLen);
    return hash;
}

std::vector<uint8_t> sha384(const std::string& data)
{
    return sha384(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ---- SHA-512 ----

std::vector<uint8_t> sha512(const uint8_t* data, size_t len)
{
    std::vector<uint8_t> hash(EVP_MD_size(EVP_sha512()));
    unsigned int hashLen = 0;
    if (!EVP_Digest(data, len, hash.data(), &hashLen, EVP_sha512(), nullptr))
        throw std::runtime_error("EVP_Digest SHA-512 failed: " + opensslError());
    hash.resize(hashLen);
    return hash;
}

std::vector<uint8_t> sha512(const std::string& data)
{
    return sha512(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

// ---- Base64 encoding ----

std::string base64Encode(const uint8_t* data, size_t len)
{
    if (len == 0 || data == nullptr)
        return {};

    // BioPtr's deleter is BIO_free (single-BIO), so the mem BIO pushed
    // onto the b64 chain would leak if we relied on BioPtr. Use a local
    // RAII wrapper that calls BIO_free_all to walk and free the entire
    // chain. Since base64Encode runs dozens of times per signature (certs,
    // hashes, CRLs, OCSP, TSA token), the leak was non-trivial.
    struct ChainFree
    {
        void operator()(BIO* p) const
        {
            BIO_free_all(p);
        }
    };
    std::unique_ptr<BIO, ChainFree> chain(BIO_new(BIO_f_base64()));
    if (!chain)
        throw std::runtime_error("BIO_new(f_base64) failed: " + opensslError());
    BIO* mem = BIO_new(BIO_s_mem());
    if (!mem)
        throw std::runtime_error("BIO_new(s_mem) failed: " + opensslError());
    BIO_push(chain.get(), mem); // chain now owns mem
    BIO_set_flags(chain.get(), BIO_FLAGS_BASE64_NO_NL);
    if (BIO_write(chain.get(), data, static_cast<int>(len)) <= 0)
        throw std::runtime_error("BIO_write failed: " + opensslError());
    BIO_flush(chain.get());

    BUF_MEM* bufMem = nullptr;
    BIO_get_mem_ptr(chain.get(), &bufMem);
    return {bufMem->data, bufMem->length};
}

std::string base64Encode(const std::vector<uint8_t>& data)
{
    return base64Encode(data.data(), data.size());
}

std::vector<uint8_t> base64Decode(const std::string& input)
{
    // Strip whitespace
    std::string cleaned;
    cleaned.reserve(input.size());
    for (char c : input) {
        if (!std::isspace(static_cast<unsigned char>(c)))
            cleaned += c;
    }
    if (cleaned.empty())
        return {};

    // Add padding if needed
    while (cleaned.size() % 4 != 0)
        cleaned += '=';

    if (cleaned.size() > static_cast<size_t>(INT_MAX))
        return {};

    // Use chain-freeing RAII wrapper (same pattern as base64Encode)
    struct ChainFree
    {
        void operator()(BIO* p) const
        {
            BIO_free_all(p);
        }
    };

    BIO* b64 = BIO_new(BIO_f_base64());
    if (!b64)
        return {};
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    BIO* bmem = BIO_new_mem_buf(cleaned.data(), static_cast<int>(cleaned.size()));
    if (!bmem) {
        BIO_free_all(b64);
        return {};
    }
    std::unique_ptr<BIO, ChainFree> chain(BIO_push(b64, bmem));

    std::vector<uint8_t> result(cleaned.size()); // Overallocate, decoded is always smaller
    int len = BIO_read(chain.get(), result.data(), static_cast<int>(result.size()));

    if (len <= 0)
        return {};
    result.resize(static_cast<size_t>(len));
    return result;
}

std::string sha256Base64(const std::vector<uint8_t>& data)
{
    // Composed from the two primitives above — avoids hand-rolled BIO
    // lifetimes and the raw-pointer cleanup path that previously shipped
    // here. Both helpers throw on error, so any SHA-256 or encoding
    // failure still surfaces.
    return base64Encode(sha256(data));
}

// ---- Base64url (RFC 4648 §5) ----

std::string base64urlEncode(const std::vector<uint8_t>& data)
{
    std::string b64 = base64Encode(data);
    for (char& c : b64) {
        if (c == '+')
            c = '-';
        else if (c == '/')
            c = '_';
    }
    while (!b64.empty() && b64.back() == '=')
        b64.pop_back();
    return b64;
}

std::string base64urlEncode(std::string_view str)
{
    return base64urlEncode(std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(str.data()),
                                                reinterpret_cast<const uint8_t*>(str.data()) + str.size()));
}

std::vector<uint8_t> base64urlDecode(const std::string& input)
{
    std::string b64 = input;
    for (char& c : b64) {
        if (c == '-')
            c = '+';
        else if (c == '_')
            c = '/';
    }
    while (b64.size() % 4 != 0)
        b64.push_back('=');
    return base64Decode(b64);
}

// ---- Hex / percent encoding ----

std::string hexEncode(std::span<const uint8_t> data)
{
    std::string out;
    out.reserve(data.size() * 2);
    for (uint8_t b : data) {
        out.push_back(kHexChars[(b >> 4) & 0x0F]);
        out.push_back(kHexChars[b & 0x0F]);
    }
    return out;
}

std::string percentEncode(std::string_view in, bool preserveSlash)
{
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved || (preserveSlash && c == '/')) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(kHexChars[c >> 4]);
            out.push_back(kHexChars[c & 0x0F]);
        }
    }
    return out;
}

// ---- Certificate parsing ----

X509Ptr parseCert(const std::vector<uint8_t>& der)
{
    if (der.size() > static_cast<size_t>(LONG_MAX))
        throw std::runtime_error("certificate DER too large");
    const unsigned char* p = der.data();
    X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (!cert)
        throw std::runtime_error("d2i_X509() failed: " + opensslError());
    return cert;
}

// ---- UTC time decomposition ----

UtcTimeParts utcNow()
{
    auto now = std::chrono::system_clock::now();
    auto dp = std::chrono::floor<std::chrono::days>(now);
    std::chrono::year_month_day ymd{dp};
    std::chrono::hh_mm_ss hms{std::chrono::floor<std::chrono::seconds>(now - dp)};
    return {
        .year = static_cast<int>(ymd.year()),
        .month = static_cast<unsigned>(ymd.month()),
        .day = static_cast<unsigned>(ymd.day()),
        .hour = static_cast<int>(hms.hours().count()),
        .min = static_cast<int>(hms.minutes().count()),
        .sec = static_cast<int>(hms.seconds().count()),
    };
}

// ---- ISO 8601 UTC timestamp ----

std::string iso8601Now()
{
    auto t = utcNow();
    return std::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", t.year, t.month, t.day, t.hour, t.min, t.sec);
}

// ---- MIME type from file extension ----

std::string mimeTypeFromFileName(const std::string& fileName)
{
    auto dot = fileName.rfind('.');
    if (dot != std::string::npos) {
        std::string ext = fileName.substr(dot + 1);
        for (char& c : ext)
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (ext == "pdf")
            return "application/pdf";
        if (ext == "xml")
            return "text/xml";
        if (ext == "txt")
            return "text/plain";
        if (ext == "html" || ext == "htm")
            return "text/html";
        if (ext == "png")
            return "image/png";
        if (ext == "jpg" || ext == "jpeg")
            return "image/jpeg";
        if (ext == "doc")
            return "application/msword";
        if (ext == "docx")
            return "application/vnd.openxmlformats-officedocument.wordprocessingml.document";
    }
    return "application/octet-stream";
}

// ---- Case-insensitive string equality ----

namespace {
bool iequals(const std::string& a, const char* b)
{
    size_t len = std::strlen(b);
    if (a.size() != len)
        return false;
    for (size_t i = 0; i < len; ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}
} // namespace

// ---- SHA family detection shared by DigestInfo + token algorithm ----
//
// OpenSSL, Java, and PKCS#11 use different spellings for the same hash.
// Normalize once here so digestInfoPrefixForAlgo + tokenAlgorithm + any
// future caller agree on the SHA family. Returns 1/256/384/512, or 0 for
// unknown.
namespace {
int shaFamilyId(const std::string& mdName)
{
    if (iequals(mdName, "SHA2-256") || iequals(mdName, "SHA-256") || iequals(mdName, "SHA256"))
        return 256;
    if (iequals(mdName, "SHA2-384") || iequals(mdName, "SHA-384") || iequals(mdName, "SHA384"))
        return 384;
    if (iequals(mdName, "SHA2-512") || iequals(mdName, "SHA-512") || iequals(mdName, "SHA512"))
        return 512;
    if (iequals(mdName, "SHA1") || iequals(mdName, "SHA-1"))
        return 1;
    return 0;
}
} // namespace

// ---- DigestInfo prefix lookup ----

std::span<const uint8_t> digestInfoPrefixForAlgo(const std::string& mdName)
{
    switch (shaFamilyId(mdName)) {
    case 256:
        return kDigestInfoSha256Prefix;
    case 384:
        return kDigestInfoSha384Prefix;
    case 512:
        return kDigestInfoSha512Prefix;
    case 1:
        return kDigestInfoSha1Prefix;
    default:
        return {};
    }
}

// ---- Token algorithm string from key type + digest ----

std::string tokenAlgorithm(int keyType, const std::string& mdName)
{
    const bool isEc = (keyType == EVP_PKEY_EC);
    // CKM_RSA_PKCS is digest-agnostic (receives DigestInfo), but we pass
    // the correct algorithm string for semantic correctness.
    const char* suffix = isEc ? "withECDSA" : "withRSA";
    switch (shaFamilyId(mdName)) {
    case 384:
        return std::string("SHA384") + suffix;
    case 512:
        return std::string("SHA512") + suffix;
    case 1:
        return std::string("SHA1") + suffix;
    case 256:
    default:
        return std::string("SHA256") + suffix; // 256 explicit + unknown-default
    }
}

// ---- Collect revocation data for a token's certificate chain ----

libresign::RevocationData collectRevocationData(libresign::Pkcs11Token& token, const libresign::TSAConfig& tsa)
{
    auto chainDer = token.certificateChain();
    std::vector<X509*> chain;
    std::vector<X509Ptr> chainOwned;
    for (const auto& der : chainDer) {
        chainOwned.push_back(parseCert(der));
        chain.push_back(chainOwned.back().get());
    }

    libresign::RevocationClient revClient;
    revClient.crlEnabled = tsa.crlEnabled;
    revClient.ocspEnabled = tsa.ocspEnabled;
    return revClient.collectForChain(chain);
}

std::vector<std::vector<uint8_t>> buildOrderedChain(const std::vector<std::vector<uint8_t>>& tokenChain,
                                                    const std::vector<std::vector<uint8_t>>& candidateCas)
{
    if (tokenChain.empty())
        return {};

    // Pool of certs we may append: the token's own non-signer certs (path
    // material) and the Trusted-List candidates (anchors). `isCandidate` marks
    // a TL anchor — once the walk appends one the chain is complete.
    struct Node
    {
        const std::vector<uint8_t>* der;
        X509Ptr x;
        bool isCandidate;
    };
    std::vector<Node> pool;
    auto addPool = [&](const std::vector<uint8_t>& der, bool candidate) {
        try {
            if (auto x = parseCert(der))
                pool.push_back({&der, std::move(x), candidate});
        } catch (const std::exception&) {
            // Skip a malformed candidate/token cert rather than aborting the
            // whole walk — one bad Trusted-List entry must not block every
            // long-term sign. parseCert throws on bad DER (it never returns
            // null), so the guard is the try/catch, not the if.
        }
    };
    for (std::size_t i = 1; i < tokenChain.size(); ++i)
        addPool(tokenChain[i], /*candidate=*/false);
    for (const auto& der : candidateCas)
        addPool(der, /*candidate=*/true);

    X509Ptr leaf;
    try {
        leaf = parseCert(tokenChain[0]);
    } catch (const std::exception&) {
        // Fall through to the empty-chain (fail-closed) return below.
    }
    if (!leaf)
        return {};

    std::vector<std::vector<uint8_t>> result;
    result.push_back(tokenChain[0]);

    X509* current = leaf.get();
    std::vector<bool> used(pool.size(), false);
    constexpr int kMaxDepth = 16; // guard against pathological / looping inputs
    for (int depth = 0; depth < kMaxDepth; ++depth) {
        // A self-signed cert is its own anchor — the chain terminates here.
        if (X509_NAME_cmp(X509_get_issuer_name(current), X509_get_subject_name(current)) == 0)
            return result;

        // The issuer is the cert whose subject matches current's issuer AND
        // whose key actually verifies current's signature. The signature check
        // is essential: a subject-DN match alone would accept a name-colliding
        // impostor that never signed this cert.
        int found = -1;
        for (std::size_t i = 0; i < pool.size(); ++i) {
            if (used[i])
                continue;
            if (X509_NAME_cmp(X509_get_subject_name(pool[i].x.get()), X509_get_issuer_name(current)) != 0)
                continue;
            EVP_PKEY* issuerKey = X509_get0_pubkey(pool[i].x.get());
            if (issuerKey && X509_verify(current, issuerKey) == 1) {
                found = static_cast<int>(i);
                break;
            }
        }
        if (found < 0)
            return {}; // issuer unresolvable — chain incomplete (caller fails closed)

        used[static_cast<std::size_t>(found)] = true;
        result.push_back(*pool[static_cast<std::size_t>(found)].der);
        if (pool[static_cast<std::size_t>(found)].isCandidate)
            return result; // reached a Trusted-List anchor — chain complete
        current = pool[static_cast<std::size_t>(found)].x.get();
    }

    return {}; // depth guard tripped — treat as incomplete
}

std::optional<libresign::SigningResult> revocationFailClosed(const libresign::RevocationData& rev)
{
    if (rev.certsWithoutRevocation.empty())
        return std::nullopt;

    return libresign::makeFailure(libresign::SignFailureKind::RevocationFetchFailed,
                                  "long-term (B-LT/B-LTA) signing requires verified revocation evidence for every "
                                  "chain certificate; " +
                                      std::to_string(rev.certsWithoutRevocation.size()) +
                                      " certificate(s) could not be covered");
}

// ---- Sign a hash with PKCS#11 token (DigestInfo for RSA) ----

std::vector<uint8_t> signHashWithToken(libresign::Pkcs11Token& token, X509* cert, const std::vector<uint8_t>& hash,
                                       const std::string& hashAlgo, std::span<const uint8_t> rawData)
{
    EVP_PKEY* pubKey = X509_get0_pubkey(cert);
    int keyType = pubKey ? EVP_PKEY_base_id(pubKey) : EVP_PKEY_RSA;
    std::string alg = tokenAlgorithm(keyType, hashAlgo);

    if (keyType != EVP_PKEY_EC) {
        // PKCS#1 v1.5: prepend DigestInfo
        auto prefix = digestInfoPrefixForAlgo(hashAlgo);
        if (prefix.empty())
            throw std::runtime_error("Unsupported hash algorithm: " + hashAlgo);

        std::vector<uint8_t> digestInfo(prefix.begin(), prefix.end());
        digestInfo.insert(digestInfo.end(), hash.begin(), hash.end());
        // Pkcs11Token internally tries the combined CKM_SHA*_RSA_PKCS form
        // first when @p rawData is supplied (hash-on-card SSCDs); on any
        // failure or when the caller has no raw bytes, it falls back to
        // the legacy CKM_RSA_PKCS path with the pre-built DigestInfo.
        return token.sign(digestInfo, alg, rawData);
    } else {
        // ECDSA: token handles DigestInfo internally
        return token.sign(hash, alg);
    }
}

// ---- libxml2 content / attribute extraction with embedded-NUL rejection ----

namespace {
struct XmlCharFreeDeleter
{
    void operator()(xmlChar* p) const
    {
        if (p)
            xmlFree(p);
    }
};
using XmlCharPtr = std::unique_ptr<xmlChar, XmlCharFreeDeleter>;

// Walk the buffer for the first @p len bytes and throw if any byte is
// NUL. The std::string-from-const-char* convenience constructor would
// silently truncate at the first NUL, so the post-validation digest
// would no longer match what the application "saw".
[[noreturn]] void throwEmbeddedNul(std::string_view what)
{
    throw std::runtime_error(std::string{"native_utils: embedded NUL byte in "} + std::string{what} +
                             " — refusing to truncate-construct a std::string");
}
} // namespace

std::string xmlContentToString(xmlNode* node)
{
    if (!node)
        return {};
    // Use xmlBufContent + xmlBufNodeDump-style buffer access so we own
    // the explicit byte length, not just the C-string view. The
    // xmlBufferCreate / xmlNodeBufGetContent pair returns a buffer the
    // caller can inspect with xmlBufferLength — if that length exceeds
    // strlen of the same data, an embedded NUL was eaten by the
    // C-string view and downstream digest/signature math would have
    // run over a different payload than what we thought we were
    // checking.
    xmlBufferPtr buf = xmlBufferCreate();
    if (!buf)
        throw std::runtime_error("native_utils: xmlBufferCreate() failed");
    struct BufFree
    {
        xmlBufferPtr p;
        ~BufFree()
        {
            xmlBufferFree(p);
        }
    } guard{buf};

    if (xmlNodeBufGetContent(buf, node) < 0)
        throw std::runtime_error("native_utils: xmlNodeBufGetContent failed");

    const xmlChar* raw = xmlBufferContent(buf);
    int rawLen = xmlBufferLength(buf);
    if (rawLen < 0)
        throw std::runtime_error("native_utils: xmlBufferLength returned negative");
    if (!raw)
        return {};
    std::size_t len = static_cast<std::size_t>(rawLen);
    if (std::memchr(raw, 0, len))
        throwEmbeddedNul("XML text content");
    return std::string{reinterpret_cast<const char*>(raw), len};
}

std::string xmlAttrToString(xmlNode* node, const char* attrName)
{
    if (!node || !attrName)
        return {};
    XmlCharPtr val(xmlGetProp(node, reinterpret_cast<const xmlChar*>(attrName)));
    if (!val)
        return {};
    const char* data = reinterpret_cast<const char*>(val.get());
    std::size_t len = std::strlen(data);
    if (std::memchr(data, 0, len))
        throwEmbeddedNul(std::string{"XML @"} + attrName + " value");
    return std::string{data, len};
}

// ---- FlateDecode (zlib decompression) ----

std::optional<std::vector<uint8_t>> flateDecode(std::span<const uint8_t> compressed, size_t sizeHint,
                                                std::size_t maxOutputBytes)
{
    if (compressed.empty())
        return std::nullopt;
    if (maxOutputBytes == 0)
        throw std::runtime_error("flateDecode: maxOutputBytes must be non-zero");

    // Streaming inflate: we grow @p output in fixed-size chunks and check
    // the running total against @p maxOutputBytes after every step, so a
    // decompression bomb (a few KiB compressed exploding to >GiB raw) is
    // rejected as early as the inflater can be asked to produce one more
    // chunk — never after the bomb has already been materialized in
    // memory.
    constexpr std::size_t kChunk = 64 * 1024;

    mz_stream stream{};
    if (mz_inflateInit(&stream) != MZ_OK)
        return std::nullopt;
    struct InflateEndGuard
    {
        mz_stream* s;
        ~InflateEndGuard()
        {
            mz_inflateEnd(s);
        }
    } guard{&stream};

    stream.next_in = compressed.data();
    stream.avail_in =
        static_cast<unsigned int>(std::min<size_t>(compressed.size(), std::numeric_limits<unsigned int>::max()));
    size_t inConsumed = stream.avail_in;

    std::vector<uint8_t> output;
    output.reserve(sizeHint > 0 ? std::min(sizeHint, maxOutputBytes) : std::min(compressed.size() * 4, maxOutputBytes));

    std::array<uint8_t, kChunk> buffer{};
    for (;;) {
        stream.next_out = buffer.data();
        stream.avail_out = static_cast<unsigned int>(buffer.size());

        int rc = mz_inflate(&stream, MZ_NO_FLUSH);
        size_t produced = buffer.size() - stream.avail_out;
        if (produced > 0) {
            if (output.size() + produced > maxOutputBytes)
                throw std::runtime_error("flateDecode: output exceeds " + std::to_string(maxOutputBytes) + " byte cap");
            output.insert(output.end(), buffer.data(), buffer.data() + produced);
        }

        if (rc == MZ_STREAM_END)
            return output;
        if (rc == MZ_BUF_ERROR && stream.avail_in == 0 && inConsumed < compressed.size()) {
            // Refill from the tail of @p compressed if the size_t source
            // didn't fit a single unsigned int.
            stream.next_in = compressed.data() + inConsumed;
            size_t remaining = compressed.size() - inConsumed;
            stream.avail_in =
                static_cast<unsigned int>(std::min<size_t>(remaining, std::numeric_limits<unsigned int>::max()));
            inConsumed += stream.avail_in;
            continue;
        }
        if (rc != MZ_OK)
            return std::nullopt;
    }
}

// ---- PNG predictor reversal for PDF xref streams ----

std::optional<std::vector<uint8_t>> reversePngPredictor(std::span<const uint8_t> data, int columns)
{
    if (columns <= 0)
        return std::nullopt;
    const int rowBytes = columns + 1; // filter byte + data
    if (data.empty() || data.size() % static_cast<size_t>(rowBytes) != 0)
        return std::nullopt;

    const int rows = static_cast<int>(data.size()) / rowBytes;
    std::vector<uint8_t> output(static_cast<size_t>(rows) * static_cast<size_t>(columns));
    std::vector<uint8_t> prevRow(static_cast<size_t>(columns), 0);

    for (int r = 0; r < rows; ++r) {
        uint8_t filter = data[static_cast<size_t>(r) * static_cast<size_t>(rowBytes)];
        const uint8_t* raw = data.data() + static_cast<size_t>(r) * static_cast<size_t>(rowBytes) + 1;
        uint8_t* out = output.data() + static_cast<size_t>(r) * static_cast<size_t>(columns);

        for (int c = 0; c < columns; ++c) {
            switch (filter) {
            case 0:
                out[c] = raw[c];
                break; // None
            case 1:
                out[c] = static_cast<uint8_t>(raw[c] + (c > 0 ? out[c - 1] : 0));
                break; // Sub
            case 2:
                out[c] = static_cast<uint8_t>(raw[c] + prevRow[c]);
                break; // Up
            case 3: {  // Average
                uint8_t left = (c > 0) ? out[c - 1] : uint8_t{0};
                out[c] = static_cast<uint8_t>(raw[c] + (left + prevRow[c]) / 2);
                break;
            }
            case 4: {                                   // Paeth
                int a = (c > 0) ? out[c - 1] : 0;       // left
                int b = prevRow[c];                     // above
                int cc2 = (c > 0) ? prevRow[c - 1] : 0; // upper-left
                int p = a + b - cc2;
                int pa = std::abs(p - a);
                int pb = std::abs(p - b);
                int pc = std::abs(p - cc2);
                uint8_t pr = (pa <= pb && pa <= pc) ? static_cast<uint8_t>(a)
                             : (pb <= pc)           ? static_cast<uint8_t>(b)
                                                    : static_cast<uint8_t>(cc2);
                out[c] = static_cast<uint8_t>(raw[c] + pr);
                break;
            }
            default:
                return std::nullopt; // Unsupported filter
            }
        }
        std::copy(out, out + columns, prevRow.begin());
    }
    return output;
}

} // namespace libresign::native_utils

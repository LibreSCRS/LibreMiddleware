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

#include <chrono>
#include <cctype>
#include <climits>
#include <cstdlib>
#include <cstring>
#include <format>
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

// ---- FlateDecode (zlib decompression) ----

std::optional<std::vector<uint8_t>> flateDecode(std::span<const uint8_t> compressed, size_t sizeHint)
{
    if (compressed.empty())
        return std::nullopt;

    size_t outSize = sizeHint > 0 ? sizeHint : compressed.size() * 4;
    std::vector<uint8_t> output(outSize);

    for (int attempt = 0; attempt < 8; ++attempt) {
        mz_ulong destLen = static_cast<mz_ulong>(output.size());
        int rc = mz_uncompress(output.data(), &destLen, compressed.data(), static_cast<mz_ulong>(compressed.size()));
        if (rc == MZ_OK) {
            output.resize(destLen);
            return output;
        }
        if (rc != MZ_BUF_ERROR)
            return std::nullopt;
        output.resize(output.size() * 2);
    }
    return std::nullopt;
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

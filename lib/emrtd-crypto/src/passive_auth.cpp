// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/crypto/passive_auth.h>

#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <cstring>
#include <memory>
#include <stdexcept>

namespace emrtd::crypto {

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL types
// ---------------------------------------------------------------------------

struct BIODeleter
{
    void operator()(BIO* p) const
    {
        BIO_free(p);
    }
};

struct CMSDeleter
{
    void operator()(CMS_ContentInfo* p) const
    {
        CMS_ContentInfo_free(p);
    }
};

struct X509StoreDeleter
{
    void operator()(X509_STORE* p) const
    {
        X509_STORE_free(p);
    }
};

struct X509Deleter
{
    void operator()(X509* p) const
    {
        X509_free(p);
    }
};

struct EVPMDCtxDeleter
{
    void operator()(EVP_MD_CTX* p) const
    {
        EVP_MD_CTX_free(p);
    }
};

using BIOPtr = std::unique_ptr<BIO, BIODeleter>;
using CMSPtr = std::unique_ptr<CMS_ContentInfo, CMSDeleter>;
using X509StorePtr = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;
using EVPMDCtxPtr = std::unique_ptr<EVP_MD_CTX, EVPMDCtxDeleter>;

// ---------------------------------------------------------------------------
// ASN.1 / BER-TLV helpers for LDSSecurityObject parsing
// ---------------------------------------------------------------------------

// Parse a BER-TLV length field starting at data[pos]. Returns (length, bytesConsumed).
static std::pair<size_t, size_t> parseBERLength(const uint8_t* data, size_t dataLen, size_t pos)
{
    if (pos >= dataLen)
        return {0, 0};

    uint8_t first = data[pos];
    if (first < 0x80) {
        return {first, 1};
    }
    size_t numBytes = first & 0x7F;
    if (numBytes == 0 || numBytes > sizeof(size_t) || pos + 1 + numBytes > dataLen)
        return {0, 0};

    size_t len = 0;
    for (size_t i = 0; i < numBytes; ++i) {
        len = (len << 8) | data[pos + 1 + i];
    }
    return {len, 1 + numBytes};
}

// Map OID bytes to hash algorithm name
static std::string oidToHashAlgorithm(const uint8_t* oidBytes, size_t oidLen)
{
    // SHA-256: 2.16.840.1.101.3.4.2.1 = 60 86 48 01 65 03 04 02 01
    static const uint8_t sha256Oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};
    // SHA-1: 1.3.14.3.2.26 = 2B 0E 03 02 1A
    static const uint8_t sha1Oid[] = {0x2B, 0x0E, 0x03, 0x02, 0x1A};
    // SHA-384: 2.16.840.1.101.3.4.2.2 = 60 86 48 01 65 03 04 02 02
    static const uint8_t sha384Oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02};
    // SHA-512: 2.16.840.1.101.3.4.2.3 = 60 86 48 01 65 03 04 02 03
    static const uint8_t sha512Oid[] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03};

    if (oidLen == sizeof(sha256Oid) && std::memcmp(oidBytes, sha256Oid, oidLen) == 0)
        return "SHA-256";
    if (oidLen == sizeof(sha1Oid) && std::memcmp(oidBytes, sha1Oid, oidLen) == 0)
        return "SHA-1";
    if (oidLen == sizeof(sha384Oid) && std::memcmp(oidBytes, sha384Oid, oidLen) == 0)
        return "SHA-384";
    if (oidLen == sizeof(sha512Oid) && std::memcmp(oidBytes, sha512Oid, oidLen) == 0)
        return "SHA-512";

    return {};
}

// Map hash algorithm name to OpenSSL EVP_MD
static const EVP_MD* hashAlgorithmToMD(const std::string& algo)
{
    if (algo == "SHA-256")
        return EVP_sha256();
    if (algo == "SHA-1")
        return EVP_sha1();
    if (algo == "SHA-384")
        return EVP_sha384();
    if (algo == "SHA-512")
        return EVP_sha512();
    return nullptr;
}

// Parse LDSSecurityObject from the eContent of the CMS SignedData.
// LDSSecurityObject ::= SEQUENCE {
//   version          INTEGER,
//   hashAlgorithm    AlgorithmIdentifier,
//   dataGroupHashValues SEQUENCE OF DataGroupHash,
//   ldsVersionInfo   [OPTIONAL] LDSVersionInfo
// }
// DataGroupHash ::= SEQUENCE {
//   dataGroupNumber  INTEGER,
//   dataGroupHashValue OCTET STRING
// }
static std::optional<SODContent> parseLDSSecurityObject(const uint8_t* data, size_t dataLen)
{
    if (dataLen < 2)
        return std::nullopt;

    size_t pos = 0;

    // Outer SEQUENCE
    if (data[pos] != 0x30)
        return std::nullopt;
    ++pos;
    auto [seqLen, seqLenBytes] = parseBERLength(data, dataLen, pos);
    if (seqLenBytes == 0)
        return std::nullopt;
    pos += seqLenBytes;

    // version INTEGER
    if (pos >= dataLen || data[pos] != 0x02)
        return std::nullopt;
    ++pos;
    auto [verLen, verLenBytes] = parseBERLength(data, dataLen, pos);
    if (verLenBytes == 0)
        return std::nullopt;
    pos += verLenBytes + verLen;

    // hashAlgorithm AlgorithmIdentifier ::= SEQUENCE { OID, optional params }
    if (pos >= dataLen || data[pos] != 0x30)
        return std::nullopt;
    ++pos;
    auto [algoSeqLen, algoSeqLenBytes] = parseBERLength(data, dataLen, pos);
    if (algoSeqLenBytes == 0)
        return std::nullopt;
    pos += algoSeqLenBytes;
    size_t algoSeqEnd = pos + algoSeqLen;

    // OID within AlgorithmIdentifier
    if (pos >= dataLen || data[pos] != 0x06)
        return std::nullopt;
    ++pos;
    auto [oidLen, oidLenBytes] = parseBERLength(data, dataLen, pos);
    if (oidLenBytes == 0)
        return std::nullopt;
    pos += oidLenBytes;

    SODContent result;
    result.hashAlgorithm = oidToHashAlgorithm(data + pos, oidLen);
    if (result.hashAlgorithm.empty())
        return std::nullopt;

    pos = algoSeqEnd; // skip past AlgorithmIdentifier

    // dataGroupHashValues SEQUENCE OF DataGroupHash
    if (pos >= dataLen || data[pos] != 0x30)
        return std::nullopt;
    ++pos;
    auto [dgSeqLen, dgSeqLenBytes] = parseBERLength(data, dataLen, pos);
    if (dgSeqLenBytes == 0)
        return std::nullopt;
    pos += dgSeqLenBytes;
    size_t dgSeqEnd = pos + dgSeqLen;

    while (pos < dgSeqEnd && pos < dataLen) {
        // DataGroupHash ::= SEQUENCE { INTEGER, OCTET STRING }
        if (data[pos] != 0x30)
            return std::nullopt;
        ++pos;
        auto [dghLen, dghLenBytes] = parseBERLength(data, dataLen, pos);
        if (dghLenBytes == 0)
            return std::nullopt;
        pos += dghLenBytes;

        // dataGroupNumber INTEGER
        if (pos >= dataLen || data[pos] != 0x02)
            return std::nullopt;
        ++pos;
        auto [dgNumLen, dgNumLenBytes] = parseBERLength(data, dataLen, pos);
        if (dgNumLenBytes == 0 || dgNumLen == 0)
            return std::nullopt;
        pos += dgNumLenBytes;

        int dgNum = 0;
        for (size_t i = 0; i < dgNumLen; ++i) {
            dgNum = (dgNum << 8) | data[pos + i];
        }
        pos += dgNumLen;

        // dataGroupHashValue OCTET STRING
        if (pos >= dataLen || data[pos] != 0x04)
            return std::nullopt;
        ++pos;
        auto [hashLen, hashLenBytes] = parseBERLength(data, dataLen, pos);
        if (hashLenBytes == 0)
            return std::nullopt;
        pos += hashLenBytes;

        result.dgHashes[dgNum] = std::vector<uint8_t>(data + pos, data + pos + hashLen);
        pos += hashLen;
    }

    // Optional: LDSVersionInfo (context tag or SEQUENCE after DG hashes)
    // We don't strictly need it for PA, but parse if present
    if (pos < dataLen && data[pos] == 0x30) {
        ++pos;
        auto [verInfoLen, verInfoLenBytes] = parseBERLength(data, dataLen, pos);
        if (verInfoLenBytes > 0) {
            pos += verInfoLenBytes;
            size_t verInfoEnd = pos + verInfoLen;

            // ldsVersion PrintableString or UTF8String
            if (pos < verInfoEnd && (data[pos] == 0x13 || data[pos] == 0x0C)) {
                ++pos;
                auto [ldsVerLen, ldsVerLenBytes] = parseBERLength(data, dataLen, pos);
                if (ldsVerLenBytes > 0) {
                    pos += ldsVerLenBytes;
                    result.ldsVersion = std::string(reinterpret_cast<const char*>(data + pos), ldsVerLen);
                    pos += ldsVerLen;
                }
            }

            // unicodeVersion PrintableString or UTF8String
            if (pos < verInfoEnd && (data[pos] == 0x13 || data[pos] == 0x0C)) {
                ++pos;
                auto [uniVerLen, uniVerLenBytes] = parseBERLength(data, dataLen, pos);
                if (uniVerLenBytes > 0) {
                    pos += uniVerLenBytes;
                    result.unicodeVersion = std::string(reinterpret_cast<const char*>(data + pos), uniVerLen);
                }
            }
        }
    }

    if (result.dgHashes.empty())
        return std::nullopt;

    return result;
}

// Extract CMS DER from EF.SOD raw bytes. EF.SOD is wrapped in tag 0x77.
static std::vector<uint8_t> extractCMSFromSOD(const std::vector<uint8_t>& sodRaw)
{
    if (sodRaw.size() < 4)
        return {};

    size_t pos = 0;

    // EF.SOD outer tag is 0x77
    if (sodRaw[pos] == 0x77) {
        ++pos;
        auto [len, lenBytes] = parseBERLength(sodRaw.data(), sodRaw.size(), pos);
        if (lenBytes == 0)
            return {};
        pos += lenBytes;
        return std::vector<uint8_t>(sodRaw.begin() + static_cast<ptrdiff_t>(pos), sodRaw.end());
    }

    // If no 0x77 wrapper, assume raw CMS (starts with 0x30)
    if (sodRaw[0] == 0x30)
        return sodRaw;

    return {};
}

// ---------------------------------------------------------------------------
// Public API implementation
// ---------------------------------------------------------------------------

std::optional<SODContent> parseSOD(const std::vector<uint8_t>& sodRaw)
{
    if (sodRaw.empty())
        return std::nullopt;

    auto cmsDER = extractCMSFromSOD(sodRaw);
    if (cmsDER.empty())
        return std::nullopt;

    // Parse CMS SignedData using OpenSSL
    BIOPtr bio(BIO_new_mem_buf(cmsDER.data(), static_cast<int>(cmsDER.size())));
    if (!bio)
        return std::nullopt;

    CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
    if (!cms)
        return std::nullopt;

    // Extract eContent (the LDSSecurityObject)
    ASN1_OCTET_STRING** eContentRef = CMS_get0_content(cms.get());
    if (!eContentRef || !*eContentRef)
        return std::nullopt;

    const ASN1_OCTET_STRING* eContent = *eContentRef;
    const uint8_t* eContentData = eContent->data;
    size_t eContentLen = static_cast<size_t>(eContent->length);

    return parseLDSSecurityObject(eContentData, eContentLen);
}

PAResult::Status verifyDGHash(const std::vector<uint8_t>& dgRaw, const std::vector<uint8_t>& expectedHash,
                              const std::string& hashAlgorithm)
{
    const EVP_MD* md = hashAlgorithmToMD(hashAlgorithm);
    if (!md)
        return PAResult::FAILED;

    EVPMDCtxPtr ctx(EVP_MD_CTX_new());
    if (!ctx)
        return PAResult::FAILED;

    if (!EVP_DigestInit_ex(ctx.get(), md, nullptr))
        return PAResult::FAILED;

    if (!dgRaw.empty()) {
        if (!EVP_DigestUpdate(ctx.get(), dgRaw.data(), dgRaw.size()))
            return PAResult::FAILED;
    }

    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int digestLen = 0;
    if (!EVP_DigestFinal_ex(ctx.get(), digest, &digestLen))
        return PAResult::FAILED;

    if (static_cast<size_t>(digestLen) != expectedHash.size())
        return PAResult::FAILED;

    if (CRYPTO_memcmp(digest, expectedHash.data(), digestLen) != 0)
        return PAResult::FAILED;

    return PAResult::PASSED;
}

PAResult::Status verifySODSignature(const std::vector<uint8_t>& sodRaw)
{
    if (sodRaw.empty())
        return PAResult::FAILED;

    auto cmsDER = extractCMSFromSOD(sodRaw);
    if (cmsDER.empty())
        return PAResult::FAILED;

    BIOPtr bio(BIO_new_mem_buf(cmsDER.data(), static_cast<int>(cmsDER.size())));
    if (!bio)
        return PAResult::FAILED;

    CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
    if (!cms)
        return PAResult::FAILED;

    // Create a detached content BIO (eContent is embedded, so pass nullptr for data)
    // CMS_NO_SIGNER_CERT_VERIFY: verify signature but not certificate chain
    // CMS_NO_CONTENT_VERIFY is NOT set so content digest is checked
    int flags = CMS_NO_SIGNER_CERT_VERIFY;
    if (CMS_verify(cms.get(), nullptr, nullptr, nullptr, nullptr, flags) == 1)
        return PAResult::PASSED;

    return PAResult::FAILED;
}

PAResult::Status verifyCSCAChain(const std::vector<uint8_t>& sodRaw, const std::string& trustStorePath)
{
    if (sodRaw.empty() || trustStorePath.empty())
        return PAResult::NOT_PERFORMED;

    auto cmsDER = extractCMSFromSOD(sodRaw);
    if (cmsDER.empty())
        return PAResult::FAILED;

    // Build X509_STORE from trust store directory
    X509StorePtr store(X509_STORE_new());
    if (!store)
        return PAResult::FAILED;

    // Load certificates from the trust store path (directory of PEM certificates)
    if (!X509_STORE_load_path(store.get(), trustStorePath.c_str()))
        return PAResult::FAILED;

    BIOPtr bio(BIO_new_mem_buf(cmsDER.data(), static_cast<int>(cmsDER.size())));
    if (!bio)
        return PAResult::FAILED;

    CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
    if (!cms)
        return PAResult::FAILED;

    // Full verification including certificate chain
    if (CMS_verify(cms.get(), nullptr, store.get(), nullptr, nullptr, 0) == 1)
        return PAResult::PASSED;

    return PAResult::FAILED;
}

PAResult performPassiveAuth(const std::vector<uint8_t>& sodRaw,
                            const std::map<int, std::vector<uint8_t>>& dgRawData,
                            const std::string& trustStorePath)
{
    PAResult result;

    // Step 1: Parse SOD to extract hash algorithm and DG hashes
    auto sodContent = parseSOD(sodRaw);
    if (!sodContent) {
        result.sodSignature = PAResult::FAILED;
        result.errorDetail = "Failed to parse EF.SOD";
        return result;
    }

    result.hashAlgorithm = sodContent->hashAlgorithm;

    // Step 2: Verify each DG hash
    for (const auto& [dgNum, expectedHash] : sodContent->dgHashes) {
        auto it = dgRawData.find(dgNum);
        if (it == dgRawData.end()) {
            // DG not read from chip — mark as not performed
            result.dgHashes[dgNum] = PAResult::NOT_PERFORMED;
            continue;
        }
        result.dgHashes[dgNum] = verifyDGHash(it->second, expectedHash, sodContent->hashAlgorithm);
    }

    // Step 3: Verify SOD signature (signature only, not certificate chain)
    result.sodSignature = verifySODSignature(sodRaw);

    // Step 4: Extract DSC info from CMS signers
    auto cmsDER = extractCMSFromSOD(sodRaw);
    if (!cmsDER.empty()) {
        BIOPtr bio(BIO_new_mem_buf(cmsDER.data(), static_cast<int>(cmsDER.size())));
        if (bio) {
            CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
            if (cms) {
                STACK_OF(X509)* signers = CMS_get1_certs(cms.get());
                if (signers && sk_X509_num(signers) > 0) {
                    X509* dsc = sk_X509_value(signers, 0);
                    if (dsc) {
                        // Extract subject
                        char* subjectStr = X509_NAME_oneline(X509_get_subject_name(dsc), nullptr, 0);
                        if (subjectStr) {
                            result.dscSubject = subjectStr;
                            OPENSSL_free(subjectStr);
                        }

                        // Extract expiry
                        const ASN1_TIME* notAfter = X509_get0_notAfter(dsc);
                        if (notAfter) {
                            BIOPtr timeBio(BIO_new(BIO_s_mem()));
                            if (timeBio && ASN1_TIME_print(timeBio.get(), notAfter)) {
                                char timeBuf[128] = {};
                                int readLen = BIO_read(timeBio.get(), timeBuf, sizeof(timeBuf) - 1);
                                if (readLen > 0) {
                                    result.dscExpiry = std::string(timeBuf, static_cast<size_t>(readLen));
                                }
                            }
                        }
                    }
                }
                // Free the signer stack (but not the certs, they're owned by CMS)
                if (signers) {
                    sk_X509_pop_free(signers, X509_free);
                }
            }
        }
    }

    // Step 5: Optionally verify CSCA chain
    if (!trustStorePath.empty()) {
        result.cscaChain = verifyCSCAChain(sodRaw, trustStorePath);
    }

    return result;
}

} // namespace emrtd::crypto

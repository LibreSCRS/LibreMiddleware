// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/native/cades_module.h"
#include "libresign/native/pkcs11_token.h"
#include "libresign/native/signing_provider.h"
#include "libresign/native/tsa_client.h"
#include "der_utils.h"
#include "native_utils.h"

#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>

#include <climits>
#include <cstring>
#include <ctime>
#include <memory>
#include <stdexcept>

namespace libresign {

namespace {

using namespace libresign::native_utils;

using ::libresign::BioPtr;
using ::libresign::CmsPtr;
using ::libresign::EvpPkeyPtr;
using ::libresign::StackX509Ptr;

// Encode CMS to DER
std::vector<uint8_t> encodeCms(CMS_ContentInfo* cms)
{
    auto result = derEncode(i2d_CMS_ContentInfo, cms);
    if (result.empty())
        throw std::runtime_error("i2d_CMS_ContentInfo() failed: " + opensslError());
    return result;
}

// Parse DER-encoded CMS
CmsPtr parseCms(const std::vector<uint8_t>& der)
{
    if (der.size() > static_cast<size_t>(LONG_MAX))
        throw std::runtime_error("CMS DER too large");
    const unsigned char* p = der.data();
    CmsPtr cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(der.size())));
    if (!cms)
        throw std::runtime_error("d2i_CMS_ContentInfo() failed: " + opensslError());
    return cms;
}

// ---- ASN.1 ESSCertIDv2 / SigningCertificateV2 construction ----
//
// ETSI EN 319 122-1 requires signing-certificate-v2 (RFC 5035).
//
// SigningCertificateV2 ::= SEQUENCE {
//     certs  SEQUENCE OF ESSCertIDv2
// }
// ESSCertIDv2 ::= SEQUENCE {
//     hashAlgorithm  AlgorithmIdentifier DEFAULT sha256,
//     certHash        OCTET STRING,
//     issuerSerial    IssuerSerial OPTIONAL
// }
// IssuerSerial ::= SEQUENCE {
//     issuer         GeneralNames,
//     serialNumber   CertificateSerialNumber
// }
//
// When hashAlgorithm is SHA-256 (the default), it SHOULD be omitted
// per RFC 5035 sec. 3 to keep the encoding compact.

std::vector<uint8_t> buildSigningCertV2Attr(X509* cert)
{
    // 1. Hash the entire DER-encoded certificate with SHA-256
    auto certDer = derEncode(i2d_X509, cert);
    if (certDer.empty())
        throw std::runtime_error("i2d_X509() failed: " + opensslError());

    auto certHash = sha256(certDer);

    // 2. Build IssuerSerial
    //    issuer = GeneralNames containing a directoryName with the issuer DN
    //    serialNumber = cert serial number

    // Get issuer name DER
    auto issuerBytes = derEncode(i2d_X509_NAME, X509_get_issuer_name(cert));
    if (issuerBytes.empty())
        throw std::runtime_error("i2d_X509_NAME() failed: " + opensslError());

    // Get serial number DER
    auto serialDer = derEncode(i2d_ASN1_INTEGER, const_cast<ASN1_INTEGER*>(X509_get0_serialNumber(cert)));
    if (serialDer.empty())
        throw std::runtime_error("i2d_ASN1_INTEGER() failed: " + opensslError());

    // Build GeneralName (directoryName) [4] IMPLICIT
    // Tag: context [4] constructed = 0xA4
    auto generalName = derWrap(0xA4, issuerBytes);

    // GeneralNames = SEQUENCE OF GeneralName
    auto generalNames = derWrap(0x30, generalName);

    // IssuerSerial = SEQUENCE { issuer GeneralNames, serialNumber INTEGER }
    std::vector<uint8_t> issuerSerialContent;
    issuerSerialContent.insert(issuerSerialContent.end(), generalNames.begin(), generalNames.end());
    issuerSerialContent.insert(issuerSerialContent.end(), serialDer.begin(), serialDer.end());

    auto issuerSerial = derWrap(0x30, issuerSerialContent);

    // 3. Build ESSCertIDv2
    //    For SHA-256 default: omit hashAlgorithm field
    //    certHash = OCTET STRING
    auto certHashOctet = derOctetString(certHash);

    std::vector<uint8_t> essCertIdV2Content;
    essCertIdV2Content.insert(essCertIdV2Content.end(), certHashOctet.begin(), certHashOctet.end());
    essCertIdV2Content.insert(essCertIdV2Content.end(), issuerSerial.begin(), issuerSerial.end());

    auto essCertIdV2 = derWrap(0x30, essCertIdV2Content);

    // 4. Build SEQUENCE OF ESSCertIDv2 (just one entry)
    auto certsSeq = derWrap(0x30, essCertIdV2);

    // 5. Build SigningCertificateV2 = SEQUENCE { certs }
    auto signingCertV2 = derWrap(0x30, certsSeq);

    return signingCertV2;
}

// Build RevocationValues ASN.1 structure (OID 1.2.840.113549.1.9.16.2.24)
//
// RevocationValues ::= SEQUENCE {
//     crlVals   [0] SEQUENCE OF CertificateList OPTIONAL,
//     ocspVals  [1] SEQUENCE OF BasicOCSPResponse OPTIONAL
// }
std::vector<uint8_t> buildRevocationValues(const RevocationData& revData)
{
    std::vector<uint8_t> content;

    // crlVals [0] SEQUENCE OF CertificateList
    if (!revData.crls.empty()) {
        std::vector<uint8_t> crlSeqContent;
        for (const auto& crl : revData.crls)
            crlSeqContent.insert(crlSeqContent.end(), crl.begin(), crl.end());

        // SEQUENCE wrapper
        auto crlSeq = derWrap(0x30, crlSeqContent);

        // [0] EXPLICIT wrapper
        auto crlTagged = derWrap(0xA0, crlSeq);
        content.insert(content.end(), crlTagged.begin(), crlTagged.end());
    }

    // ocspVals [1] SEQUENCE OF BasicOCSPResponse
    if (!revData.ocspResponses.empty()) {
        std::vector<uint8_t> ocspSeqContent;
        for (const auto& ocsp : revData.ocspResponses)
            ocspSeqContent.insert(ocspSeqContent.end(), ocsp.begin(), ocsp.end());

        // SEQUENCE wrapper
        auto ocspSeq = derWrap(0x30, ocspSeqContent);

        // [1] EXPLICIT wrapper
        auto ocspTagged = derWrap(0xA1, ocspSeq);
        content.insert(content.end(), ocspTagged.begin(), ocspTagged.end());
    }

    // Outer SEQUENCE
    return derSequence(content);
}

// Get the first CMS_SignerInfo from a CMS structure
CMS_SignerInfo* getFirstSignerInfo(CMS_ContentInfo* cms)
{
    STACK_OF(CMS_SignerInfo)* signerInfos = CMS_get0_SignerInfos(cms);
    if (!signerInfos || sk_CMS_SignerInfo_num(signerInfos) == 0)
        throw std::runtime_error("CMS has no SignerInfos");
    return sk_CMS_SignerInfo_value(signerInfos, 0);
}

// Add an unsigned attribute to a CMS_SignerInfo
void addUnsignedAttr(CMS_SignerInfo* si, const char* oid, const std::vector<uint8_t>& value)
{
    ASN1_OBJECT* obj = OBJ_txt2obj(oid, 1);
    if (!obj)
        throw std::runtime_error(std::string("OBJ_txt2obj failed for OID: ") + oid);

    ASN1_STRING* str = ASN1_STRING_new();
    if (!str) {
        ASN1_OBJECT_free(obj);
        throw std::runtime_error("ASN1_STRING_new() failed");
    }
    ASN1_STRING_set(str, value.data(), static_cast<int>(value.size()));

    // CMS_unsigned_add1_attr_by_OBJ adds a copy, we free our originals
    X509_ATTRIBUTE* attr = X509_ATTRIBUTE_create_by_OBJ(
        nullptr, obj, V_ASN1_SEQUENCE, const_cast<unsigned char*>(ASN1_STRING_get0_data(str)), ASN1_STRING_length(str));
    ASN1_STRING_free(str);
    ASN1_OBJECT_free(obj);

    if (!attr)
        throw std::runtime_error("X509_ATTRIBUTE_create_by_OBJ() failed: " + opensslError());

    if (!CMS_unsigned_add1_attr(si, attr)) {
        X509_ATTRIBUTE_free(attr);
        throw std::runtime_error("CMS_unsigned_add1_attr() failed: " + opensslError());
    }
    X509_ATTRIBUTE_free(attr);
}

} // namespace

// ---- signBB ----

std::vector<uint8_t> CAdESModule::signBB(const std::vector<uint8_t>& data, Pkcs11Token& token)
{
    // 1. Get signer certificate from token
    auto certDer = token.certificate();
    if (certDer.empty())
        throw std::runtime_error("No certificate found on token");

    X509Ptr signerCert = parseCert(certDer);

    // 2. Create an EVP_PKEY backed by the PKCS#11 token.
    //    This key has the cert's public key but delegates sign() to the card.
    //    OpenSSL CMS API uses it transparently — no workarounds needed.
    EvpPkeyPtr pkey(createPkcs11EvpKey(token, signerCert.get()).release());

    // 3. Create CMS SignedData with the PKCS#11-backed key.
    //    OpenSSL handles content-type, message-digest, and signing-time
    //    signed attributes automatically. We add signing-certificate-v2 manually.
    BioPtr dataBio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!dataBio)
        throw std::runtime_error("BIO_new_mem_buf() failed");

    constexpr unsigned int kFlags = CMS_PARTIAL | CMS_BINARY | CMS_DETACHED | CMS_NOSMIMECAP;

    // Create empty CMS (no signer yet)
    CmsPtr cms(CMS_sign(nullptr, nullptr, nullptr, dataBio.get(), kFlags));
    if (!cms)
        throw std::runtime_error("CMS_sign() failed: " + opensslError());

    // Add signer with explicit digest. Our provider keymgmt implements export
    // so EVP_PKEY_eq inside CMS_add1_signer succeeds for key/cert matching.
    CMS_SignerInfo* si = CMS_add1_signer(cms.get(), signerCert.get(), pkey.get(), EVP_sha256(), kFlags);
    if (!si)
        throw std::runtime_error("CMS_add1_signer() failed: " + opensslError());

    // 4. Add signing-certificate-v2 signed attribute (ETSI EN 319 122-1 §5.2.2)
    auto sigCertV2Der = buildSigningCertV2Attr(signerCert.get());

    ASN1_OBJECT* sigCertV2Oid = OBJ_txt2obj("1.2.840.113549.1.9.16.2.47", 1);
    if (!sigCertV2Oid)
        throw std::runtime_error("OBJ_txt2obj failed for signing-certificate-v2 OID");

    X509_ATTRIBUTE* sigCertAttr = X509_ATTRIBUTE_create_by_OBJ(
        nullptr, sigCertV2Oid, V_ASN1_SEQUENCE, sigCertV2Der.data(), static_cast<int>(sigCertV2Der.size()));
    ASN1_OBJECT_free(sigCertV2Oid);
    if (!sigCertAttr)
        throw std::runtime_error("X509_ATTRIBUTE_create_by_OBJ() failed: " + opensslError());

    if (!CMS_signed_add1_attr(si, sigCertAttr)) {
        X509_ATTRIBUTE_free(sigCertAttr);
        throw std::runtime_error("CMS_signed_add1_attr() failed: " + opensslError());
    }
    X509_ATTRIBUTE_free(sigCertAttr);

    // 5. Finalize — OpenSSL computes message-digest, adds signing-time,
    //    hashes signed attributes, and calls our PKCS#11-backed EVP_PKEY
    //    to produce the signature. All transparently.
    BioPtr dataBio2(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!CMS_final(cms.get(), dataBio2.get(), nullptr, CMS_BINARY | CMS_DETACHED))
        throw std::runtime_error("CMS_final() failed: " + opensslError());

    // 6. Encode final CMS to DER
    return encodeCms(cms.get());
}

// ---- addTimestamp ----

std::vector<uint8_t> CAdESModule::addTimestamp(const std::vector<uint8_t>& cmsBytes, const TSAConfig& tsa)
{
    if (tsa.url.empty())
        throw std::runtime_error("TSA URL is required for B-T level");

    CmsPtr cms = parseCms(cmsBytes);
    CMS_SignerInfo* si = getFirstSignerInfo(cms.get());

    // Get the signature value to timestamp
    ASN1_OCTET_STRING* sigValue = CMS_SignerInfo_get0_signature(si);
    if (!sigValue)
        throw std::runtime_error("Cannot get signature value from SignerInfo");

    const unsigned char* sigData = ASN1_STRING_get0_data(sigValue);
    int sigLen = ASN1_STRING_length(sigValue);
    if (!sigData || sigLen <= 0)
        throw std::runtime_error("Signature value is empty");

    // Hash the signature value with SHA-256
    auto sigHash = sha256(sigData, static_cast<size_t>(sigLen));

    // Request timestamp from TSA
    TSAClient tsaClient;
    auto tsaResult = tsaClient.timestamp(sigHash, tsa.url, tsa.timeoutSeconds);
    if (!tsaResult.success)
        throw std::runtime_error("TSA timestamp failed: " + tsaResult.errorMessage);

    // Add as unsigned attribute: id-smime-aa-signatureTimeStamp (1.2.840.113549.1.9.16.2.14)
    addUnsignedAttr(si, "1.2.840.113549.1.9.16.2.14", tsaResult.token);

    return encodeCms(cms.get());
}

// ---- addRevocationData ----

std::vector<uint8_t> CAdESModule::addRevocationData(const std::vector<uint8_t>& cmsBytes, const RevocationData& revData)
{
    if (revData.crls.empty() && revData.ocspResponses.empty())
        return cmsBytes; // nothing to add

    CmsPtr cms = parseCms(cmsBytes);
    CMS_SignerInfo* si = getFirstSignerInfo(cms.get());

    // Build RevocationValues ASN.1 and add as unsigned attribute
    // OID: id-smime-aa-ets-revValues (1.2.840.113549.1.9.16.2.24)
    auto revValues = buildRevocationValues(revData);
    addUnsignedAttr(si, "1.2.840.113549.1.9.16.2.24", revValues);

    return encodeCms(cms.get());
}

// ---- addArchiveTimestamp ----

// Build a DER-encoded SEQUENCE OF OCTET STRING from a vector of hashes.
std::vector<uint8_t> buildSequenceOfOctetStrings(const std::vector<std::vector<uint8_t>>& hashes)
{
    std::vector<uint8_t> inner;
    for (auto& hash : hashes) {
        auto os = ::libresign::derOctetString(hash);
        inner.insert(inner.end(), os.begin(), os.end());
    }
    return ::libresign::derSequence(inner);
}

// Build the ATSHashIndex ASN.1 structure per ETSI EN 319 122-1 section 5.5.2:
// ATSHashIndex ::= SEQUENCE {
//     hashIndAlgorithm     AlgorithmIdentifier,
//     certificatesHashIndex  SEQUENCE OF OCTET STRING,
//     crlsHashIndex          SEQUENCE OF OCTET STRING,
//     unsignedAttrsHashIndex SEQUENCE OF OCTET STRING
// }
std::vector<uint8_t> buildAtsHashIndex(const std::vector<std::vector<uint8_t>>& certHashes,
                                       const std::vector<std::vector<uint8_t>>& crlHashes,
                                       const std::vector<std::vector<uint8_t>>& attrHashes)
{
    // SHA-256 AlgorithmIdentifier DER: SEQUENCE { OID 2.16.840.1.101.3.4.2.1, NULL }
    static const uint8_t sha256AlgId[] = {0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                          0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00};

    auto certSeq = buildSequenceOfOctetStrings(certHashes);
    auto crlSeq = buildSequenceOfOctetStrings(crlHashes);
    auto attrSeq = buildSequenceOfOctetStrings(attrHashes);

    // Build outer SEQUENCE content
    std::vector<uint8_t> content;
    content.insert(content.end(), std::begin(sha256AlgId), std::end(sha256AlgId));
    content.insert(content.end(), certSeq.begin(), certSeq.end());
    content.insert(content.end(), crlSeq.begin(), crlSeq.end());
    content.insert(content.end(), attrSeq.begin(), attrSeq.end());

    return ::libresign::derSequence(content);
}

std::vector<uint8_t> CAdESModule::addArchiveTimestamp(const std::vector<uint8_t>& cmsBytes, const TSAConfig& tsa)
{
    if (tsa.url.empty())
        throw std::runtime_error("TSA URL is required for B-LTA level");

    // ETSI EN 319 122-1 section 5.5.2: build ats-hash-index-v3 by hashing
    // individual SignedData components (certificates, CRLs, unsigned attrs).
    CmsPtr cms = parseCms(cmsBytes);
    CMS_SignerInfo* si = getFirstSignerInfo(cms.get());

    // 1. Hash each certificate DER individually
    std::vector<std::vector<uint8_t>> certHashes;
    STACK_OF(X509)* certs = CMS_get1_certs(cms.get());
    if (certs) {
        for (int i = 0; i < sk_X509_num(certs); ++i) {
            X509* cert = sk_X509_value(certs, i);
            auto der = derEncode(i2d_X509, cert);
            if (!der.empty())
                certHashes.push_back(sha256(der));
        }
        sk_X509_pop_free(certs, X509_free);
    }

    // 2. Hash each CRL DER individually
    std::vector<std::vector<uint8_t>> crlHashes;
    STACK_OF(X509_CRL)* crls = CMS_get1_crls(cms.get());
    if (crls) {
        for (int i = 0; i < sk_X509_CRL_num(crls); ++i) {
            X509_CRL* crl = sk_X509_CRL_value(crls, i);
            auto der = derEncode(i2d_X509_CRL, crl);
            if (!der.empty())
                crlHashes.push_back(sha256(der));
        }
        sk_X509_CRL_pop_free(crls, X509_CRL_free);
    }

    // 3. Hash each unsigned attribute DER, excluding archive timestamps
    std::vector<std::vector<uint8_t>> attrHashes;
    // OID for id-aa-ets-archiveTimestampV3: 1.2.840.113549.1.9.16.2.48
    std::unique_ptr<ASN1_OBJECT, decltype(&ASN1_OBJECT_free)> archiveTstOid(
        OBJ_txt2obj("1.2.840.113549.1.9.16.2.48", 1), ASN1_OBJECT_free);
    int attrCount = CMS_unsigned_get_attr_count(si);
    for (int i = 0; i < attrCount; ++i) {
        X509_ATTRIBUTE* attr = CMS_unsigned_get_attr(si, i);
        ASN1_OBJECT* attrObj = X509_ATTRIBUTE_get0_object(attr);
        // Skip existing archive timestamps
        if (OBJ_cmp(attrObj, archiveTstOid.get()) == 0)
            continue;
        auto der = derEncode(i2d_X509_ATTRIBUTE, attr);
        if (!der.empty())
            attrHashes.push_back(sha256(der));
    }

    // 4. Build ATSHashIndex attribute
    auto atsHashIndex = buildAtsHashIndex(certHashes, crlHashes, attrHashes);

    // 5. Timestamp the entire CMS DER encoding
    auto cmsHash = sha256(cmsBytes);
    TSAClient tsaClient;
    auto tsaResult = tsaClient.timestamp(cmsHash, tsa.url, tsa.timeoutSeconds);
    if (!tsaResult.success)
        throw std::runtime_error("Archive TSA timestamp failed: " + tsaResult.errorMessage);

    // 6. Add both attributes: ats-hash-index-v3 and archive timestamp
    // id-aa-ATSHashIndex: 0.4.0.1733.2.5
    addUnsignedAttr(si, "0.4.0.1733.2.5", atsHashIndex);
    // id-aa-ets-archiveTimestampV3: 1.2.840.113549.1.9.16.2.48
    addUnsignedAttr(si, "1.2.840.113549.1.9.16.2.48", tsaResult.token);

    return encodeCms(cms.get());
}

// ---- sign (convenience) ----

SigningResult CAdESModule::sign(const std::vector<uint8_t>& data, Pkcs11Token& token, SignatureLevel level,
                                const TSAConfig& tsa)
{
    if (data.empty())
        return {false, {}, "Input data is empty"};

    try {
        auto cms = signBB(data, token);
        if (cms.empty())
            return {false, {}, "CAdES B-B signing produced empty output"};

        if (level >= SignatureLevel::B_T) {
            cms = addTimestamp(cms, tsa);
        }

        if (level >= SignatureLevel::B_LT) {
            auto revData = collectRevocationData(token, tsa);
            cms = addRevocationData(cms, revData);
        }

        if (level >= SignatureLevel::B_LTA) {
            cms = addArchiveTimestamp(cms, tsa);
        }

        return {true, std::move(cms), {}};
    } catch (const std::exception& e) {
        return {false, {}, std::string("CAdES error: ") + e.what()};
    }
}

} // namespace libresign

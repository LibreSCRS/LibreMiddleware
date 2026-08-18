// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/cades_module.h"
#include "native/pkcs11_token.h"
#include "native/signing_provider.h"
#include "native/tsa_client.h"
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
#include <memory>
#include <span>
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

// Get the CMS_SignerInfo at @p index (0-based) from a CMS structure.
//
// Positional lookup is only meaningful on a CMS that was just parsed: the
// SignedData signerInfos field is an ASN.1 SET OF, and DER requires SET OF
// members to be written in sorted-encoding order, so OpenSSL reorders them
// inside i2d_CMS_ContentInfo. An index is therefore valid against the DER a
// caller holds right now, and NOT across an encode. Callers that need to keep
// hold of one signer while the document changes must carry the
// CMS_SignerInfo* itself — see applyLevelUpgrades().
CMS_SignerInfo* signerInfoAt(CMS_ContentInfo* cms, int index)
{
    STACK_OF(CMS_SignerInfo)* signerInfos = CMS_get0_SignerInfos(cms);
    const int count = signerInfos ? sk_CMS_SignerInfo_num(signerInfos) : 0;
    if (count == 0)
        throw std::runtime_error("CMS has no SignerInfos");
    if (index < 0 || index >= count)
        throw std::runtime_error("CMS has no SignerInfo at index " + std::to_string(index));
    return sk_CMS_SignerInfo_value(signerInfos, index);
}

// An absent TSA URL is a caller error, not a document error: check it before
// touching the CMS bytes so it surfaces as InvalidInput even when the document
// is also malformed.
void requireTsaUrl(const TSAConfig& tsa, const char* levelName)
{
    if (tsa.url.empty())
        throw SignFailureException(SignFailureKind::InvalidInput,
                                   std::string("TSA URL is required for ") + levelName + " level");
}

// Attach the ESS signing-certificate-v2 signed attribute (ETSI EN 319 122-1
// §5.2.2) to @p si built over @p cert. Throws std::runtime_error on OpenSSL
// failure. Factored out so signBB and appendSigner share the exact same
// attribute construction.
void attachSigningCertificateV2(CMS_SignerInfo* si, X509* cert)
{
    auto sigCertV2Der = buildSigningCertV2Attr(cert);

    Asn1ObjectPtr sigCertV2Oid(OBJ_txt2obj("1.2.840.113549.1.9.16.2.47", 1));
    if (!sigCertV2Oid)
        throw std::runtime_error("OBJ_txt2obj failed for signing-certificate-v2 OID");

    X509AttributePtr sigCertAttr(X509_ATTRIBUTE_create_by_OBJ(
        nullptr, sigCertV2Oid.get(), V_ASN1_SEQUENCE, sigCertV2Der.data(), static_cast<int>(sigCertV2Der.size())));
    if (!sigCertAttr)
        throw std::runtime_error("X509_ATTRIBUTE_create_by_OBJ() failed: " + opensslError());

    if (!CMS_signed_add1_attr(si, sigCertAttr.get()))
        throw std::runtime_error("CMS_signed_add1_attr() failed: " + opensslError());
}

// Add an unsigned attribute to a CMS_SignerInfo
void addUnsignedAttr(CMS_SignerInfo* si, const char* oid, const std::vector<uint8_t>& value)
{
    Asn1ObjectPtr obj(OBJ_txt2obj(oid, 1));
    if (!obj)
        throw std::runtime_error(std::string("OBJ_txt2obj failed for OID: ") + oid);

    Asn1StringPtr str(ASN1_STRING_new());
    if (!str)
        throw std::runtime_error("ASN1_STRING_new() failed");
    ASN1_STRING_set(str.get(), value.data(), static_cast<int>(value.size()));

    // CMS_unsigned_add1_attr_by_OBJ adds a copy, we free our originals
    X509AttributePtr attr(X509_ATTRIBUTE_create_by_OBJ(nullptr, obj.get(), V_ASN1_SEQUENCE,
                                                       const_cast<unsigned char*>(ASN1_STRING_get0_data(str.get())),
                                                       ASN1_STRING_length(str.get())));

    if (!attr)
        throw std::runtime_error("X509_ATTRIBUTE_create_by_OBJ() failed: " + opensslError());

    if (!CMS_unsigned_add1_attr(si, attr.get()))
        throw std::runtime_error("CMS_unsigned_add1_attr() failed: " + opensslError());
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
    attachSigningCertificateV2(si, signerCert.get());

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

namespace {

// Attach the RFC 3161 signature timestamp (ETSI EN 319 122-1 §5.3.1) to
// @p si. Operates on the live SignerInfo so the caller can target one signer
// of several — see signerInfoAt() on why an index cannot do that.
void addTimestampTo(CMS_SignerInfo* si, const TSAConfig& tsa)
{
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
    auto tsaResult = tsaClient.timestamp(sigHash, toTsaRequest(tsa));
    if (!tsaResult.success)
        throw SignFailureException(SignFailureKind::TsaUnreachable, "TSA timestamp failed: " + tsaResult.errorMessage);

    // Add as unsigned attribute: id-smime-aa-signatureTimeStamp (1.2.840.113549.1.9.16.2.14)
    addUnsignedAttr(si, "1.2.840.113549.1.9.16.2.14", tsaResult.token);
}

// Embed @p chainDer[1..] in the SignedData certificates set. UNION, never
// replace: the set is shared by every signer, so evicting an entry would strip
// path material a prior signer's verifier still needs. CMS_add1_cert is
// idempotent on a certificate already in the set, so overlapping chains
// between signers collapse instead of duplicating.
void addCertificateChainTo(CMS_ContentInfo* cms, const std::vector<std::vector<uint8_t>>& chainDer)
{
    // chainDer[0] is the signer leaf — CMS_add1_signer already placed it in the
    // SignedData certificates set. Embed the remaining path (issuing CA up to
    // the trust anchor) so a B-LT signature carries the certificates a verifier
    // needs to build the path without external fetching.
    for (std::size_t i = 1; i < chainDer.size(); ++i) {
        X509Ptr cert = parseCert(chainDer[i]);
        if (cert && CMS_add1_cert(cms, cert.get()) != 1)
            throw std::runtime_error("CMS_add1_cert() failed: " + opensslError());
    }
}

// Attach the revocation values (ETSI EN 319 122-1 §5.4.2) to @p si.
void addRevocationDataTo(CMS_SignerInfo* si, const RevocationData& revData)
{
    if (revData.crls.empty() && revData.ocspResponses.empty())
        return; // nothing to add

    // Build RevocationValues ASN.1 and add as unsigned attribute
    // OID: id-smime-aa-ets-revValues (1.2.840.113549.1.9.16.2.24)
    auto revValues = buildRevocationValues(revData);
    addUnsignedAttr(si, "1.2.840.113549.1.9.16.2.24", revValues);
}

} // namespace

// ---- byte-oriented wrappers ----
//
// Single-signer entry points kept for the callers that hand a whole document
// across a module boundary (the PAdES path embeds a CMS built one signature at
// a time). They parse, resolve signer 0 — unambiguous on a single-signer CMS —
// delegate to the core above, and re-encode.

std::vector<uint8_t> CAdESModule::addTimestamp(const std::vector<uint8_t>& cmsBytes, const TSAConfig& tsa)
{
    requireTsaUrl(tsa, "B-T");
    CmsPtr cms = parseCms(cmsBytes);
    addTimestampTo(signerInfoAt(cms.get(), 0), tsa);
    return encodeCms(cms.get());
}

std::vector<uint8_t> CAdESModule::addCertificateChain(const std::vector<uint8_t>& cmsBytes,
                                                      const std::vector<std::vector<uint8_t>>& chainDer)
{
    if (chainDer.size() <= 1)
        return cmsBytes;

    CmsPtr cms = parseCms(cmsBytes);
    addCertificateChainTo(cms.get(), chainDer);
    return encodeCms(cms.get());
}

std::vector<uint8_t> CAdESModule::addRevocationData(const std::vector<uint8_t>& cmsBytes, const RevocationData& revData)
{
    if (revData.crls.empty() && revData.ocspResponses.empty())
        return cmsBytes; // nothing to add

    CmsPtr cms = parseCms(cmsBytes);
    addRevocationDataTo(signerInfoAt(cms.get(), 0), revData);
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

namespace {

// Attach the ats-hash-index-v3 and archive-timestamp unsigned attributes
// (ETSI EN 319 122-1 §5.5.2 / §5.5.4) to @p si.
//
// Note the asymmetry with the two cores above: the archive timestamp's message
// imprint is computed over the WHOLE SignedData — certificates and CRLs
// included — not just over @p si. That is why an archive timestamp cannot be
// minted for a signer appended to an existing document: adding a signer adds
// its certificate to the set the imprint covers, so the prior signers' archive
// timestamps would no longer describe the document they were computed over.
void addArchiveTimestampTo(CMS_ContentInfo* cms, CMS_SignerInfo* si, const TSAConfig& tsa)
{
    // ETSI EN 319 122-1 section 5.5.2: build ats-hash-index-v3 by hashing
    // individual SignedData components (certificates, CRLs, unsigned attrs).

    // 1. Hash each certificate DER individually
    std::vector<std::vector<uint8_t>> certHashes;
    STACK_OF(X509)* certs = CMS_get1_certs(cms);
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
    STACK_OF(X509_CRL)* crls = CMS_get1_crls(cms);
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
    Asn1ObjectPtr archiveTstOid(OBJ_txt2obj("1.2.840.113549.1.9.16.2.48", 1));
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

    // 5. Build the archive timestamp message imprint per ETSI EN 319 122-1 §5.5.4:
    //    hash( signature_value || eContentType || eContent || certificates || crls || ats-hash-index-v3 )
    std::vector<uint8_t> archiveInput;

    // 5a. SignerInfo.signature value (raw octets)
    ASN1_OCTET_STRING* sigValue = CMS_SignerInfo_get0_signature(si);
    if (!sigValue)
        throw std::runtime_error("Cannot get signature value from SignerInfo");
    const unsigned char* sigData = ASN1_STRING_get0_data(sigValue);
    int sigLen = ASN1_STRING_length(sigValue);
    if (!sigData || sigLen <= 0)
        throw std::runtime_error("Signature value is empty");
    archiveInput.insert(archiveInput.end(), sigData, sigData + sigLen);

    // 5b. eContentType OID DER
    const ASN1_OBJECT* eContentType = CMS_get0_eContentType(cms);
    if (eContentType) {
        auto eContentTypeDer = derEncode(i2d_ASN1_OBJECT, const_cast<ASN1_OBJECT*>(eContentType));
        if (!eContentTypeDer.empty())
            archiveInput.insert(archiveInput.end(), eContentTypeDer.begin(), eContentTypeDer.end());
    }

    // 5c. eContent (the signed data octets) — for detached signatures this
    //     is absent from the CMS structure, so we skip it when not present.
    ASN1_OCTET_STRING** eContentRef = CMS_get0_content(cms);
    if (eContentRef && *eContentRef) {
        const unsigned char* eData = ASN1_STRING_get0_data(*eContentRef);
        int eLen = ASN1_STRING_length(*eContentRef);
        if (eData && eLen > 0)
            archiveInput.insert(archiveInput.end(), eData, eData + eLen);
    }

    // 5d. Certificate values (DER-encoded, in order)
    STACK_OF(X509)* certsForHash = CMS_get1_certs(cms);
    if (certsForHash) {
        for (int i = 0; i < sk_X509_num(certsForHash); ++i) {
            X509* cert = sk_X509_value(certsForHash, i);
            auto der = derEncode(i2d_X509, cert);
            if (!der.empty())
                archiveInput.insert(archiveInput.end(), der.begin(), der.end());
        }
        sk_X509_pop_free(certsForHash, X509_free);
    }

    // 5e. CRL values (DER-encoded, in order)
    STACK_OF(X509_CRL)* crlsForHash = CMS_get1_crls(cms);
    if (crlsForHash) {
        for (int i = 0; i < sk_X509_CRL_num(crlsForHash); ++i) {
            X509_CRL* crl = sk_X509_CRL_value(crlsForHash, i);
            auto der = derEncode(i2d_X509_CRL, crl);
            if (!der.empty())
                archiveInput.insert(archiveInput.end(), der.begin(), der.end());
        }
        sk_X509_CRL_pop_free(crlsForHash, X509_CRL_free);
    }

    // 5f. ats-hash-index-v3 DER
    archiveInput.insert(archiveInput.end(), atsHashIndex.begin(), atsHashIndex.end());

    auto archiveHash = sha256(archiveInput);
    TSAClient tsaClient;
    auto tsaResult = tsaClient.timestamp(archiveHash, toTsaRequest(tsa));
    if (!tsaResult.success)
        throw SignFailureException(SignFailureKind::TsaUnreachable,
                                   "Archive TSA timestamp failed: " + tsaResult.errorMessage);

    // 6. Add both attributes: ats-hash-index-v3 and archive timestamp
    // id-aa-ATSHashIndex: 0.4.0.1733.2.5
    addUnsignedAttr(si, "0.4.0.1733.2.5", atsHashIndex);
    // id-aa-ets-archiveTimestampV3: 1.2.840.113549.1.9.16.2.48
    addUnsignedAttr(si, "1.2.840.113549.1.9.16.2.48", tsaResult.token);
}

// ---- the level-upgrade ladder ----
//
// The ONE definition of what each SignatureLevel adds on top of B-B, shared by
// sign() and appendSigner() so the two entry points cannot drift apart.
//
// Everything runs against the live @p cms / @p si: a signer is identified by
// pointer, never by position. The SignedData signerInfos field is an ASN.1
// SET OF, so i2d_CMS_ContentInfo writes its members in sorted-encoding order
// rather than insertion order — a position obtained before an encode does not
// survive it, and shifts again whenever a step changes a SignerInfo's encoding
// (adding a timestamp is exactly such a change). Encoding once, at the end,
// keeps @p si valid for the whole ladder.
//
// Returns a failure result for the fail-closed policy stops, std::nullopt when
// the document reached @p level. Throws SignFailureException on TSA faults.
std::optional<SigningResult> applyLevelUpgrades(CMS_ContentInfo* cms, CMS_SignerInfo* si, Pkcs11Token& token,
                                                SignatureLevel level, const TSAConfig& tsa)
{
    // The B-T signature timestamp and B-LTA archive timestamp drive an RFC 3161
    // round-trip through TSAClient. A missing TSA URL or a failed round-trip
    // throws a typed SignFailureException (InvalidInput / TsaUnreachable) which
    // both callers map to the precise kind, so a failing TSA surfaces the same
    // way as on the XAdES / JAdES / PAdES paths. Every other throw from these
    // helpers (malformed SignerInfo, CMS encode, OpenSSL faults) is a plain
    // std::exception and falls through to EngineError.
    if (level >= SignatureLevel::B_T) {
        requireTsaUrl(tsa, "B-T");
        addTimestampTo(si, tsa);
    }

    if (level >= SignatureLevel::B_LT) {
        auto revData = collectRevocationData(token, tsa);
        if (auto failure = revocationFailClosed(revData))
            return failure;
        addCertificateChainTo(cms, token.certificateChain());
        addRevocationDataTo(si, revData);
    }

    if (level >= SignatureLevel::B_LTA) {
        requireTsaUrl(tsa, "B-LTA");
        addArchiveTimestampTo(cms, si, tsa);
    }

    return std::nullopt;
}

} // namespace

std::vector<uint8_t> CAdESModule::addArchiveTimestamp(const std::vector<uint8_t>& cmsBytes, const TSAConfig& tsa)
{
    requireTsaUrl(tsa, "B-LTA");
    CmsPtr cms = parseCms(cmsBytes);
    addArchiveTimestampTo(cms.get(), signerInfoAt(cms.get(), 0), tsa);
    return encodeCms(cms.get());
}

// ---- sign (convenience) ----

SigningResult CAdESModule::sign(const std::vector<uint8_t>& data, Pkcs11Token& token, SignatureLevel level,
                                const TSAConfig& tsa)
{
    if (data.empty())
        return makeFailure(SignFailureKind::InvalidDocument, "Input data is empty");

    try {
        auto cmsBytes = signBB(data, token);
        if (cmsBytes.empty())
            return makeFailure(SignFailureKind::OpensslError, "CAdES B-B signing produced empty output");

        // signBB emits exactly one SignerInfo, so index 0 names it
        // unambiguously. From here the ladder works on the live pointer.
        CmsPtr cms = parseCms(cmsBytes);
        if (auto failure = applyLevelUpgrades(cms.get(), signerInfoAt(cms.get(), 0), token, level, tsa))
            return *failure;

        return makeSuccess(encodeCms(cms.get()));
    } catch (const SignFailureException& e) {
        // Typed failure (TSA unreachable / missing URL) — preserve its precise
        // kind. MUST precede the std::exception arm: SignFailureException
        // derives from std::runtime_error, so the generic arm would otherwise
        // collapse it back to EngineError.
        return makeFailure(e.kind, e.what());
    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("CAdES error: ") + e.what());
    }
}

// ---- appendSigner ----

SigningResult CAdESModule::appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                        Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa)
{
    if (prior.empty())
        return makeFailure(SignFailureKind::InvalidDocument, "CAdES appendSigner: empty prior signature");
    if (originalDoc.empty())
        return makeFailure(SignFailureKind::InvalidInput, "CAdES detached appendSigner requires originalDocument");
    if (prior.size() > static_cast<size_t>(LONG_MAX))
        return makeFailure(SignFailureKind::InvalidDocument, "CAdES appendSigner: prior signature too large");
    if (originalDoc.size() > static_cast<size_t>(INT_MAX))
        return makeFailure(SignFailureKind::InvalidDocument, "CAdES appendSigner: originalDocument too large");

    // B-T and B-LT carry per-signer unsigned attributes and are applied to the
    // appended SignerInfo alone. B-LTA is not: the ETSI EN 319 122-1 §5.5.4
    // archive-timestamp message imprint is computed over the whole SignedData,
    // certificate set included, and appending a signer adds a certificate to
    // that set. An archive timestamp minted here would therefore describe a
    // document state that the prior signers' own archive timestamps do not,
    // and recomputing theirs would need PKCS#11 sessions we no longer hold.
    // Refuse rather than emit a spec-wrong document.
    if (level > SignatureLevel::B_LT)
        return makeFailure(SignFailureKind::PolicyViolation,
                           "CAdES appendSigner: B-LTA is not supported for an appended signer — the ETSI "
                           "EN 319 122-1 §5.5.4 archive-timestamp imprint covers the SignedData certificate "
                           "set, which appending a signer changes; use B-LT or lower");

    try {
        // 1. Parse the prior CMS ContentInfo.
        const unsigned char* p = prior.data();
        CmsPtr cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(prior.size())));
        if (!cms)
            return makeFailure(SignFailureKind::InvalidDocument,
                               "CAdES appendSigner: prior is not valid CMS: " + opensslError());

        // 2. Verify the prior CMS is DETACHED. For an attached CMS,
        //    CMS_get0_content() returns a non-null pointer to a non-null
        //    embedded content OCTET STRING; for detached it is either null
        //    or points to a null. We only support DETACHED multi-signer at
        //    this layer — attached would require splicing the original
        //    payload twice and is out of scope.
        ASN1_OCTET_STRING** eContent = CMS_get0_content(cms.get());
        if (eContent && *eContent && ASN1_STRING_length(*eContent) > 0)
            return makeFailure(SignFailureKind::PolicyViolation,
                               "CAdES appendSigner: prior CMS is attached; only detached is supported");

        // 3. Load signer cert + PKCS#11-backed EVP_PKEY (same path as signBB).
        auto certDer = token.certificate();
        if (certDer.empty())
            return makeFailure(SignFailureKind::CardError, "CAdES appendSigner: no certificate on token");

        X509Ptr signerCert = parseCert(certDer);
        if (!signerCert)
            return makeFailure(SignFailureKind::EngineError, "CAdES appendSigner: failed to parse signer certificate");

        EvpPkeyPtr pkey(createPkcs11EvpKey(token, signerCert.get()).release());
        if (!pkey)
            return makeFailure(SignFailureKind::CardError, "CAdES appendSigner: failed to obtain PKCS#11 key handle");

        // 4. Append the new SignerInfo with CMS_PARTIAL so OpenSSL does not
        //    immediately try to sign. We sign ONLY the new SignerInfo via
        //    CMS_SignerInfo_sign below; CMS_final / CMS_dataFinal would walk
        //    EVERY SignerInfo and call cms_SignerInfo_content_sign on each,
        //    which fails with CMS_R_NO_PRIVATE_KEY for the pre-existing
        //    signers (their pkey is null after d2i — only the serialised
        //    signature value travels across DER).
        constexpr unsigned int kFlags = CMS_PARTIAL | CMS_BINARY | CMS_DETACHED | CMS_NOSMIMECAP;

        CMS_SignerInfo* si = CMS_add1_signer(cms.get(), signerCert.get(), pkey.get(), EVP_sha256(), kFlags);
        if (!si)
            return makeFailure(SignFailureKind::OpensslError,
                               "CAdES appendSigner: CMS_add1_signer failed: " + opensslError());

        // 5. Attach signing-certificate-v2 to the NEW signer's signed attrs.
        attachSigningCertificateV2(si, signerCert.get());

        // 6. Compute and attach the two CMS-mandatory signed attributes
        //    (content-type + message-digest) on the new SignerInfo.
        //    cms_SignerInfo_content_sign would do this for us, but the only
        //    public entry points that call it (CMS_final / CMS_dataFinal)
        //    iterate every SignerInfo — see note above. CMS_SignerInfo_sign's
        //    attribute-validity check (ossl_cms_si_check_attributes) rejects
        //    the SignerInfo if either attribute is missing.
        const ASN1_OBJECT* eContentType = CMS_get0_eContentType(cms.get());
        if (!eContentType)
            return makeFailure(SignFailureKind::OpensslError,
                               "CAdES appendSigner: CMS_get0_eContentType returned null");
        if (!CMS_signed_add1_attr_by_NID(si, NID_pkcs9_contentType, V_ASN1_OBJECT, eContentType, -1))
            return makeFailure(SignFailureKind::OpensslError,
                               "CAdES appendSigner: failed to add contentType attribute: " + opensslError());

        auto contentHash = sha256(originalDoc.data(), originalDoc.size());
        if (!CMS_signed_add1_attr_by_NID(si, NID_pkcs9_messageDigest, V_ASN1_OCTET_STRING, contentHash.data(),
                                         static_cast<int>(contentHash.size())))
            return makeFailure(SignFailureKind::OpensslError,
                               "CAdES appendSigner: failed to add messageDigest attribute: " + opensslError());

        // 7. Sign ONLY the new SignerInfo. CMS_SignerInfo_sign encodes the
        //    signed-attrs SET, runs it through the (PKCS#11-backed)
        //    EVP_PKEY, and stores the resulting signature value on this si.
        //    Pre-existing SignerInfos are untouched — their original DER
        //    signatureValue survives intact through the upcoming re-encode.
        if (!CMS_SignerInfo_sign(si))
            return makeFailure(SignFailureKind::OpensslError,
                               "CAdES appendSigner: CMS_SignerInfo_sign failed: " + opensslError());

        // 8. Apply the requested level upgrades to the NEW SignerInfo only,
        //    through the same ladder sign() uses. `si` is the pointer
        //    CMS_add1_signer just handed back, which is what makes this
        //    correct: the appended signer cannot be named by position because
        //    the DER encode below reorders the signerInfos SET OF.
        //
        //    Adding this signer already mutated the SignedData certificate set
        //    that any archive timestamp a PRIOR signer carries was computed
        //    over — true at every level, B-B included. Appending to a document
        //    whose existing signers hold archive timestamps is outside what
        //    this method can keep intact.
        if (auto failure = applyLevelUpgrades(cms.get(), si, token, level, tsa))
            return *failure;

        // 9. Serialise to DER.
        return makeSuccess(encodeCms(cms.get()));
    } catch (const SignFailureException& e) {
        // Typed failure (TSA unreachable / missing URL) — preserve its precise
        // kind. MUST precede the std::exception arm, same as sign().
        return makeFailure(e.kind, e.what());
    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("CAdES appendSigner error: ") + e.what());
    }
}

} // namespace libresign

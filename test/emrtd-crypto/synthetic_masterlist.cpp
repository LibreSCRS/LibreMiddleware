// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "synthetic_masterlist.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <ctime>
#include <filesystem>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <utility>

namespace LibreSCRS::Test {
namespace {

// ---------------------------------------------------------------------------
// RAII wrappers
//
// Deliberately local. EMRTDCryptoTests sees only ../lib/emrtd-crypto/src, whose
// wrappers are internal to passive_auth.cpp, and libresign's openssl_raii.h
// belongs to a different library and must not be pulled across.
// ---------------------------------------------------------------------------

struct Asn1ObjectDeleter
{
    void operator()(ASN1_OBJECT* p) const
    {
        ASN1_OBJECT_free(p);
    }
};

struct Asn1TimeDeleter
{
    void operator()(ASN1_TIME* p) const
    {
        ASN1_TIME_free(p);
    }
};

struct BignumDeleter
{
    void operator()(BIGNUM* p) const
    {
        BN_free(p);
    }
};

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

struct EVPPKeyDeleter
{
    void operator()(EVP_PKEY* p) const
    {
        EVP_PKEY_free(p);
    }
};

struct X509Deleter
{
    void operator()(X509* p) const
    {
        X509_free(p);
    }
};

using Asn1ObjectPtr = std::unique_ptr<ASN1_OBJECT, Asn1ObjectDeleter>;
using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Asn1TimeDeleter>;
using BignumPtr = std::unique_ptr<BIGNUM, BignumDeleter>;
using BIOPtr = std::unique_ptr<BIO, BIODeleter>;
using CMSPtr = std::unique_ptr<CMS_ContentInfo, CMSDeleter>;
using EVPPKeyPtr = std::unique_ptr<EVP_PKEY, EVPPKeyDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

/// The ICAO CscaMasterList content type, `data/oid-database/icao-9303.tsv`.
constexpr const char* kCscaMasterListOid = "2.23.136.1.1.2";

/// How far back every certificate's notBefore is placed, and how far forward
/// its notAfter goes when the caller does not name one. See makeCert().
constexpr long kBackdate = 15L * 365 * 24 * 3600;
constexpr long kForwardValidity = 10L * 365 * 24 * 3600;

[[noreturn]] void fail(const char* what)
{
    throw std::runtime_error(std::string("synthetic master list: ") + what);
}

std::string randomHex(std::size_t bytes)
{
    std::vector<unsigned char> raw(bytes);
    if (RAND_bytes(raw.data(), static_cast<int>(raw.size())) != 1) {
        fail("RAND_bytes failed");
    }
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes * 2);
    for (const unsigned char b : raw) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

std::vector<uint8_t> sha256(const uint8_t* data, std::size_t len)
{
    std::vector<uint8_t> out(EVP_MAX_MD_SIZE);
    unsigned int outLen = 0;
    if (EVP_Digest(data, len, out.data(), &outLen, EVP_sha256(), nullptr) != 1) {
        fail("EVP_Digest failed");
    }
    out.resize(outLen);
    return out;
}

// --- DER assembly ----------------------------------------------------------

void appendDerLength(std::vector<uint8_t>& out, std::size_t len)
{
    if (len < 0x80) {
        out.push_back(static_cast<uint8_t>(len));
        return;
    }
    std::vector<uint8_t> be;
    for (std::size_t v = len; v != 0; v >>= 8) {
        be.push_back(static_cast<uint8_t>(v & 0xFF));
    }
    out.push_back(static_cast<uint8_t>(0x80 | be.size()));
    out.insert(out.end(), be.rbegin(), be.rend());
}

std::vector<uint8_t> derWrap(uint8_t tag, const std::vector<uint8_t>& content)
{
    std::vector<uint8_t> out;
    out.push_back(tag);
    appendDerLength(out, content.size());
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

/// Reads the DER length starting at @p pos; returns (length, length-byte count).
std::pair<std::size_t, std::size_t> readDerLength(const std::vector<uint8_t>& der, std::size_t pos)
{
    if (pos >= der.size()) {
        fail("truncated DER length");
    }
    const uint8_t first = der[pos];
    if (first < 0x80) {
        return {first, 1};
    }
    const std::size_t count = first & 0x7F;
    if (count == 0 || count > sizeof(std::size_t) || pos + 1 + count > der.size()) {
        fail("unsupported DER length");
    }
    std::size_t len = 0;
    for (std::size_t i = 0; i < count; ++i) {
        len = (len << 8) | der[pos + 1 + i];
    }
    return {len, count + 1};
}

/// Offset of the LAST byte of the serialNumber VALUE inside a DER Certificate.
///
/// Hand-parsed rather than searched for: an i2d'd serialNumber could in
/// principle occur elsewhere in the encoding, and the tamper must land in the
/// serial or the length changes.
///
/// The last byte, not the first, and both halves of that matter. Flipping the
/// first byte can reorder the anchor against its neighbour in the DER SET OF
/// (a low bit carries the smallest encoding past a neighbour one greater),
/// which turns a bad-signature fixture into a malformed-encoding one. Flipping
/// the last byte leaves the ordering to an earlier byte, which differs between
/// two 15-byte random serials with probability 1 - 2^-112. Minimality is
/// governed by the leading byte alone, so it is untouched either way.
std::size_t serialValueOffset(const std::vector<uint8_t>& certDer)
{
    std::size_t pos = 0;
    const auto enterSequence = [&] {
        if (pos >= certDer.size() || certDer[pos] != 0x30) {
            fail("certificate is not a SEQUENCE");
        }
        ++pos;
        pos += readDerLength(certDer, pos).second;
    };

    enterSequence(); // Certificate
    enterSequence(); // tbsCertificate

    if (pos < certDer.size() && certDer[pos] == 0xA0) { // [0] EXPLICIT version
        ++pos;
        const auto [len, lenBytes] = readDerLength(certDer, pos);
        pos += lenBytes + len;
    }
    if (pos >= certDer.size() || certDer[pos] != 0x02) {
        fail("tbsCertificate does not start with serialNumber");
    }
    ++pos;
    const auto [serialLen, serialLenBytes] = readDerLength(certDer, pos);
    pos += serialLenBytes;
    if (serialLen == 0 || pos + serialLen > certDer.size()) {
        fail("truncated serialNumber");
    }
    return pos + serialLen - 1;
}

// --- certificates ----------------------------------------------------------

struct Cert
{
    X509Ptr x;
    EVPPKeyPtr key;
};

struct CertRequest
{
    std::string commonName;
    bool ca = false;
    const Cert* issuer = nullptr;          ///< nullptr: self-signed with its own key
    const X509_NAME* issuerName = nullptr; ///< nullptr: the issuer's (or its own) subject
    std::string keyUsage;
    std::string ekuOid;
    std::string notAfter; ///< empty: one year from now
    /// nullptr: mint a fresh key and name the certificate after commonName.
    /// Otherwise this is a LINK CERTIFICATE for that certificate and takes BOTH
    /// its subject name and its public key, so the two are interchangeable to a
    /// path builder; commonName is then unused. See
    /// makeMasterListWithLinkCertificate().
    const Cert* sameSubjectAndKeyAs = nullptr;
};

void addExtension(X509* cert, X509* issuer, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, issuer, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    if (ext == nullptr) {
        fail("X509V3_EXT_conf_nid failed");
    }
    const int added = X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    if (added != 1) {
        fail("X509_add_ext failed");
    }
}

/// A 119-bit serial: exactly 15 bytes, top bit clear, so DER adds no leading
/// 0x00 pad. Both halves serve makeTamperedMasterList, which flips a bit in the
/// LAST value byte. The fixed multi-byte width keeps that byte from ever also
/// being the leading one, and the absent pad means the leading byte is a real
/// magnitude byte — so the encoding stays minimal whatever happens at the tail.
void setRandomSerial(X509* cert)
{
    BignumPtr bn(BN_new());
    if (!bn || BN_rand(bn.get(), 119, BN_RAND_TOP_ONE, BN_RAND_BOTTOM_ANY) != 1) {
        fail("BN_rand failed");
    }
    if (BN_to_ASN1_INTEGER(bn.get(), X509_get_serialNumber(cert)) == nullptr) {
        fail("BN_to_ASN1_INTEGER failed");
    }
}

Cert makeCert(const CertRequest& req)
{
    Cert out;
    if (req.sameSubjectAndKeyAs != nullptr) {
        // A link certificate carries the key it links TO, not one of its own:
        // the SubjectPublicKeyInfo is the same object, so a document signer
        // issued under either certificate verifies against either.
        if (EVP_PKEY_up_ref(req.sameSubjectAndKeyAs->key.get()) != 1) {
            fail("EVP_PKEY_up_ref failed");
        }
        out.key.reset(req.sameSubjectAndKeyAs->key.get());
    } else {
        out.key.reset(EVP_EC_gen("P-256"));
    }
    out.x.reset(X509_new());
    if (!out.key || !out.x) {
        fail("key or certificate allocation failed");
    }

    X509_set_version(out.x.get(), 2); // v3
    setRandomSerial(out.x.get());

    // Every certificate here is backdated fifteen years, the window a real CSCA
    // carries. Without it nothing can be verified AT SIGNING TIME, which is how
    // ICAO accepts an expired document signer on a still-valid passport: a
    // chain validated at a past date would fall over on the anchor with
    // "certificate is not yet valid" instead of proving anything about the DSC.
    // A supplied notAfter is normally in the past for the same reason, so the
    // start has to sit well before it either way.
    X509_gmtime_adj(X509_getm_notBefore(out.x.get()), -kBackdate);
    if (req.notAfter.empty()) {
        X509_gmtime_adj(X509_getm_notAfter(out.x.get()), kForwardValidity);
    } else if (ASN1_TIME_set_string(X509_getm_notAfter(out.x.get()), req.notAfter.c_str()) != 1) {
        fail("ASN1_TIME_set_string rejected the supplied notAfter");
    }

    if (X509_set_pubkey(out.x.get(), out.key.get()) != 1) {
        fail("X509_set_pubkey failed");
    }

    if (req.sameSubjectAndKeyAs != nullptr) {
        // Copied whole, not rebuilt from parts: the two subjects have to compare
        // equal under X509_NAME_cmp, which a re-entered name would not
        // guarantee if the string types ever differed.
        if (X509_set_subject_name(out.x.get(), X509_get_subject_name(req.sameSubjectAndKeyAs->x.get())) != 1) {
            fail("X509_set_subject_name failed");
        }
    } else {
        X509_NAME* subject = X509_get_subject_name(out.x.get());
        X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, reinterpret_cast<const unsigned char*>("XX"), -1, -1, 0);
        X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>(req.commonName.c_str()), -1, -1, 0);
    }

    X509* issuerCert = req.issuer != nullptr ? req.issuer->x.get() : out.x.get();
    const X509_NAME* issuerName = req.issuerName != nullptr ? req.issuerName : X509_get_subject_name(issuerCert);
    if (X509_set_issuer_name(out.x.get(), const_cast<X509_NAME*>(issuerName)) != 1) {
        fail("X509_set_issuer_name failed");
    }

    // No subjectKeyIdentifier / authorityKeyIdentifier anywhere: chains here
    // are meant to be selected by DN alone, so that the impersonated-issuer SOD
    // reaches the signature check instead of being dropped on a key-id
    // mismatch.
    addExtension(out.x.get(), issuerCert, NID_basic_constraints, req.ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    if (!req.keyUsage.empty()) {
        addExtension(out.x.get(), issuerCert, NID_key_usage, req.keyUsage.c_str());
    }
    if (!req.ekuOid.empty()) {
        addExtension(out.x.get(), issuerCert, NID_ext_key_usage, req.ekuOid.c_str());
    }

    EVP_PKEY* signingKey = req.issuer != nullptr ? req.issuer->key.get() : out.key.get();
    if (X509_sign(out.x.get(), signingKey, EVP_sha256()) == 0) {
        fail("X509_sign failed");
    }
    return out;
}

std::vector<uint8_t> certDer(X509* cert)
{
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert, &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_X509 failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

std::vector<uint8_t> spkiSha256(X509* cert)
{
    X509_PUBKEY* spki = X509_get_X509_PUBKEY(cert);
    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(spki, &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_X509_PUBKEY failed");
    }
    std::vector<uint8_t> out = sha256(der, static_cast<std::size_t>(len));
    OPENSSL_free(der);
    return out;
}

// --- the anchor key registry -----------------------------------------------
//
// makeSod has to ISSUE a DSC from ml.cscaDer[anchorIndex], so it needs that
// anchor's private key — and SyntheticMasterList carries certificates only.
// Rather than widen the struct, the generator remembers the key of every anchor
// it minted, keyed by the certificate's own encoding. Process-lifetime state in
// a test fixture, not in any shipped surface.

std::mutex& anchorKeysMutex()
{
    static std::mutex mutex;
    return mutex;
}

std::map<std::vector<uint8_t>, EVPPKeyPtr>& anchorKeys()
{
    static std::map<std::vector<uint8_t>, EVPPKeyPtr> keys;
    return keys;
}

void rememberAnchorKey(const std::vector<uint8_t>& der, EVP_PKEY* key)
{
    if (EVP_PKEY_up_ref(key) != 1) {
        fail("EVP_PKEY_up_ref failed");
    }
    const std::lock_guard<std::mutex> lock(anchorKeysMutex());
    anchorKeys().insert_or_assign(der, EVPPKeyPtr(key));
}

/// The anchor's certificate alone. Enough to READ it — its subject name, say —
/// and it works on any list, including one rebuilt from PEM files on disk.
Cert anchorCertificateOnly(const SyntheticMasterList& ml, int anchorIndex)
{
    if (anchorIndex < 0 || static_cast<std::size_t>(anchorIndex) >= ml.cscaDer.size()) {
        fail("anchorIndex is out of range");
    }
    const std::vector<uint8_t>& der = ml.cscaDer[static_cast<std::size_t>(anchorIndex)];

    Cert out;
    const unsigned char* p = der.data();
    out.x.reset(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (!out.x) {
        fail("d2i_X509 failed on an anchor");
    }
    return out;
}

/// The anchor plus its private key, so a DSC can be ISSUED from it. Only a list
/// minted in this process has a remembered key.
Cert anchorCert(const SyntheticMasterList& ml, int anchorIndex)
{
    Cert out = anchorCertificateOnly(ml, anchorIndex);
    const std::vector<uint8_t>& der = ml.cscaDer[static_cast<std::size_t>(anchorIndex)];

    const std::lock_guard<std::mutex> lock(anchorKeysMutex());
    const auto it = anchorKeys().find(der);
    if (it == anchorKeys().end()) {
        fail("no private key remembered for this anchor: it was not minted in this process");
    }
    if (EVP_PKEY_up_ref(it->second.get()) != 1) {
        fail("EVP_PKEY_up_ref failed");
    }
    out.key.reset(it->second.get());
    return out;
}

// --- CMS -------------------------------------------------------------------

/// Which `signingTime` the SIGNED attributes of an object this file signs
/// carry.
///
/// Three cases and not a flag, because none of them is the absence of another.
/// `Current` is what OpenSSL does unbidden -- it adds a signingTime of `now`
/// whenever it finds none -- and is what every object here carried before this
/// existed. `Fixed` is the only way to get an instant a test can compare with a
/// literal. `None` needs CMS_NO_SIGNING_TIME, since leaving something out is
/// precisely what produces `Current`.
struct SigningTimeChoice
{
    enum class Kind : uint8_t {
        Current,
        Fixed,
        None,
    };

    Kind kind = Kind::Current;
    int64_t epochSeconds = 0;
};

/// Puts exactly @p epochSeconds into the SIGNED signingTime attribute of every
/// SignerInfo of @p cms, which must not have been finalised yet.
///
/// Before CMS_final and not after: the attribute is under the signature, so one
/// planted afterwards would only invalidate it. Setting it here is also what
/// keeps OpenSSL from planting its own -- it adds a signingTime of `now` only
/// when it finds none.
void setSignedSigningTime(CMS_ContentInfo* cms, int64_t epochSeconds)
{
    STACK_OF(CMS_SignerInfo)* signerInfos = CMS_get0_SignerInfos(cms);
    if (sk_CMS_SignerInfo_num(signerInfos) <= 0) {
        fail("no SignerInfo to give a signingTime to");
    }
    const Asn1TimePtr when(ASN1_TIME_set(nullptr, static_cast<time_t>(epochSeconds)));
    if (!when) {
        fail("ASN1_TIME_set failed");
    }
    for (int i = 0; i < sk_CMS_SignerInfo_num(signerInfos); ++i) {
        // The (type, value, -1) form, which is what OpenSSL uses for this very
        // attribute: with a length of -1 the value handed over is the
        // ASN1_STRING itself rather than raw content bytes.
        if (CMS_signed_add1_attr_by_NID(sk_CMS_SignerInfo_value(signerInfos, i), NID_pkcs9_signingTime, when->type,
                                        when.get(), -1) != 1) {
            fail("CMS_signed_add1_attr_by_NID(signingTime) failed");
        }
    }
}

/// @param eContentTypeOid nullptr keeps the CMS default, id-data.
/// @param signingTime which signingTime the signed attributes carry; see
///        SigningTimeChoice. Anything but `Current` needs the CMS_PARTIAL path,
///        i.e. an @p eContentTypeOid, because the SignerInfo has to be reached
///        before it is signed.
std::vector<uint8_t> signCms(const Cert& signer, const std::vector<uint8_t>& content, const char* eContentTypeOid,
                             SigningTimeChoice signingTime = {})
{
    BIOPtr bio(BIO_new_mem_buf(content.data(), static_cast<int>(content.size())));
    if (!bio) {
        fail("BIO_new_mem_buf failed");
    }

    if (signingTime.kind == SigningTimeChoice::Kind::Fixed && eContentTypeOid == nullptr) {
        fail("a fixed signingTime needs the CMS_PARTIAL path, which only an eContentType caller takes");
    }

    int flags = CMS_BINARY | CMS_NOSMIMECAP;
    if (signingTime.kind == SigningTimeChoice::Kind::None) {
        // The flag, not an omission: without it CMS_sign puts the current time
        // in the signed attributes on its own.
        flags |= CMS_NO_SIGNING_TIME;
    }
    if (eContentTypeOid != nullptr) {
        // CMS_PARTIAL is mandatory here: without it CMS_sign finalises at once,
        // CMS_set1_eContentType no longer has any effect, and nothing could
        // tell a master list from anything else. The contentType signed
        // attribute is copied from the eContentType at CMS_final time, so
        // setting it in between is what makes the two agree.
        flags |= CMS_PARTIAL;
    }

    CMSPtr cms(CMS_sign(signer.x.get(), signer.key.get(), nullptr, bio.get(), flags));
    if (!cms) {
        fail("CMS_sign failed");
    }

    if (eContentTypeOid != nullptr) {
        Asn1ObjectPtr oid(OBJ_txt2obj(eContentTypeOid, 1));
        if (!oid || CMS_set1_eContentType(cms.get(), oid.get()) != 1) {
            fail("CMS_set1_eContentType failed");
        }
        if (signingTime.kind == SigningTimeChoice::Kind::Fixed) {
            setSignedSigningTime(cms.get(), signingTime.epochSeconds);
        }
        if (CMS_final(cms.get(), bio.get(), nullptr, CMS_BINARY) != 1) {
            fail("CMS_final failed");
        }
    }

    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms.get(), &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_CMS_ContentInfo failed");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// @return @p cmsDer re-encoded with @p cert dropped into its
///         SignedData.certificates.
/// @note The signature is neither recomputed nor disturbed, and that is the
///       whole point: the certificate bag is outside everything a SignedData
///       signature covers, so a document stays verifiable after anybody at all
///       has added to it.
std::vector<uint8_t> addToCertificateBag(const std::vector<uint8_t>& cmsDer, X509* cert)
{
    BIOPtr bio(BIO_new_mem_buf(cmsDer.data(), static_cast<int>(cmsDer.size())));
    if (!bio) {
        fail("BIO_new_mem_buf failed while planting a certificate");
    }
    CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
    if (!cms) {
        fail("d2i_CMS_bio failed while planting a certificate");
    }
    if (CMS_add1_cert(cms.get(), cert) != 1) {
        fail("CMS_add1_cert failed");
    }

    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms.get(), &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_CMS_ContentInfo failed after planting a certificate");
    }
    std::vector<uint8_t> out(der, der + len);
    OPENSSL_free(der);
    return out;
}

/// SignedData.certificates as encoded, in the order a reader of @p cmsDer
/// meets them. Read back off the produced bytes rather than remembered from
/// the way they were built, because the DER SET OF order is decided by the
/// encoder and is exactly the thing a caller here needs told.
std::vector<std::vector<uint8_t>> certificateBagOf(const std::vector<uint8_t>& cmsDer)
{
    BIOPtr bio(BIO_new_mem_buf(cmsDer.data(), static_cast<int>(cmsDer.size())));
    if (!bio) {
        fail("BIO_new_mem_buf failed while reading a certificate bag");
    }
    CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
    if (!cms) {
        fail("d2i_CMS_bio failed while reading a certificate bag");
    }

    STACK_OF(X509)* certs = CMS_get1_certs(cms.get());
    std::vector<std::vector<uint8_t>> out;
    for (int i = 0; i < sk_X509_num(certs); ++i) {
        out.push_back(certDer(sk_X509_value(certs, i)));
    }
    // sk_X509_pop_free, unlike the stack CMS_get0_signers hands back:
    // CMS_get1_certs takes a reference on every certificate it returns, so
    // these are ours to free.
    sk_X509_pop_free(certs, X509_free);
    return out;
}

// --- CscaMasterList --------------------------------------------------------

struct MasterListContent
{
    std::vector<uint8_t> der;
    std::size_t serialOffset = 0; ///< 0 when the list carries no anchor
};

/// CscaMasterList ::= SEQUENCE { version INTEGER, certificates SET OF Certificate }
///
/// Assembled by hand: OpenSSL has no ASN1_ITEM for it.
/// @param sortedCerts anchors already in ascending encoding order. DER SET OF
///        demands that order; an unsorted SET would only ever work against the
///        parser that produced it.
MasterListContent buildMasterListContent(const std::vector<std::vector<uint8_t>>& sortedCerts)
{
    std::vector<uint8_t> certsBlob;
    for (const std::vector<uint8_t>& cert : sortedCerts) {
        certsBlob.insert(certsBlob.end(), cert.begin(), cert.end());
    }
    const std::vector<uint8_t> certSet = derWrap(0x31, certsBlob);

    std::vector<uint8_t> body{0x02, 0x01, 0x00}; // version v0
    const std::size_t setOffsetInBody = body.size();
    body.insert(body.end(), certSet.begin(), certSet.end());

    MasterListContent out;
    out.der = derWrap(0x30, body);
    if (!sortedCerts.empty()) {
        const std::size_t bodyOffset = out.der.size() - body.size();
        const std::size_t setHeader = certSet.size() - certsBlob.size();
        out.serialOffset = bodyOffset + setOffsetInBody + setHeader + serialValueOffset(sortedCerts.front());
    }
    return out;
}

/// Absolute offset of @p content inside @p cmsDer. CMS_BINARY plus a definite
/// length i2d embeds the eContent as one contiguous OCTET STRING, so the signed
/// bytes appear verbatim.
std::size_t contentOffsetIn(const std::vector<uint8_t>& cmsDer, const std::vector<uint8_t>& content)
{
    const auto it = std::search(cmsDer.begin(), cmsDer.end(), content.begin(), content.end());
    if (it == cmsDer.end()) {
        fail("the signed content is not embedded in the CMS encoding");
    }
    return static_cast<std::size_t>(std::distance(cmsDer.begin(), it));
}

Cert makeCsca(int index)
{
    // The random suffix keeps two lists minted in one test process from sharing
    // a subject DN, which would make a store lookup ambiguous.
    return makeCert({.commonName = "Synthetic CSCA " + std::to_string(index) + " " + randomHex(4),
                     .ca = true,
                     .issuer = nullptr,
                     .issuerName = nullptr,
                     .keyUsage = "critical,keyCertSign,cRLSign",
                     .ekuOid = {},
                     .notAfter = {}});
}

/// Mints a fresh signing CA plus its master list signer and signs @p anchors.
/// @param anchors already sorted; taken by value because it becomes cscaDer.
/// @param signerNotAfter empty keeps the default forward validity; see
///        makeMasterList. Only the SIGNER takes it, not the CA above it: a
///        signer whose key has rotated out is the ordinary case, and expiring
///        the CA with it would confuse two different things.
SyntheticMasterList signMasterList(std::vector<std::vector<uint8_t>> anchors, const std::string& signerNotAfter = {},
                                   const std::string& signerEku = {}, SigningTimeChoice signingTime = {})
{
    // Step one, and the one that must not be relaxed: the signer's CA is NOT an
    // anchor in the list it signs.
    const Cert mlRoot = makeCert({.commonName = "Synthetic Master List CA " + randomHex(4),
                                  .ca = true,
                                  .issuer = nullptr,
                                  .issuerName = nullptr,
                                  .keyUsage = "critical,keyCertSign,cRLSign",
                                  .ekuOid = {},
                                  .notAfter = {}});
    const Cert mlSigner = makeCert({.commonName = "Synthetic Master List Signer " + randomHex(4),
                                    .ca = false,
                                    .issuer = &mlRoot,
                                    .issuerName = nullptr,
                                    .keyUsage = "critical,digitalSignature",
                                    .ekuOid = signerEku,
                                    .notAfter = signerNotAfter});

    const MasterListContent content = buildMasterListContent(anchors);

    SyntheticMasterList out;
    out.cscaDer = std::move(anchors);
    out.der = signCms(mlSigner, content.der, kCscaMasterListOid, signingTime);
    out.signerSpkiSha256 = spkiSha256(mlSigner.x.get());
    if (content.serialOffset != 0) {
        out.eContentTamperOffset = contentOffsetIn(out.der, content.der) + content.serialOffset;
    }
    return out;
}

/// The anchors a fixture list carries: @p cscaCount freshly minted CSCAs,
/// each with its private key remembered, sorted into the DER SET OF order the
/// list has to carry them in.
std::vector<std::vector<uint8_t>> mintAnchors(int cscaCount)
{
    if (cscaCount < 0) {
        fail("cscaCount must not be negative");
    }

    std::vector<std::vector<uint8_t>> anchors;
    anchors.reserve(static_cast<std::size_t>(cscaCount));
    for (int i = 0; i < cscaCount; ++i) {
        const Cert csca = makeCsca(i);
        std::vector<uint8_t> der = certDer(csca.x.get());
        rememberAnchorKey(der, csca.key.get());
        anchors.push_back(std::move(der));
    }
    std::sort(anchors.begin(), anchors.end());
    return anchors;
}

/// Whether the first SignerInfo of @p cmsDer carries a signingTime among its
/// UNSIGNED attributes. Read back off the produced bytes, so that a decoy that
/// did not survive re-encoding is caught where it was planted.
bool carriesUnsignedSigningTime(const std::vector<uint8_t>& cmsDer)
{
    BIOPtr bio(BIO_new_mem_buf(cmsDer.data(), static_cast<int>(cmsDer.size())));
    if (!bio) {
        fail("BIO_new_mem_buf failed while reading back a decoy signingTime");
    }
    CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
    if (!cms) {
        fail("d2i_CMS_bio failed while reading back a decoy signingTime");
    }
    STACK_OF(CMS_SignerInfo)* signerInfos = CMS_get0_SignerInfos(cms.get());
    if (sk_CMS_SignerInfo_num(signerInfos) <= 0) {
        return false;
    }
    return CMS_unsigned_get_attr_by_NID(sk_CMS_SignerInfo_value(signerInfos, 0), NID_pkcs9_signingTime, -1) >= 0;
}

/// The one data group the security object below covers, and its number. At
/// file scope rather than inside the builder because a caller that wants the
/// hash to come out right has to hand a verifier THESE bytes; two copies would
/// be two things to keep in step.
constexpr int kDataGroup1Number = 1;
constexpr uint8_t kDataGroup1[] = {0x61, 0x03, 0x5F, 0x01, 0x00};

/// LDSSecurityObject ::= SEQUENCE { version, hashAlgorithm, dataGroupHashValues }
/// One data group is enough; nothing here is about the number of them.
std::vector<uint8_t> buildLdsSecurityObject()
{
    static constexpr uint8_t kSha256Algorithm[] = {0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
                                                   0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00};

    std::vector<uint8_t> body{0x02, 0x01, 0x00}; // version v0
    body.insert(body.end(), std::begin(kSha256Algorithm), std::end(kSha256Algorithm));

    std::vector<uint8_t> hashEntry{0x02, 0x01, static_cast<uint8_t>(kDataGroup1Number)};
    const std::vector<uint8_t> digest = sha256(kDataGroup1, sizeof(kDataGroup1));
    const std::vector<uint8_t> digestOctets = derWrap(0x04, digest);
    hashEntry.insert(hashEntry.end(), digestOctets.begin(), digestOctets.end());

    const std::vector<uint8_t> hashValues = derWrap(0x30, derWrap(0x30, hashEntry));
    body.insert(body.end(), hashValues.begin(), hashValues.end());

    return derWrap(0x30, body);
}

/// The data groups buildLdsSecurityObject() hashed, keyed by number and as
/// hashed, ready to be handed to a verifier alongside the object itself.
std::map<int, std::vector<uint8_t>> ldsDataGroups()
{
    return {{kDataGroup1Number, std::vector<uint8_t>(std::begin(kDataGroup1), std::end(kDataGroup1))}};
}

} // namespace

// ---------------------------------------------------------------------------
// Public fixture API
// ---------------------------------------------------------------------------

SyntheticMasterList makeMasterList(int cscaCount, const std::string& signerNotAfter, const std::string& signerEku)
{
    return signMasterList(mintAnchors(cscaCount), signerNotAfter, signerEku);
}

SyntheticMasterList makeMasterListSignedAt(int cscaCount, int64_t signingTimeEpochSeconds)
{
    return signMasterList(mintAnchors(cscaCount), {}, {}, {SigningTimeChoice::Kind::Fixed, signingTimeEpochSeconds});
}

SyntheticMasterList makeMasterListWithoutSigningTime(int cscaCount)
{
    return signMasterList(mintAnchors(cscaCount), {}, {}, {SigningTimeChoice::Kind::None, 0});
}

SyntheticMasterList makeMasterListWithSigningTimeInUnsignedAttributes(const SyntheticMasterList& ml,
                                                                      int64_t decoyEpochSeconds)
{
    BIOPtr bio(BIO_new_mem_buf(ml.der.data(), static_cast<int>(ml.der.size())));
    if (!bio) {
        fail("BIO_new_mem_buf failed while planting a signingTime");
    }
    CMSPtr cms(d2i_CMS_bio(bio.get(), nullptr));
    if (!cms) {
        fail("d2i_CMS_bio failed while planting a signingTime");
    }

    STACK_OF(CMS_SignerInfo)* signerInfos = CMS_get0_SignerInfos(cms.get());
    if (sk_CMS_SignerInfo_num(signerInfos) != 1) {
        fail("a decoy signingTime needs a list carrying exactly one SignerInfo");
    }
    CMS_SignerInfo* signerInfo = sk_CMS_SignerInfo_value(signerInfos, 0);

    const Asn1TimePtr decoy(ASN1_TIME_set(nullptr, static_cast<time_t>(decoyEpochSeconds)));
    if (!decoy) {
        fail("ASN1_TIME_set failed");
    }

    // A decoy equal to the value it is meant to be mistaken for stages
    // nothing, so the two are COMPARED rather than assumed to differ.
    const int signedIndex = CMS_signed_get_attr_by_NID(signerInfo, NID_pkcs9_signingTime, -1);
    if (signedIndex < 0) {
        fail("the list carries no signed signingTime for a decoy to differ from");
    }
    const ASN1_TYPE* signedValue = X509_ATTRIBUTE_get0_type(CMS_signed_get_attr(signerInfo, signedIndex), 0);
    if (signedValue == nullptr || signedValue->value.asn1_string == nullptr) {
        fail("the signed signingTime carries no value");
    }
    const int order = ASN1_TIME_compare(decoy.get(), signedValue->value.asn1_string);
    if (order == -2) {
        fail("the two signing times could not be compared");
    }
    if (order == 0) {
        fail("the decoy signingTime equals the signed one, so it stages nothing");
    }

    if (CMS_unsigned_add1_attr_by_NID(signerInfo, NID_pkcs9_signingTime, decoy->type, decoy.get(), -1) != 1) {
        fail("CMS_unsigned_add1_attr_by_NID(signingTime) failed");
    }

    unsigned char* der = nullptr;
    const int len = i2d_CMS_ContentInfo(cms.get(), &der);
    if (len <= 0 || der == nullptr) {
        fail("i2d_CMS_ContentInfo failed after planting a signingTime");
    }
    SyntheticMasterList out = ml;
    out.der.assign(der, der + len);
    OPENSSL_free(der);
    // The extra attribute shifts every offset after it; see the header.
    out.eContentTamperOffset = 0;

    if (out.der == ml.der) {
        fail("planting the decoy signingTime changed nothing");
    }
    if (!carriesUnsignedSigningTime(out.der)) {
        fail("the decoy signingTime did not survive re-encoding");
    }
    return out;
}

SyntheticMasterList makeMasterListWithOtherSigner(const SyntheticMasterList& base)
{
    // Anything from makeMasterList is already sorted, so re-encoding reproduces
    // the previous eContent byte for byte and only the signer differs. A
    // hand-built base is sorted here rather than trusted, because an unsorted
    // SET OF is not DER and would only ever parse against its own producer.
    std::vector<std::vector<uint8_t>> anchors = base.cscaDer;
    std::sort(anchors.begin(), anchors.end());
    return signMasterList(std::move(anchors));
}

std::vector<uint8_t> masterListSignerCertificateDer(const SyntheticMasterList& ml)
{
    const auto bag = certificateBagOf(ml.der);
    if (bag.size() != 1) {
        fail("masterListSignerCertificateDer: a list this file signed carries exactly its signer");
    }
    return bag.front();
}

SyntheticCscaRotation makeMasterListWithLinkCertificate()
{
    const Cert outgoing = makeCsca(0);
    const Cert incoming = makeCsca(1);
    // The link certificate: the INCOMING CSCA's subject and key, signed by the
    // OUTGOING key. Not self-signed, which is the whole reason it exists here --
    // see makeMasterListWithLinkCertificate() in the header.
    const Cert link = makeCert({.commonName = {},
                                .ca = true,
                                .issuer = &outgoing,
                                .issuerName = nullptr,
                                .keyUsage = "critical,keyCertSign,cRLSign",
                                .ekuOid = {},
                                .notAfter = {},
                                .sameSubjectAndKeyAs = &incoming});

    const std::vector<uint8_t> outgoingDer = certDer(outgoing.x.get());
    const std::vector<uint8_t> incomingDer = certDer(incoming.x.get());
    const std::vector<uint8_t> linkDer = certDer(link.x.get());
    rememberAnchorKey(outgoingDer, outgoing.key.get());
    rememberAnchorKey(incomingDer, incoming.key.get());
    // The SAME key under a second encoding, deliberately, and through the one
    // registry the rest of this file uses rather than a mechanism of its own: a
    // document signer issued "from the link certificate" is issued by the
    // incoming CSCA, because they are one key.
    rememberAnchorKey(linkDer, link.key.get());

    std::vector<std::vector<uint8_t>> anchors{outgoingDer, incomingDer, linkDer};
    std::sort(anchors.begin(), anchors.end());

    const auto indexOf = [&anchors](const std::vector<uint8_t>& der) {
        const auto it = std::find(anchors.begin(), anchors.end(), der);
        if (it == anchors.end()) {
            fail("an anchor went missing from the rotation");
        }
        return static_cast<int>(std::distance(anchors.begin(), it));
    };

    SyntheticCscaRotation out;
    out.outgoingIndex = indexOf(outgoingDer);
    out.incomingIndex = indexOf(incomingDer);
    out.linkIndex = indexOf(linkDer);
    out.list = signMasterList(std::move(anchors));
    return out;
}

std::vector<uint8_t> makeSignedNonMasterList()
{
    // The content IS a well-formed CscaMasterList, so the content type is the
    // only thing that gives it away.
    const Cert csca = makeCsca(0);
    const MasterListContent content = buildMasterListContent({certDer(csca.x.get())});

    const Cert signer = makeCert({.commonName = "Synthetic Plain Signer " + randomHex(4),
                                  .ca = false,
                                  .issuer = nullptr,
                                  .issuerName = nullptr,
                                  .keyUsage = "critical,digitalSignature",
                                  .ekuOid = {},
                                  .notAfter = {}});
    return signCms(signer, content.der, nullptr);
}

SyntheticMasterList makeTamperedMasterList(const SyntheticMasterList& ml)
{
    if (ml.eContentTamperOffset == 0 || ml.eContentTamperOffset >= ml.der.size()) {
        fail("this master list carries no anchor to tamper with");
    }
    SyntheticMasterList out = ml;
    out.der[out.eContentTamperOffset] ^= 0x01;
    return out;
}

std::string writePemDir(const std::vector<std::vector<uint8_t>>& certsDer)
{
    const std::filesystem::path dir = std::filesystem::temp_directory_path() / ("librescrs-csca-" + randomHex(8));
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    if (ec) {
        fail("could not create the PEM directory");
    }

    for (std::size_t i = 0; i < certsDer.size(); ++i) {
        const unsigned char* p = certsDer[i].data();
        X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(certsDer[i].size())));
        if (!cert) {
            fail("d2i_X509 failed while writing the PEM directory");
        }
        const std::filesystem::path file = dir / (std::to_string(i) + ".pem");
        BIOPtr out(BIO_new_file(file.string().c_str(), "w"));
        if (!out || PEM_write_bio_X509(out.get(), cert.get()) != 1) {
            fail("PEM_write_bio_X509 failed");
        }
    }
    return dir.string();
}

std::map<int, std::vector<uint8_t>> sodDataGroups()
{
    return ldsDataGroups();
}

std::vector<uint8_t> makeCertificateIssuedByAnchor(const SyntheticMasterList& ml, int anchorIndex,
                                                   const std::string& notAfter)
{
    const Cert anchor = anchorCert(ml, anchorIndex);
    const Cert leaf = makeCert({.commonName = "Synthetic Signer " + randomHex(4),
                                .ca = false,
                                .issuer = &anchor,
                                .issuerName = nullptr,
                                .keyUsage = "critical,digitalSignature",
                                .ekuOid = {},
                                .notAfter = notAfter});
    return certDer(leaf.x.get());
}

std::vector<uint8_t> makeSod(const SyntheticMasterList& ml, int anchorIndex, const std::string& dscEku,
                             const std::string& dscNotAfter)
{
    const Cert anchor = anchorCert(ml, anchorIndex);
    const Cert dsc = makeCert({.commonName = "Synthetic Document Signer " + randomHex(4),
                               .ca = false,
                               .issuer = &anchor,
                               .issuerName = nullptr,
                               .keyUsage = "critical,digitalSignature",
                               .ekuOid = dscEku,
                               .notAfter = dscNotAfter});
    return signCms(dsc, buildLdsSecurityObject(), nullptr);
}

std::vector<uint8_t> makeForgedSod()
{
    const Cert dsc = makeCert({.commonName = "Forged Document Signer " + randomHex(4),
                               .ca = false,
                               .issuer = nullptr,
                               .issuerName = nullptr,
                               .keyUsage = "critical,digitalSignature",
                               .ekuOid = {},
                               .notAfter = {}});
    return signCms(dsc, buildLdsSecurityObject(), nullptr);
}

std::vector<uint8_t> makeSodWithImpersonatedIssuer(const SyntheticMasterList& ml, int anchorIndex)
{
    // Only the anchor's NAME is impersonated, so its private key is not needed
    // and this works on a list rebuilt from disk.
    const Cert anchor = anchorCertificateOnly(ml, anchorIndex);
    // Its own key signs it, but it names the anchor as issuer: the DN prefilter
    // lets it through and the signature is what fails.
    const Cert dsc = makeCert({.commonName = "Impersonating Document Signer " + randomHex(4),
                               .ca = false,
                               .issuer = nullptr,
                               .issuerName = X509_get_subject_name(anchor.x.get()),
                               .keyUsage = "critical,digitalSignature",
                               .ekuOid = {},
                               .notAfter = {}});
    return signCms(dsc, buildLdsSecurityObject(), nullptr);
}

SyntheticSodWithImpostor makeSodWithImpostorPrependedToCertificateBag(const SyntheticMasterList& ml, int anchorIndex)
{
    const Cert anchor = anchorCert(ml, anchorIndex);

    SyntheticSodWithImpostor out;
    out.realSignerCommonName = "Synthetic Document Signer " + randomHex(4);
    // Short, and deliberately so: this is what puts the impostor at index 0 of
    // a SET OF nobody can order by hand. See the note on the declaration; the
    // check at the bottom of this function is what keeps the reasoning honest.
    out.impostorCommonName = "Impostor " + randomHex(4);

    const Cert dsc = makeCert({.commonName = out.realSignerCommonName,
                               .ca = false,
                               .issuer = &anchor,
                               .issuerName = nullptr,
                               .keyUsage = "critical,digitalSignature",
                               .ekuOid = {},
                               .notAfter = {}});
    // Self-signed, and issued by nobody the list knows: it has to be a
    // certificate that no verifier would ever arrive at on its own, so that
    // seeing its name in a result can only mean the bag was read.
    const Cert impostor = makeCert({.commonName = out.impostorCommonName,
                                    .ca = false,
                                    .issuer = nullptr,
                                    .issuerName = nullptr,
                                    .keyUsage = "critical,digitalSignature",
                                    .ekuOid = {},
                                    .notAfter = {}});

    // Signed first and planted afterwards, which is the order the attack
    // happens in: the document is genuine when it leaves the issuing state,
    // and what is added to the bag after that cannot disturb the signature.
    out.der = addToCertificateBag(signCms(dsc, buildLdsSecurityObject(), nullptr), impostor.x.get());
    out.dgs = ldsDataGroups();

    const std::vector<std::vector<uint8_t>> bag = certificateBagOf(out.der);
    if (bag.size() != 2) {
        fail("the impostor did not reach the certificate bag");
    }
    if (bag.front() != certDer(impostor.x.get())) {
        fail("the impostor did not sort first in the certificate bag; the two common names have drifted in length");
    }
    return out;
}

} // namespace LibreSCRS::Test

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "csca_master_list.h"

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/cms.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <climits>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <optional>
#include <utility>

namespace emrtd::crypto {

// Internal linkage throughout: passive_auth.cpp already defines its own
// deleters and its own error-queue bracket at namespace scope in this same
// namespace, and two differing definitions of one name would be an ODR
// violation. Nothing here is meant to be shared, so nothing here is visible
// outside this file.
namespace {

struct CMSDeleter
{
    void operator()(CMS_ContentInfo* p) const
    {
        CMS_ContentInfo_free(p);
    }
};

struct X509Deleter
{
    void operator()(X509* p) const
    {
        X509_free(p);
    }
};

using CMSPtr = std::unique_ptr<CMS_ContentInfo, CMSDeleter>;
using X509Ptr = std::unique_ptr<X509, X509Deleter>;

/// Discards, when it goes out of scope, whatever OpenSSL queued since it was
/// constructed, leaving anything the caller had queued below it untouched --
/// on every path out of the scope, an exception included, so a mark is never
/// left dangling for some later, unrelated ERR_pop_to_mark() to stop short at.
///
/// **The rule for placing one.** The error queue is a fixed-size ring (16
/// entries in this OpenSSL) and a new entry clears the mark of the slot it
/// reclaims, so a mark stops protecting the caller's entries once enough has
/// been pushed past it. What protects them is bounding how much can be queued
/// between a mark and its pop -- so a mark goes around a BOUNDED piece of work,
/// and bounded means bounded by this file rather than by the input. A mark
/// spanning a walk whose length the input chooses is not a bound.
///
/// Two shapes follow from that, and both are in use here:
/// - **Per element, inside the loop body**, wherever a loop runs once per thing
///   the input carries: a list holds hundreds of certificates, a trust store
///   hundreds of anchors, a directory hundreds of files. A loop that CARRIES ON
///   past an item that failed has no other option -- decodeAnchors passes over
///   an element that does not decode, and loadAnchorDerFromDirectory passes
///   over a file it could not read, so each queues once per bad item and each
///   marks per item.
/// - **Around one step**, where what runs under it cannot queue an unbounded
///   amount: a fixed number of header reads, one d2i, one CMS_verify. Loops do
///   sit under marks of this kind, and that is sound only because they RETURN
///   at the first item that queues anything, so at most one item's worth ever
///   accumulates -- the signer walks and the store-building loop are all of
///   that kind.
///
/// The second shape is the fragile one, and it is fragile in a way nothing
/// fails to warn about: a loop under a step-scoped mark that is ever changed to
/// carry on past a bad item has to grow a mark of its own in the same edit.
/// That is why the distinction is written down here rather than left to be read
/// off wherever the brackets happen to sit.
///
/// One limit no placement lifts: a caller that walks in with the ring nearly
/// full loses its own oldest entries to eviction before anything here gets to
/// pop what it queued. What is still in the ring is restored; what the ring
/// dropped is gone.
class ErrorQueueMark
{
public:
    ErrorQueueMark()
    {
        ERR_set_mark();
    }
    ~ErrorQueueMark()
    {
        ERR_pop_to_mark();
    }
    ErrorQueueMark(const ErrorQueueMark&) = delete;
    ErrorQueueMark& operator=(const ErrorQueueMark&) = delete;
};

// id-icao-cscaMasterList, ICAO 9303-12.
constexpr const char* kCscaMasterListOid = "2.23.136.1.1.2";

/// True when @p oid is exactly id-icao-cscaMasterList.
///
/// Compared in dotted form: OpenSSL 3.5.5 has no entry for this OID, so it has
/// no NID to compare against, and OBJ_obj2txt with no_name set prints the
/// numeric form whether or not the object table happens to know the arc.
bool isCscaMasterListOid(const ASN1_OBJECT* oid)
{
    // Callers really do pass null here -- an attribute that is missing,
    // duplicated, multi-valued or not an OID all arrive as one. It still
    // cannot change a verdict, and neither can `len > 0` below, and neither
    // can the two together: `text` is zero-initialised and the comparison is
    // an exact strcmp, so a null object leaves an empty string that matches
    // nothing whatever OBJ_obj2txt does with it. This stays because resting a
    // security check on an initialiser is not a contract.
    if (oid == nullptr) {
        return false;
    }
    char text[128] = {0};
    // OBJ_obj2txt returns the length it would have written, snprintf-style.
    //
    // Neither test below can change a verdict either, for the same reason as
    // above and because 128 bytes hold any OID -- a rendering cut off at 127
    // characters could never equal the 14-character constant. They stay
    // because truncation here is silent, and a shorter buffer or a longer
    // constant would make both of them real.
    const int len = OBJ_obj2txt(text, sizeof(text), oid, 1);
    return len > 0 && static_cast<size_t>(len) < sizeof(text) && std::strcmp(text, kCscaMasterListOid) == 0;
}

/// Reads one universal-class ASN.1 header at @p cursor, which must be the tag
/// @p expectedTag and must be constructed exactly when @p constructed says so.
/// On success @p cursor is left on the first content byte and @p outLen holds
/// the content length; on failure @p cursor is unusable and the caller must
/// stop.
///
/// Indefinite lengths are rejected: they are BER, and a master list is DER.
bool readHeader(const unsigned char*& cursor, const unsigned char* limit, int expectedTag, bool constructed,
                long& outLen)
{
    // Cannot change a verdict: ASN1_get_object rejects a non-positive `omax`
    // itself. It stays so that the precondition is stated here rather than
    // borrowed, and so that a negative length is never handed over.
    if (cursor >= limit) {
        return false;
    }
    long len = 0;
    int tag = 0;
    int objectClass = 0;
    const int ret = ASN1_get_object(&cursor, &len, &tag, &objectClass, limit - cursor);
    // ASN1_get_object reports an error by setting 0x80 and otherwise returns
    // the constructed bit (0x20) or-ed with the indefinite-length bit (0x01),
    // so the only acceptable returns are exactly 0x20 and exactly 0 -- not
    // merely "0x80 is clear".
    // The indefinite-length half pairs with `setEnd != end` in the caller:
    // ASN1_get_object reports length 0 for an indefinite form, so either alone
    // rejects one and only removing both lets one through. The constructed
    // half stands alone -- it is what refuses a BER constructed `version`
    // INTEGER (tag 0x22), which no span check notices, since the length and
    // value are untouched and the walk strides over exactly the same bytes.
    if (ret != (constructed ? V_ASN1_CONSTRUCTED : 0)) {
        return false;
    }
    // Both halves stand alone as well, for the same reason: a version tag of
    // 0x42 (the same tag number, APPLICATION class) or 0x04 (OCTET STRING)
    // leaves the walk covering identical bytes, so nothing downstream notices
    // either.
    if (objectClass != V_ASN1_UNIVERSAL || tag != expectedTag) {
        return false;
    }
    outLen = len;
    return true;
}

/// Walks `CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF
/// Certificate }` over [@p p, @p end) and returns the elements of its SET as
/// the bytes the list itself carries for each -- the slice d2i consumed, not a
/// re-encoding of what it produced.
std::expected<MasterList, MasterListError> readCscaMasterListContent(const unsigned char* p,
                                                                     const unsigned char* const end)
{
    long seqLen = 0;
    long versionLen = 0;
    long setLen = 0;
    {
        // Three headers at most, so one bracket covers them all without any
        // risk of filling the ring.
        const ErrorQueueMark errorMark;
        // The three `!readHeader` returns below are pinned as a group with the
        // span checks, not one by one: readHeader leaves the length at 0 when
        // it fails, so dropping any single one of them still ends in
        // `Malformed` a line or two later and fells no test. They stay because
        // a walk that carries on past a header it could not read has stopped
        // meaning anything, whatever verdict it happens to reach.
        if (!readHeader(p, end, V_ASN1_SEQUENCE, true, seqLen)) {
            return std::unexpected(MasterListError::Malformed);
        }
        // The CscaMasterList is the whole encapsulated content; anything after
        // it is not part of the structure and is not signed as one either.
        //
        // Load-bearing, not a tidiness check. The headers below are read
        // against `end`, not against the SEQUENCE's own declared end, so a
        // SEQUENCE that understates its length still parses field by field
        // and yields anchors out of a structure that never closes. This is
        // the only line that notices.
        if (p + seqLen != end) {
            return std::unexpected(MasterListError::Malformed);
        }
        if (!readHeader(p, end, V_ASN1_INTEGER, false, versionLen)) {
            return std::unexpected(MasterListError::Malformed);
        }
        // The version's value is not examined; see the header. ASN1_get_object
        // has already refused a length that runs past `end`, so this stays in
        // bounds.
        p += versionLen;
        if (!readHeader(p, end, V_ASN1_SET, true, setLen)) {
            return std::unexpected(MasterListError::Malformed);
        }
    }

    const unsigned char* const setEnd = p + setLen;
    if (setEnd != end) {
        // Also load-bearing: without it a third field appended after the SET
        // is simply never read, and the list parses as though it were not
        // there. CscaMasterList has two fields.
        return std::unexpected(MasterListError::Malformed);
    }
    if (p == setEnd) {
        return std::unexpected(MasterListError::Empty);
    }

    MasterList out;
    while (p < setEnd) {
        // Per element: see ErrorQueueMark. A list holds hundreds of these.
        const ErrorQueueMark errorMark;
        const unsigned char* const start = p;
        const X509Ptr cert(d2i_X509(nullptr, &p, setEnd - p));
        if (!cert) {
            return std::unexpected(MasterListError::Malformed);
        }
        out.cscaDer.emplace_back(start, p);
    }
    return out;
}

} // namespace

std::expected<MasterList, MasterListError> parseCscaMasterList(const std::vector<uint8_t>& der)
{
    CMSPtr cms;
    {
        const ErrorQueueMark errorMark;
        // `der.empty()`, `!cms` below, and the trailing-bytes check after it
        // overlap in pairs, and no one of the three can be dropped alone:
        // empty input is caught by the first, and by the second once the first
        // is gone; garbage is caught by the second, and by the third once the
        // second is gone. Drop either pair and CMS_get0_type(nullptr)
        // segfaults. These are the null guard, not tidiness.
        //
        // The LONG_MAX half cannot change a verdict where this builds --
        // size_t and long are both 64-bit, so no such vector can exist -- and
        // stays for the narrowing cast on the line after next, which is where
        // a 32-bit long would make it real.
        if (der.empty() || der.size() > static_cast<size_t>(LONG_MAX)) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
        const unsigned char* p = der.data();
        cms.reset(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(der.size())));
        if (!cms) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
        // d2i stops at the end of the object it decoded, so bytes may be left
        // over. A published master list is the ContentInfo and nothing else.
        if (p != der.data() + der.size()) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
    }

    STACK_OF(CMS_SignerInfo)* signers = nullptr;
    {
        // No input reaches an OpenSSL call under this bracket that queues
        // anything: everything inside it raises only for shapes the gate on
        // the next line has already turned away, so removing it fells no test.
        // It stays because isCscaMasterListOid calls OBJ_obj2txt, whose BIGNUM
        // path for an arc of 2^64 or more can still raise on an allocation
        // failure -- a case no fixture can produce on demand.
        const ErrorQueueMark errorMark;
        // Cannot change a verdict on its own: a ContentInfo that is not
        // SignedData carries no SignerInfo, so the count check below turns one
        // away in any case. It stays because it is the only thing keeping
        // CMS_get0_content, read further down outside any bracket, away from
        // its default branch -- which reaches into cms->d.other for a content
        // type nothing here has established anything about -- and because it
        // is the direct statement of what this function will read. The
        // redundancy runs one way only: the count check below IS load-bearing
        // alone.
        if (OBJ_obj2nid(CMS_get0_type(cms.get())) != NID_pkcs7_signed) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
        // One half of "both places", and the half nothing else covers. The
        // mirror case -- the field says master list and the attribute does not
        // -- is caught by the attribute check below; this direction, the
        // attribute saying master list over a field that does not, is caught
        // only here.
        if (!isCscaMasterListOid(CMS_get0_eContentType(cms.get()))) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
        signers = CMS_get0_SignerInfos(cms.get());
    }

    const int signerCount = sk_CMS_SignerInfo_num(signers);
    if (signerCount <= 0) {
        // Load-bearing on its own. A SignedData with an EMPTY signerInfos SET
        // is still a SignedData, so it walks past the gate above, and nothing
        // else here would refuse to hand back anchors that no signer ever
        // vouched for. It also covers the NULL a non-SignedData yields, which
        // is what makes the gate redundant without making it removable.
        return std::unexpected(MasterListError::NotAMasterList);
    }

    const ASN1_OBJECT* contentTypeAttribute = OBJ_nid2obj(NID_pkcs9_contentType);
    for (int i = 0; i < signerCount; ++i) {
        // EVERY signer, not the first. SignerInfos are a DER SET OF, so which
        // one lands at index 0 is decided by the encoding rather than by
        // whoever added them; stopping after signers[0] lets a second signer
        // disagree about what was signed and never be read.
        //
        // Per signer, not around the loop: see ErrorQueueMark. The count comes
        // from the input.
        const ErrorQueueMark errorMark;
        const CMS_SignerInfo* signer = sk_CMS_SignerInfo_value(signers, i);
        // lastpos -3 asks for exactly one attribute with this OID carrying
        // exactly one value, which is what RFC 5652 s11.1 requires of the
        // content-type attribute; a second copy, a second value, or a value
        // that is not an OID all yield nullptr. OpenSSL enforces that
        // cardinality on its own verify path but never compares the attribute
        // with the eContentType field beside it, which is the comparison that
        // matters here -- only the attribute is under the signature.
        //
        // Both halves of that cardinality are load-bearing: relaxing -3 to -2
        // admits an attribute carrying two values, and to -1 a duplicated
        // attribute. In each case every copy names the ICAO OID, so a reader
        // that took the first would see nothing wrong -- and would have no way
        // to tell which copy the signer meant.
        //
        // The line below carries one more behaviour that is not obvious from
        // it: an ABSENT attribute arrives here as nullptr and is refused by
        // the same test. That is not a bookkeeping detail. A signer with no
        // contentType attribute has nothing under its signature saying what it
        // signed, which is the entire reason this attribute is read rather
        // than the field beside it.
        const auto* signedContentType = static_cast<const ASN1_OBJECT*>(
            CMS_signed_get0_data_by_OBJ(signer, contentTypeAttribute, -3, V_ASN1_OBJECT));
        if (!isCscaMasterListOid(signedContentType)) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
    }

    ASN1_OCTET_STRING** content = CMS_get0_content(cms.get());
    // `*content == nullptr` is the detached case: the object still says master
    // list, but the list is not in it, and reading on is a segfault rather
    // than a wrong answer. `content == nullptr` cannot change a verdict --
    // CMS_get0_content returns null only for a content type already refused
    // above -- and stays because the dereference beside it is unconditional.
    if (content == nullptr || *content == nullptr) {
        return std::unexpected(MasterListError::Malformed);
    }
    const unsigned char* const contentData = ASN1_STRING_get0_data(*content);
    const int contentLen = ASN1_STRING_length(*content);
    // Neither half can change a verdict on its own. `contentData == nullptr`
    // happens only for a string with no data, which `contentLen <= 0` already
    // covers; `contentLen <= 0` is in turn backstopped by `cursor >= limit` in
    // readHeader, which turns an empty content into `Malformed` anyway. Both
    // stay as the earlier and plainer place to say the content has to be
    // there and has to have something in it.
    if (contentData == nullptr || contentLen <= 0) {
        return std::unexpected(MasterListError::Malformed);
    }

    return readCscaMasterListContent(contentData, contentData + contentLen);
}

// A second anonymous namespace, opened after parseCscaMasterList rather than
// widening the one above it, so that nothing verification needs is in scope
// while the parser is read. Same internal-linkage rule and the same reason:
// passive_auth.cpp shares this namespace.
namespace {

struct X509StackDeleter
{
    void operator()(STACK_OF(X509) * p) const
    {
        // sk_X509_free, not sk_X509_pop_free/OSSL_STACK_OF_X509_free.
        // CMS_get0_signers builds its stack with X509_ADD_FLAG_DEFAULT, which
        // takes no reference, so the certificates in it belong to the
        // CMS_ContentInfo. Freeing them here would free that object's own.
        sk_X509_free(p);
    }
};

using X509StackPtr = std::unique_ptr<STACK_OF(X509), X509StackDeleter>;

struct Asn1TimeDeleter
{
    void operator()(ASN1_TIME* p) const
    {
        ASN1_TIME_free(p);
    }
};

struct OpenSslBytesDeleter
{
    void operator()(unsigned char* p) const
    {
        OPENSSL_free(p);
    }
};

using Asn1TimePtr = std::unique_ptr<ASN1_TIME, Asn1TimeDeleter>;
using OpenSslBytesPtr = std::unique_ptr<unsigned char, OpenSslBytesDeleter>;

/// @p cert as it was encoded, or an empty vector when that cannot be produced.
///
/// i2d over a certificate that was PARSED hands back the bytes it was parsed
/// from, OpenSSL having kept the original encoding, so this is the slice the
/// object carried rather than a re-encoding of it. That is what a caller going
/// on to build a path with it should be given: what the publisher published.
///
/// The owning pointer is taken before anything can throw. The header says
/// std::bad_alloc escapes, so the vector below is a live throwing path and a
/// raw OPENSSL_free pointer across it would be a leak nothing unwinds.
std::vector<uint8_t> certificateDer(X509* cert)
{
    if (cert == nullptr) {
        return {};
    }
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert, &der);
    const OpenSslBytesPtr owned(der);
    if (len <= 0 || der == nullptr) {
        return {};
    }
    return std::vector<uint8_t>(der, der + len);
}

/// @p when as seconds since the Unix epoch, or nothing when it cannot be read.
///
/// Through ASN1_TIME_diff against the epoch itself rather than through a
/// `struct tm` and timegm: the arithmetic then belongs to the same library that
/// decoded the field, timegm is a platform extension rather than a C function,
/// and nothing here goes near the process's timezone state. ASN1_TIME_diff also
/// validates what it is given, so a value that is tagged as a time and is not
/// one comes back as nothing instead of as a number.
std::optional<int64_t> epochSecondsOf(const ASN1_TIME* when)
{
    if (when == nullptr) {
        return std::nullopt;
    }
    const Asn1TimePtr epoch(ASN1_TIME_set(nullptr, static_cast<time_t>(0)));
    if (!epoch) {
        return std::nullopt;
    }
    int days = 0;
    int seconds = 0;
    if (ASN1_TIME_diff(&days, &seconds, epoch.get(), when) != 1) {
        return std::nullopt;
    }
    // Both come back with the same sign, so one expression covers a time before
    // 1970 as well as one after it. A day count that could overflow this is some
    // five million years wide.
    return static_cast<int64_t>(days) * 86400 + seconds;
}

/// The instant the SIGNED attributes of @p signerInfo commit to, or nothing.
///
/// The SIGNED attributes and never the unsigned ones. `signingTime` is part of
/// `signedAttrs`, so the signature covers it and a verified object's publisher
/// is committed to it; the same attribute among the unsigned ones is outside
/// every signature and is whatever the last hand to touch the file wrote there.
/// Reading the wrong one would not be a smaller check, it would be a date that
/// looks like protection while being attacker-chosen.
///
/// Nothing, rather than a guess, in every case where the object does not say
/// exactly one time: no attribute, a second one beside it, an attribute holding
/// more or less than one value, or a value that is neither a UTCTime nor a
/// GeneralizedTime. Picking one of two, or reading a time out of something that
/// is not one, would be inventing the answer.
std::optional<int64_t> signedSigningTimeOf(CMS_SignerInfo* signerInfo)
{
    const int index = CMS_signed_get_attr_by_NID(signerInfo, NID_pkcs9_signingTime, -1);
    if (index < 0) {
        return std::nullopt;
    }
    // The search resumes AFTER the one just found, so this is "is there a
    // second one", not "is there a first one".
    if (CMS_signed_get_attr_by_NID(signerInfo, NID_pkcs9_signingTime, index) >= 0) {
        return std::nullopt;
    }
    X509_ATTRIBUTE* attribute = CMS_signed_get_attr(signerInfo, index);
    if (attribute == nullptr || X509_ATTRIBUTE_count(attribute) != 1) {
        return std::nullopt;
    }
    const ASN1_TYPE* value = X509_ATTRIBUTE_get0_type(attribute, 0);
    if (value == nullptr || (value->type != V_ASN1_UTCTIME && value->type != V_ASN1_GENERALIZEDTIME)) {
        return std::nullopt;
    }
    return epochSecondsOf(value->value.asn1_string);
}

/// The SignerInfo whose signature @p signerCert verified, or null.
///
/// By identity and not by index. CMS_get0_signers builds its stack by walking
/// the SignerInfos and pushing each one's resolved certificate, but it SKIPS
/// any SignerInfo that has none -- so the two are parallel only as long as
/// every SignerInfo resolved, which is true after a successful CMS_verify and
/// is not a thing to rest an attribute read on. The pointers compared both come
/// out of this one CMS_ContentInfo, so what is matched here is the very
/// certificate the verification used.
///
/// Queues nothing: every call in it is a getter. That is what lets it sit under
/// a mark that brackets a step rather than an item.
///
/// The FIRST match, on the pathological object that carries one certificate
/// signing twice: two SignerInfos are then two signatures by one key, and the
/// attributes read are the first one's.
CMS_SignerInfo* signerInfoOf(CMS_ContentInfo* cms, const X509* signerCert)
{
    STACK_OF(CMS_SignerInfo)* signerInfos = CMS_get0_SignerInfos(cms);
    for (int i = 0; i < sk_CMS_SignerInfo_num(signerInfos); ++i) {
        CMS_SignerInfo* signerInfo = sk_CMS_SignerInfo_value(signerInfos, i);
        X509* itsSigner = nullptr;
        CMS_SignerInfo_get0_algs(signerInfo, nullptr, &itsSigner, nullptr, nullptr);
        if (itsSigner != nullptr && itsSigner == signerCert) {
            return signerInfo;
        }
    }
    return nullptr;
}

/// SHA-256 over the DER of @p cert's SubjectPublicKeyInfo, or an empty vector
/// if it cannot be produced.
///
/// The SubjectPublicKeyInfo rather than the certificate, so that a key
/// reissued in a new certificate keeps its fingerprint -- see
/// VerifiedMasterList::signerSpkiSha256. It is re-encoded with i2d rather than
/// taken as the slice the certificate carried, because two encodings of one
/// key must not fingerprint differently; that is the same re-encode
/// MasterList::cscaDer tells a consumer to do, done here.
std::vector<uint8_t> spkiSha256(X509* cert)
{
    // Neither null can be reached from any input: X509_PUBKEY is not OPTIONAL
    // in the Certificate template, so a certificate that parsed has one, and
    // this is only ever called on a certificate CMS_verify already verified a
    // signature with. They are here so that an allocation failure cannot come
    // back as a short or empty fingerprint that then goes on to be compared.
    X509_PUBKEY* spki = cert != nullptr ? X509_get_X509_PUBKEY(cert) : nullptr;
    if (spki == nullptr) {
        return {};
    }
    // Allocated BEFORE the encoding, not after it: this allocation can throw,
    // and `der` is a raw OPENSSL_free pointer that no unwinding would release.
    // The header says std::bad_alloc escapes, so that is a documented path and
    // not a hypothetical one.
    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned char* der = nullptr;
    const int len = i2d_X509_PUBKEY(spki, &der);
    if (len <= 0 || der == nullptr) {
        return {};
    }
    unsigned int digestLen = 0;
    const int ok = EVP_Digest(der, static_cast<size_t>(len), digest.data(), &digestLen, EVP_sha256(), nullptr);
    OPENSSL_free(der);
    if (ok != 1) {
        return {};
    }
    digest.resize(digestLen);
    return digest;
}

/// True when @p fingerprint is exactly @p expected.
///
/// The length is compared FIRST and is not a formality: without it a caller
/// that passed a truncated fingerprint would have only that prefix compared,
/// and a 4-byte pin would match one signer in 2^32 instead of naming one. The
/// bytes themselves go through CRYPTO_memcmp, which does not stop at the first
/// difference.
bool fingerprintMatches(const std::vector<uint8_t>& fingerprint, const std::vector<uint8_t>& expected)
{
    return !fingerprint.empty() && fingerprint.size() == expected.size() &&
           CRYPTO_memcmp(fingerprint.data(), expected.data(), fingerprint.size()) == 0;
}

} // namespace

std::expected<VerifiedMasterList, MasterListError>
parseAndVerifyMasterList(const std::vector<uint8_t>& der, const std::vector<uint8_t>& expectedSpkiSha256)
{
    CMSPtr cms;
    {
        const ErrorQueueMark errorMark;
        // The null guard, as in parseCscaMasterList -- but the overlaps are
        // not the same ones, because there is no trailing-bytes check here to
        // be the third member. Measured: `der.empty()` alone can be dropped
        // with every test still green, since d2i refuses a zero length itself
        // and `!cms` below then answers. `!cms` cannot be dropped -- CMS_verify
        // would be handed a null. The LONG_MAX half cannot change a verdict
        // where this builds, size_t and long both being 64-bit, and stays for
        // the narrowing cast two lines down.
        if (der.empty() || der.size() > static_cast<size_t>(LONG_MAX)) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
        const unsigned char* p = der.data();
        cms.reset(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(der.size())));
        if (!cms) {
            return std::unexpected(MasterListError::NotAMasterList);
        }
        // Bytes trailing the ContentInfo are deliberately NOT rejected here.
        // parseCscaMasterList refuses them at step 4, over the same `der`, so
        // such an input is still refused and with the answer that names the
        // real fault. Repeating the check here would only move which of the
        // two lines does it.
    }

    std::vector<uint8_t> reportedFingerprint;
    std::vector<uint8_t> signerCertDer;
    std::optional<int64_t> signingTime;
    bool identityChecked = false;
    {
        // One bracket over the whole of verification, and there is room to
        // spare: measured, a CMS_verify failure leaves 2 entries under this
        // mark and the signer walk below adds none, against a usable ring
        // depth of 15. The fingerprint work shares the bracket because it
        // belongs to the same step, not because the ring is tight.
        const ErrorQueueMark errorMark;
        // CMS_NO_SIGNER_CERT_VERIFY: no chain is built, and none can be --
        // the list is what supplies the anchors, so at first import there is
        // nothing to chain its signer to. But impossibility is only half the
        // reason. Once identity rests on a fingerprint the caller obtained out
        // of band, the signer's certificate is a CONTAINER FOR THE KEY, not a
        // credential, and every check the flag skips is a statement about the
        // container rather than about the key that was pinned.
        //
        // The flag skips one function, cms_signerinfo_verify_cert, and with it
        // the chain, the validity dates, the key usage, the extended key usage
        // and the CRLs. Two of those would actively break real imports:
        // - the dates, because a master list outlives by years the key that
        //   signed it, and a signer rotates while the list stays in use;
        // - the extended key usage, because CMS_verify applies the smime_sign
        //   purpose, which demands emailProtection -- an EKU ICAO does not
        //   profile on a master list signer.
        // AcceptsAPinnedListWhoseSignerCertificateWouldFailEveryCredentialCheck
        // pins both at once: a signer that has lapsed AND carries the EKU ICAO
        // profiles on a master list signer -- which OpenSSL's own smime_sign
        // purpose rejects, while it would have passed a bare certificate with
        // no EKU at all -- is ACCEPTED against a correct pin. The risk in this
        // paragraph runs one way: every plausible change here makes the
        // function stricter, so the failure is working imports beginning to
        // refuse in the field with a green suite, and that test is what stands
        // in the way.
        //
        // The other three -- key usage, basic constraints and revocation --
        // are NOT pinned by anything. Two of those three are measured rather
        // than assumed: a build that applies OpenSSL's own key-usage rejection
        // to every signer passes this whole suite, and so does one that
        // refuses a CA certificate as a signer, the fixture's signer happening
        // to satisfy both. Revocation is asserted and not measured -- there is
        // no CRL anywhere in the fixture set to build a mutant around.
        //
        // Everything else CMS_verify does stays on, notably that EVERY
        // SignerInfo verifies, so a second signer cannot attest to different
        // content beside a first one the caller pinned. Adding
        // CMS_NO_ATTR_VERIFY or CMS_NO_CONTENT_VERIFY here fells a test each,
        // which is what keeps this flag word from growing.
        if (CMS_verify(cms.get(), nullptr, nullptr, nullptr, nullptr, CMS_NO_SIGNER_CERT_VERIFY) != 1) {
            return std::unexpected(MasterListError::BadSignature);
        }
        // AFTER CMS_verify, never before: a SignerInfo's `signer` is unresolved
        // until verification runs, so this returns NULL on an object nothing
        // has verified -- which would read as "no signer" rather than as "not
        // asked yet".
        //
        // And CMS_get0_signers, never CMS_get1_certs. They differ by one token
        // and by the whole trust model: the second returns the object's
        // certificate BAG, which is unauthenticated and which anybody may drop
        // anybody's certificate into. Matching the pin against that answers
        // "is the pinned certificate carried here", not "did the pinned key
        // sign this" -- so a stranger's list, genuinely signed by the
        // stranger, with the trusted publisher's certificate planted beside
        // it, would be accepted and would report the pinned fingerprint back.
        // RefusesAListThatMerelyCarriesThePinnedSignersCertificate is that
        // input, and it is the only test that separates the two.
        const X509StackPtr signers(CMS_get0_signers(cms.get()));
        const int signerCount = sk_X509_num(signers.get());
        // Cannot be reached from any input: CMS_verify has already refused an
        // object with no SignerInfo, and one whose signer certificate it could
        // not find. It stays because sk_X509_value below would otherwise be
        // read from a null or empty stack -- a crash, not a wrong verdict --
        // if CMS_get0_signers ever failed to allocate.
        if (signerCount <= 0) {
            return std::unexpected(MasterListError::BadSignature);
        }

        // An empty expectation means "do not compare", and is the only way to
        // ask for that. The two paths report DIFFERENT signers, which is the
        // whole point of splitting them: reported is the signer this call
        // established something about, and with no pin the only such signer is
        // the one a reader meets first.
        //
        // Not one loop with the comparison switched off inside it:
        // fingerprintMatches compares the lengths, so an empty pin matches no
        // signer, and a shared loop would answer SignerMismatch to a caller
        // that asked for no comparison at all.
        // The certificate behind the fingerprint that gets reported, whichever
        // of the two paths below chooses it. Both fields describe ONE signer,
        // so it is picked once, where the choice is made, rather than looked up
        // again afterwards from an index that would have to agree.
        X509* reportedSigner = nullptr;

        if (expectedSpkiSha256.empty()) {
            reportedSigner = sk_X509_value(signers.get(), 0);
            reportedFingerprint = spkiSha256(reportedSigner);
            if (reportedFingerprint.empty()) {
                // Unreachable, for the reason spkiSha256 gives for its own
                // guards. `BadSignature` and not `SignerMismatch`, here and in
                // the loop below alike: a fingerprint that could not be
                // computed is not a fingerprint that failed to match, and one
                // cause must not reach the caller as two verdicts.
                return std::unexpected(MasterListError::BadSignature);
            }
        } else {
            for (int i = 0; i < signerCount; ++i) {
                // ANY signer, not signers[0]. SignerInfos are a DER SET OF, so
                // which one lands first is decided by the encoding rather than
                // by whoever assembled the list; a pin on the signer that
                // happens to sort second would otherwise never be met.
                X509* const candidate = sk_X509_value(signers.get(), i);
                std::vector<uint8_t> fingerprint = spkiSha256(candidate);
                if (fingerprint.empty()) {
                    return std::unexpected(MasterListError::BadSignature);
                }
                if (fingerprintMatches(fingerprint, expectedSpkiSha256)) {
                    // The signer that MATCHED, not signers[0]. The two are the
                    // same on the single-signer lists ICAO publishes and are
                    // not on a list an attacker has appended a signer to --
                    // and reporting a fingerprint this call established
                    // nothing about is how a caller comes to store one.
                    reportedFingerprint = std::move(fingerprint);
                    reportedSigner = candidate;
                    identityChecked = true;
                    break;
                }
            }
            if (!identityChecked) {
                return std::unexpected(MasterListError::SignerMismatch);
            }
        }

        signerCertDer = certificateDer(reportedSigner);
        if (signerCertDer.empty()) {
            // Unreachable for the reason spkiSha256's own guards give: this
            // certificate has just verified a signature and has just been
            // encoded once already, for its fingerprint. It stays because empty
            // bytes are not a certificate, and handing them back as one is how
            // a caller comes to build a path out of nothing. Same verdict as
            // there, and for the same reason: a signer that cannot be named is
            // "nothing here vouches for these anchors".
            return std::unexpected(MasterListError::BadSignature);
        }

        // The attributes of THAT signer's SignerInfo, not of the object: a
        // signingTime belongs to one SignerInfo, so a list carrying several
        // signers carries several answers and only the pinned one's is the
        // answer to the question asked.
        //
        // A SignerInfo that cannot be found is the same answer as an attribute
        // that is not there -- no time -- because that is what it is: nothing
        // here says when this was signed. It cannot happen anyway, the
        // certificate having come out of the stack built from these very
        // SignerInfos.
        CMS_SignerInfo* const signerInfo = signerInfoOf(cms.get(), reportedSigner);
        signingTime = signerInfo != nullptr ? signedSigningTimeOf(signerInfo) : std::nullopt;
    }

    // Not a formality after the checks above, and not merely "now read the
    // anchors". Only the SIGNED contentType attribute is under the signature;
    // the eContentType field beside it is not. So an object genuinely signed by
    // the very signer just pinned, over genuine master-list bytes, under some
    // other content type, and relabelled afterwards, clears CMS_verify and
    // clears the fingerprint -- and parseCscaMasterList comparing those two
    // places is the only thing that stops it. This line is a barrier, not a
    // read.
    std::expected<MasterList, MasterListError> parsed = parseCscaMasterList(der);
    if (!parsed) {
        return std::unexpected(parsed.error());
    }
    return VerifiedMasterList{std::move(*parsed), std::move(reportedFingerprint), identityChecked,
                              std::move(signerCertDer), signingTime};
}

std::optional<std::vector<uint8_t>> spkiSha256FromCertificateDer(const std::vector<uint8_t>& certDer)
{
    const ErrorQueueMark errorMark;
    // `certDer.empty()` cannot change a verdict -- d2i refuses a zero length
    // itself -- and stays as the plainer statement beside the LONG_MAX half,
    // which cannot change one where this builds, size_t and long both being
    // 64-bit, and which is there for the narrowing cast below.
    if (certDer.empty() || certDer.size() > static_cast<size_t>(LONG_MAX)) {
        return std::nullopt;
    }
    const unsigned char* p = certDer.data();
    const X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(certDer.size())));
    if (!cert) {
        return std::nullopt;
    }
    // d2i stops at the end of the object it decoded, so bytes may be left over.
    // A caller pinning a key is making an identity statement about one
    // certificate; being handed a buffer that holds something else as well is a
    // reason to stop rather than to answer about the part that parsed.
    if (p != certDer.data() + certDer.size()) {
        return std::nullopt;
    }
    // THE helper the pinned path itself uses, not a second copy of it: two
    // implementations of one fingerprint is how a caller comes to compute a pin
    // that never matches. See spkiSha256 for why it is over the
    // SubjectPublicKeyInfo, re-encoded.
    std::vector<uint8_t> fingerprint = spkiSha256(cert.get());
    if (fingerprint.empty()) {
        return std::nullopt;
    }
    return fingerprint;
}

// A third anonymous namespace, opened after the two functions above for the
// same reason the second one was: nothing the chain verdict needs is in scope
// while they are read. Same internal-linkage rule, and the same reason --
// passive_auth.cpp shares this namespace.
namespace {

struct X509StoreDeleter
{
    void operator()(X509_STORE* p) const
    {
        X509_STORE_free(p);
    }
};

struct VerifyParamDeleter
{
    void operator()(X509_VERIFY_PARAM* p) const
    {
        X509_VERIFY_PARAM_free(p);
    }
};

struct X509StoreCtxDeleter
{
    void operator()(X509_STORE_CTX* p) const
    {
        X509_STORE_CTX_free(p);
    }
};

using X509StorePtr = std::unique_ptr<X509_STORE, X509StoreDeleter>;
using VerifyParamPtr = std::unique_ptr<X509_VERIFY_PARAM, VerifyParamDeleter>;
using X509StoreCtxPtr = std::unique_ptr<X509_STORE_CTX, X509StoreCtxDeleter>;

/// Decodes every element of @p anchorsDer that is a certificate, in order,
/// passing over every element that is not.
///
/// Passing over rather than refusing: see evaluateCscaChain's header. An
/// element that does not decode is not an anchor, so it can neither match an
/// issuer name nor enter a store, and one unreadable file among many costs
/// only that file. What it cannot do is turn into an anchor later, so nothing
/// downstream has to re-check.
std::vector<X509Ptr> decodeAnchors(const std::vector<std::vector<uint8_t>>& anchorsDer)
{
    std::vector<X509Ptr> anchors;
    for (const std::vector<uint8_t>& der : anchorsDer) {
        // Per element, not around the loop: see ErrorQueueMark. A trust store
        // holds hundreds of these, and a directory of unreadable ones would
        // queue an entry each -- which is exactly the shape that overruns the
        // ring and starts evicting the caller's own entries.
        const ErrorQueueMark errorMark;
        // `der.empty()` cannot change a verdict -- d2i refuses a zero length
        // itself -- and stays as the plainer statement beside the LONG_MAX
        // half, which cannot change one where this builds, size_t and long
        // both being 64-bit, and which is there for the narrowing cast below.
        if (der.empty() || der.size() > static_cast<size_t>(LONG_MAX)) {
            continue;
        }
        const unsigned char* p = der.data();
        X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
        if (cert) {
            anchors.push_back(std::move(cert));
        }
    }
    return anchors;
}

/// True when some certificate in @p signers names some certificate in
/// @p anchors as its issuer.
///
/// Whole names, compared with X509_NAME_cmp. Not the country attribute on its
/// own: two authorities of one country are two different anchors, and matching
/// on the country would hand a document to whichever of them we happened to
/// hold.
///
/// ANY signer, not signers[0]. SignerInfos are a DER SET OF, so which one
/// lands first is decided by the encoding rather than by whoever assembled the
/// document, and anybody may append a signer to a document they did not sign.
/// Reading only the first would let an appended signer decide that we hold no
/// anchor for a document whose own signer we do hold one for -- which is a
/// rejection either way, but one that sends a reader off to configure an
/// anchor for the attacker.
bool someSignerNamesAnAnchor(const STACK_OF(X509) * signers, const std::vector<X509Ptr>& anchors)
{
    for (int i = 0; i < sk_X509_num(signers); ++i) {
        const X509_NAME* issuer = X509_get_issuer_name(sk_X509_value(signers, i));
        for (const X509Ptr& anchor : anchors) {
            // X509_NAME_cmp returns -2 on error, so this is an equality test
            // and not a `<= 0` one.
            if (X509_NAME_cmp(issuer, X509_get_subject_name(anchor.get())) == 0) {
                return true;
            }
        }
    }
    return false;
}

/// An X509_STORE holding @p anchors, with the two verification defaults
/// evaluateCscaChain's header describes turned off, or null if it cannot be
/// built.
X509StorePtr storeOfAnchors(const std::vector<X509Ptr>& anchors)
{
    X509StorePtr store(X509_STORE_new());
    if (!store) {
        return nullptr;
    }
    for (const X509Ptr& anchor : anchors) {
        // X509_STORE_add_cert up-refs, so the store does not take ownership of
        // anything the caller still holds. A duplicate is not an error in
        // OpenSSL 3, which matters: a directory may hold one anchor twice.
        if (X509_STORE_add_cert(store.get(), anchor.get()) != 1) {
            return nullptr;
        }
    }

    const VerifyParamPtr param(X509_VERIFY_PARAM_new());
    if (!param) {
        return nullptr;
    }
    // X509_PURPOSE_ANY, because CMS_verify applies the smime_sign purpose,
    // which passes a certificate carrying NO extended key usage and rejects
    // one whose extended key usage is present and omits emailProtection -- so
    // it is precisely the ICAO-profiled document signer, the real one, that
    // the default turns away.
    //
    // Set on the STORE, which is what makes it stick: CMS_verify goes on to
    // call X509_STORE_CTX_set_default(ctx, "smime_sign"), and that inherits
    // only into fields the context has not already been given. The store's
    // parameters are copied in first, so a purpose set here is not overwritten
    // -- while one set on the context afterwards would have nowhere to be set
    // from.
    //
    // "Any purpose" is not "no checks". Basic constraints still keep a leaf
    // from acting as a CA in the middle of a chain, the issuer's key usage
    // still has to allow certificate signing, and every signature in the chain
    // is still verified; those are checked outside the purpose machinery.
    if (X509_VERIFY_PARAM_set_purpose(param.get(), X509_PURPOSE_ANY) != 1) {
        return nullptr;
    }
    // NO_CHECK_TIME, because a document signer's key lives months while the
    // documents it signed live ten years, so a signer that has since lapsed is
    // the ordinary case rather than the suspicious one.
    //
    // THIS VERDICT THEREFORE CONTAINS NO STATEMENT ABOUT TIME, at either end
    // of the chain: an expired -- or not yet valid -- anchor passes too. The
    // check that belongs here is not "is this chain valid now" but "was it
    // valid when the document was signed", and that needs a signing time this
    // function is not given. When one is available this flag gives way to
    // X509_VERIFY_PARAM_set_time, and only then may what a caller tells a
    // person get stronger.
    // PARTIAL_CHAIN admits exactly one thing: ANY certificate in this store may
    // terminate a chain, self-signed or not. Without it OpenSSL accepts a chain
    // only where it ends at a self-signed certificate, and goes looking for the
    // issuer of anything else -- X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT when the
    // store does not hold it.
    //
    // That refuses ordinary documents. An ICAO master list carries CSCA LINK
    // CERTIFICATES: the same subject and the same public key as a country's new
    // self-signed CSCA, signed by the OUTGOING key so that a verifier holding
    // the old certificate can reach the new one. A link certificate is not
    // self-signed, so a caller whose anchors include one -- and only it, or it
    // ahead of the self-signed twin the store cannot tell apart, since a store
    // lookup takes whichever same-subject object its sort puts first and does
    // not backtrack -- answered `Failed` on a genuine passport from a country
    // that had rotated. `Failed` is the accusation verdict; CscaVerdict's own
    // header says collapsing it with a store nobody finished configuring is the
    // failure to avoid.
    //
    // It widens nothing a caller did not already say. "These are my configured
    // trust anchors" already means any of them may end a chain; the flag makes
    // the store agree. What it does NOT relax: every signature in the chain is
    // still verified, basic constraints and the issuer's key usage still apply,
    // and an anchor still has to be reached by name and by key.
    if (X509_VERIFY_PARAM_set_flags(param.get(), X509_V_FLAG_NO_CHECK_TIME | X509_V_FLAG_PARTIAL_CHAIN) != 1) {
        return nullptr;
    }
    if (X509_STORE_set1_param(store.get(), param.get()) != 1) {
        return nullptr;
    }
    return store;
}

} // namespace

CscaVerdict evaluateCscaChain(const std::vector<uint8_t>& sodDer, const std::vector<std::vector<uint8_t>>& anchorsDer,
                              bool anchorsPathWasGiven)
{
    // The flag before the vector, and both before the document. A caller that
    // hands over anchors while saying nothing was configured is answered
    // NotConfigured rather than judged against them: this function cannot tell
    // where the anchors came from, so when the two disagree the flag is the
    // one that was written down on purpose, and the answer that neither
    // vouches for nor accuses a document is the safe one to give.
    if (!anchorsPathWasGiven) {
        return CscaVerdict::NotConfigured;
    }

    const std::vector<X509Ptr> anchors = decodeAnchors(anchorsDer);
    // An empty input and an input of which nothing decoded arrive here as the
    // same thing, which is the point: both mean a source was configured and
    // no anchor came out of it.
    if (anchors.empty()) {
        return CscaVerdict::AnchorsUnusable;
    }

    CMSPtr cms;
    {
        const ErrorQueueMark errorMark;
        // The null guard, as in the two functions above. `sodDer.empty()` and
        // `!cms` overlap -- d2i refuses a zero length itself -- but neither
        // can be dropped alone once the other is: CMS_verify would be handed a
        // null. The LONG_MAX half cannot change a verdict where this builds
        // and stays for the narrowing cast two lines down.
        if (sodDer.empty() || sodDer.size() > static_cast<size_t>(LONG_MAX)) {
            return CscaVerdict::Failed;
        }
        const unsigned char* p = sodDer.data();
        cms.reset(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(sodDer.size())));
        if (!cms) {
            return CscaVerdict::Failed;
        }
        // Bytes trailing the ContentInfo are not rejected. A security object
        // is read off a chip by a caller that knows how long it is, and this
        // function's subject is who signed the object, not how it was framed.
    }

    {
        // One bracket over signer resolution and the name comparison: a
        // CMS_verify failure leaves a handful of entries under it, and the
        // comparison itself queues nothing.
        const ErrorQueueMark errorMark;
        // CMS_NO_SIGNER_CERT_VERIFY, for one call only, and not because the
        // chain does not matter: it is built two blocks down, against the
        // store. This pass exists because a SignerInfo's `signer` stays
        // unresolved until something verifies the object, so there is no way
        // to ask who signed a document without first checking that anybody
        // did. Signatures, digests and signed attributes are all checked here;
        // only the chain is deferred.
        //
        // The failure of this call is Failed and never NoAnchorForIssuer, and
        // the order is what makes that so. A document whose signature does not
        // hold has no established signer, so it has no established issuer
        // either -- and the issuer field is written by whoever made the
        // document, so a verdict resting on it before the signature is a
        // verdict the forger chose.
        if (CMS_verify(cms.get(), nullptr, nullptr, nullptr, nullptr, CMS_NO_SIGNER_CERT_VERIFY) != 1) {
            return CscaVerdict::Failed;
        }
        // CMS_get0_signers, never CMS_get1_certs. They differ by one token and
        // by the whole trust model: the second returns the object's
        // certificate BAG, which nothing signs and which anybody may drop
        // anybody's certificate into. Comparing issuer names against the bag
        // would answer "does this document CARRY a certificate from an
        // authority we hold" instead of "was it SIGNED by one" -- so a
        // forgery travelling with a genuine document signer beside it would be
        // taken as far as the chain check, and a genuine document would be
        // judged on whichever stranger's certificate someone had planted in it.
        //
        // Freed with sk_X509_free through X509StackPtr, which does not
        // down-ref: CMS_get0_signers builds its stack with
        // X509_ADD_FLAG_DEFAULT, so the certificates in it belong to the
        // CMS_ContentInfo.
        const X509StackPtr signers(CMS_get0_signers(cms.get()));
        // Cannot be reached from any input: CMS_verify has already refused an
        // object with no SignerInfo, and one whose signer certificate it could
        // not find. It stays because an allocation failure inside
        // CMS_get0_signers would otherwise leave an empty stack that names no
        // anchor, and answering NoAnchorForIssuer to that would blame the
        // caller's configuration for a failure here.
        if (sk_X509_num(signers.get()) <= 0) {
            return CscaVerdict::Failed;
        }
        // This narrows the refusal and never grants anything -- only the chain
        // check below accepts a document. It does narrow what can be accepted
        // in one way: it assumes the ICAO profile, in which a document signer
        // is issued directly by a country signing certificate, so a signer
        // that would chain through an intermediate the caller does not hold is
        // answered NoAnchorForIssuer. That is a narrowing towards refusal.
        if (!someSignerNamesAnAnchor(signers.get(), anchors)) {
            return CscaVerdict::NoAnchorForIssuer;
        }
    }

    // The chain, and the only step that can accept anything. A document whose
    // issuer name matches an anchor and whose signature was made by another
    // key reaches here and is refused here.
    const ErrorQueueMark errorMark;
    const X509StorePtr store = storeOfAnchors(anchors);
    if (!store) {
        // An allocation or a parameter that would not take. Failed rather than
        // AnchorsUnusable: the anchors decoded, so nothing is wrong with what
        // the caller configured, and rather than Passed because nothing was
        // established.
        return CscaVerdict::Failed;
    }
    // No flags: everything CMS_verify does is wanted this time, including that
    // EVERY signer chains, so a stranger appended beside the genuine document
    // signer cannot ride along.
    return CMS_verify(cms.get(), nullptr, store.get(), nullptr, nullptr, 0) == 1 ? CscaVerdict::Passed
                                                                                 : CscaVerdict::Failed;
}

bool signerChainsToAnyAnchor(const std::vector<uint8_t>& signerCertDer,
                             const std::vector<std::vector<uint8_t>>& anchorsDer)
{
    // decodeAnchors brackets the queue per element, as it does for
    // evaluateCscaChain; everything after it is bracketed once here, because a
    // failed X509_verify_cert leaves a handful of entries behind and this
    // function promises the caller's queue back unchanged.
    const std::vector<X509Ptr> anchors = decodeAnchors(anchorsDer);
    // An empty set and a set of which nothing decoded arrive here as the same
    // thing, deliberately: with one question and two answers there is no
    // configuration verdict to distinguish them with. A caller that needs the
    // distinction knows its own configuration.
    if (anchors.empty()) {
        return false;
    }

    const ErrorQueueMark errorMark;

    // The same null and LONG_MAX guards as everywhere else here. d2i refuses a
    // zero length itself, so `empty()` cannot change the answer; the LONG_MAX
    // half cannot either where this builds, and stays for the narrowing cast.
    if (signerCertDer.empty() || signerCertDer.size() > static_cast<size_t>(LONG_MAX)) {
        return false;
    }
    const unsigned char* p = signerCertDer.data();
    const X509Ptr signer(d2i_X509(nullptr, &p, static_cast<long>(signerCertDer.size())));
    if (!signer) {
        return false;
    }
    // Bytes trailing the certificate are not refused, as evaluateCscaChain does
    // not refuse them after a ContentInfo: the subject here is who issued this
    // certificate, not how the caller framed it.

    // storeOfAnchors and not a store of its own, so that this function cannot
    // drift from evaluateCscaChain on the two defaults both must turn off.
    // X509_V_FLAG_PARTIAL_CHAIN is the one that decides this function's whole
    // subject: a CSCA link certificate is not self-signed, so without it the
    // rotation rule this exists to serve is answered `false` in exactly the
    // case it was written for. See the header, and storeOfAnchors above for the
    // full reasoning -- it is not repeated because there must be one copy of it.
    const X509StorePtr store = storeOfAnchors(anchors);
    if (!store) {
        // An allocation or a parameter that would not take. False rather than
        // true, because nothing was established.
        return false;
    }

    const X509StoreCtxPtr ctx(X509_STORE_CTX_new());
    if (!ctx) {
        return false;
    }
    // No untrusted stack: a caller with a bare certificate has no chain to
    // offer, and an intermediate it does not hold is one the anchors have to
    // reach on their own. That narrows towards refusal, like the issuer-name
    // prefilter in evaluateCscaChain.
    if (X509_STORE_CTX_init(ctx.get(), store.get(), signer.get(), nullptr) != 1) {
        return false;
    }
    // X509_STORE_CTX_init copies the store's verification parameters into the
    // context, which is what carries the two flags across; setting them on the
    // store rather than here is also what keeps them from being overwritten.
    return X509_verify_cert(ctx.get()) == 1;
}

// A fourth anonymous namespace, opened after the four functions above for the
// same reason the others were: nothing the directory loader needs is in scope
// while they are read. Same internal-linkage rule, and the same reason --
// passive_auth.cpp shares this namespace and defines a BIODeleter of its own at
// namespace scope.
namespace {

struct BIODeleter
{
    void operator()(BIO* p) const
    {
        BIO_free(p);
    }
};

// OPENSSL_malloc'd buffers (e.g. the output of i2d_X509) are freed with
// OPENSSL_free, not the type-specific *_free functions above.
struct OpenSSLBufferDeleter
{
    void operator()(unsigned char* p) const
    {
        OPENSSL_free(p);
    }
};

using BIOPtr = std::unique_ptr<BIO, BIODeleter>;
using OpenSSLBufferPtr = std::unique_ptr<unsigned char, OpenSSLBufferDeleter>;

// Re-encodes @p cert as DER and appends it to @p out. The intermediate
// OPENSSL_malloc'd buffer is held in an RAII wrapper before the append, so a
// throwing emplace_back (e.g. std::bad_alloc) cannot leak it. Returns false,
// appending nothing, on a failed encode; any OpenSSL error this leaves
// queued is the caller's concern (see ErrorQueueMark, used per entry in
// loadAnchorDerFromDirectory below).
bool appendCertDer(X509* cert, std::vector<std::vector<uint8_t>>& out)
{
    // i2d_re_X509_tbs FIRST, and it is not tidiness. X509_CINF is an
    // ASN1_SEQUENCE_enc: a certificate decoded from BER keeps the
    // tbsCertificate bytes it was decoded from, and i2d_X509 replays that
    // cached copy verbatim -- so a file carrying `30 80 ... 00 00` inside its
    // Certificate comes back out still carrying it. The tbsCertificate holds
    // the subject, the key and the serial, which is what a fingerprint or a
    // revocation lookup is about, so one logical anchor spelled two ways would
    // otherwise fingerprint two ways. This call marks the cache stale, and the
    // i2d below then encodes from the parsed structure.
    //
    // Only the encoding changes: the fields do not, so the subject and the key
    // an anchor is used for are the same either way.
    if (i2d_re_X509_tbs(cert, nullptr) <= 0)
        return false;
    unsigned char* der = nullptr;
    const int len = i2d_X509(cert, &der);
    if (len <= 0)
        return false;
    OpenSSLBufferPtr guard(der);
    out.emplace_back(guard.get(), guard.get() + len);
    return true;
}

} // namespace

std::vector<std::vector<uint8_t>> loadAnchorDerFromDirectory(const std::string& dir, bool* outReadable)
{
    if (outReadable)
        *outReadable = false;

    std::vector<std::vector<uint8_t>> result;

    // status()-based queries never throw and report a nonexistent path as
    // "not a directory" rather than as an error, so this alone already
    // rejects a missing path without needing the iterator below.
    std::error_code ec;
    if (!std::filesystem::is_directory(dir, ec) || ec)
        return result;

    // The error_code overload: the default-constructing one throws on a
    // regular file, a dangling symlink, or an unreadable directory, and that
    // exception would unwind straight across the plugin's dlopen boundary.
    std::filesystem::directory_iterator it(dir, ec);
    if (ec)
        return result;

    // Tracks whether every entry the directory listed could actually be
    // opened and, once a certificate was parsed out of it, returned. A
    // directory can be listable (read permission) while an individual entry
    // in it cannot be opened -- e.g. a directory mode that allows reading
    // its listing but not searching it still lets readdir() report each
    // entry's type from the listing itself, so is_regular_file() succeeds;
    // the permission failure only surfaces later, when opening the entry by
    // name requires resolving that same denied path. A dangling symlink
    // fails earlier, at the type check itself, because following it always
    // requires a real lookup that the listing alone cannot answer. Neither
    // is "this happens not to be a certificate", and folding either into an
    // ordinary skip would make a non-empty, partially unreadable directory
    // look identical to an empty, fully-read one; *outReadable exists
    // specifically so a caller can tell those apart.
    bool fullyEnumerated = true;

    const std::filesystem::directory_iterator end;
    while (it != end) {
        // Bounds the OpenSSL error-queue window to this one entry (see
        // ErrorQueueMark above) rather than the whole scan; it pops back to
        // its mark, discarding whatever this entry alone queued, when this
        // iteration's scope ends -- on every path out of it: falling
        // through to the next iteration, `break` below, and an exception.
        //
        // How much room one entry needs was measured rather than assumed,
        // because a failed ASN.1 parse can queue one error per template level
        // unwound rather than a single summary error: exhaustive single-byte
        // corruption of a real certificate (807 positions, tried both raw and
        // PEM-wrapped) plus a 300 000-mutant fuzz found a worst case of 11
        // pushes for one entry (a PEM-wrapped certificate with 3 bytes
        // flipped). That is inside the 16-slot ring, but with 5 slots of
        // headroom, not the 14 a naive "one push per failed attempt" count
        // would suggest -- and it is why this mark is per entry and not per
        // scan.
        const ErrorQueueMark errorMark;

        std::error_code fileEc;
        const bool isRegular = it->is_regular_file(fileEc);
        if (fileEc) {
            fullyEnumerated = false;
        } else if (isRegular) {
            const std::string path = it->path().string();
            BIOPtr bio(BIO_new_file(path.c_str(), "rb"));
            if (!bio) {
                fullyEnumerated = false;
            } else {
                // A file may hold more than one certificate (an
                // administrator's concatenated PEM bundle is the ordinary
                // shape of a published CSCA set, not the exception), so read
                // PEM certificates in a loop until none remain rather than
                // stopping after the first.
                bool sawPemCert = false;
                while (true) {
                    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
                    if (!cert)
                        break; // end of a bundle, or not PEM at all -- either way, done here
                    sawPemCert = true;
                    if (!appendCertDer(cert.get(), result))
                        fullyEnumerated = false; // parsed, but could not be returned
                }

                if (!sawPemCert) {
                    // Not PEM (or empty): rewind and try raw DER. File BIOs
                    // return fseek()'s convention here -- 0 on success -- the
                    // opposite of the usual OpenSSL "1 means success", so
                    // this return is deliberately left unchecked rather than
                    // tested the normal way. A failed rewind just leaves the
                    // read position wherever the failed PEM attempt left it,
                    // and d2i_X509_bio below then fails harmlessly on
                    // whatever follows.
                    static_cast<void>(BIO_reset(bio.get()));
                    X509Ptr cert(d2i_X509_bio(bio.get(), nullptr));
                    if (cert) {
                        if (!appendCertDer(cert.get(), result))
                            fullyEnumerated = false; // parsed, but could not be returned
                    }
                    // else: not a certificate at all; skip silently.
                }
            }
        }
        // else: not a regular file (a subdirectory, a device, ...); skip
        // silently -- this is not a readability problem.

        it.increment(ec);
        if (ec) {
            fullyEnumerated = false;
            break;
        }
    }

    if (outReadable)
        *outReadable = fullyEnumerated;

    return result;
}

} // namespace emrtd::crypto

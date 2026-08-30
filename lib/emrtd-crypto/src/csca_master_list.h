// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace emrtd::crypto {

/// @brief Why a CSCA master list could not be turned into a set of anchors.
enum class MasterListError {
    /// The bytes are not a master list at all. Also the answer for empty
    /// input, for bytes that are not exactly one CMS ContentInfo, for a
    /// ContentInfo that is not a SignedData, for one carrying no SignerInfo,
    /// and for a signed `contentType` attribute that is absent, duplicated,
    /// multi-valued, not an OID, or disagrees with the `eContentType` field.
    /// parseCscaMasterList() lists all of them.
    NotAMasterList,
    /// A master list that carries no certificate. Distinct from a successful
    /// parse returning nothing, which never happens.
    Empty,
    /// The object is a master list, but its content cannot be read: detached,
    /// so the list is not in it at all; or present and not decodable as a
    /// `CscaMasterList`; or holding an element that is not a certificate.
    Malformed,
    /// The signature over the list does not verify.
    /// @note Never returned by parseCscaMasterList(), which does not look at
    ///       the signature; it exists for the verifying caller.
    BadSignature,
    /// The list verifies, but not against the signer that was expected.
    /// @note Never returned by parseCscaMasterList(), which does not look at
    ///       the signer; it exists for the verifying caller.
    SignerMismatch,
};

/// @brief The trust anchors an ICAO CSCA master list carries.
struct MasterList
{
    /// Every element of the list's `SET OF`, each as the bytes the list
    /// carries for it -- the exact slice `d2i` consumed, not a re-encoding of
    /// what `d2i` produced.
    ///
    /// The order is the list's own encoded order, and that is a guarantee
    /// about this output rather than something the parser tolerates on the way
    /// in: `SET OF` ordering is not checked, but whatever order arrives is the
    /// order returned, element for element. A caller may index into this
    /// against its own reading of the same file. Reordering here would not
    /// make the parser stricter or looser, it would quietly hand back
    /// different anchors under the same indices.
    ///
    /// Each element parsed as a certificate, but is not guaranteed to be DER:
    /// `d2i` accepts BER, so an element rewrapped with an indefinite length
    /// comes back beginning `30 80` and ending `00 00`. Handing the bytes on
    /// as found is deliberate. parseCscaMasterList() runs before anything has
    /// verified the input, so the encoding is whatever produced the file --
    /// an attacker included -- and canonicalising it here would replace the
    /// bytes a later check is meant to be checking. A consumer that needs
    /// canonical DER, to hash or fingerprint or re-emit, must re-encode.
    ///
    /// Re-encoding means `i2d_re_X509_tbs(x, nullptr)` and THEN `i2d_X509`.
    /// `i2d_X509` on its own does not canonicalise: `X509_CINF` is an
    /// `ASN1_SEQUENCE_enc`, so a certificate decoded from BER keeps the
    /// `tbsCertificate` bytes it came from and `i2d_X509` replays that cached
    /// copy verbatim -- output that still begins `30 82 .. 30 80`, still not
    /// DER. The `tbsCertificate` is where the subject, the key and the serial
    /// are, so that is exactly the part a fingerprint is about.
    /// loadAnchorDerFromDirectory() does this and returns canonical DER;
    /// nothing else here does it for you.
    std::vector<std::vector<uint8_t>> cscaDer;
};

/// @brief Reads the anchors out of an ICAO CSCA master list.
///
/// Parses `der` as a CMS SignedData whose encapsulated content is
/// `CscaMasterList ::= SEQUENCE { version INTEGER, certList SET OF Certificate }`
/// (ICAO 9303-12) and returns the certificates it carries.
///
/// **This function does not verify the signature, and does not look at who
/// produced it.** It answers "what does this list say it carries", not "may
/// this list be trusted"; a caller that acts on the anchors has to establish
/// the second question separately. `BadSignature` and `SignerMismatch` are
/// therefore never returned here.
///
/// What it does check, and the answer when the check fails:
/// - `der` is exactly one CMS ContentInfo, with nothing trailing it, and that
///   ContentInfo is a SignedData -- otherwise `NotAMasterList`.
/// - The encapsulated content type is `2.23.136.1.1.2` (id-icao-cscaMasterList)
///   in **both** places it appears: the `eContentType` field, and the signed
///   `contentType` attribute of every SignerInfo. There must be at least one
///   SignerInfo, and each must carry exactly one such attribute with exactly
///   one value. Any disagreement, absence or duplication -- otherwise
///   `NotAMasterList`. Both are read because only the attribute is covered by
///   the signature: an object whose `eContentType` field alone says master list
///   may simply have been relabelled after signing.
/// - The encapsulated content is present (not detached) and decodes as a
///   SEQUENCE holding an INTEGER followed by a SET, with no other field in the
///   SEQUENCE and nothing after it, and every element of that SET parses as a
///   Certificate -- otherwise `Malformed`. Those three structural headers must
///   be universal-class, carry the exact tag, use a definite length, and be
///   constructed exactly where the type says so -- a BER constructed `version`
///   INTEGER is rejected. None of that reaches inside an element: those only
///   have to parse, and `d2i` accepts BER there (see MasterList::cscaDer).
/// - The encapsulated content is not empty. A present but zero-length eContent
///   is `Malformed`, not `Empty`: `Empty` is reserved for a list that parsed
///   and carries no certificate, and nothing parsed here.
/// - The SET holds at least one element -- otherwise `Empty`.
///
/// Some of what it accepts without comment. This list is not exhaustive: the
/// rule is that anything not named under "does check" above goes unexamined.
/// - The `version` INTEGER has to be there, but its value is not examined; any
///   value parses.
/// - The certificates are returned as encoded, not judged: expiry, CA basic
///   constraints, key usage, self-signature and duplicates are all somebody
///   else's question, and none of them is checked here.
/// - `SET OF` ordering is not checked, so a list whose set is not sorted --
///   which is not DER -- is still read.
/// - Everything else in the SignedData is ignored: the certificates and CRLs
///   carried beside the content, unsigned attributes, and every signed
///   attribute other than `contentType`.
/// - Encoding forms this is not the place to police, because nothing has been
///   verified yet and rejecting them here would only move the argument: the
///   outer ContentInfo may be BER with indefinite lengths; the three
///   structural headers may use a non-minimal long-form length, or the
///   high-tag-number form (`3F 10`, `3F 11`, `1F 02`) instead of the short
///   one; and an element may be any BER `d2i_X509` tolerates.
///
///   That tolerance is a parser-differential surface, and it is safe only
///   because of what MasterList::cscaDer promises: the element comes back as
///   the raw slice, and a consumer that hashes or fingerprints one is told to
///   re-encode first -- with `i2d_re_X509_tbs` before `i2d_X509`, since
///   `i2d_X509` alone replays the cached BER and canonicalises nothing. See
///   MasterList::cscaDer for why. Fingerprint the slice as found and the same
///   logical anchor yields a different fingerprint for every encoding of it --
///   which is a revocation list that misses, or a trust store that holds one
///   anchor twice. The re-encode is not tidiness; it is the condition on
///   accepting these forms at all.
///
/// Rejections are silent: nothing is logged, and no exception is thrown to
/// describe them -- the returned error is the whole diagnosis. `std::bad_alloc`
/// can still escape, as it can from any other `std::vector` use.
///
/// The OpenSSL error queue is left exactly as the caller had it, on both the
/// success and the rejection paths -- with one limit no bracket can lift. The
/// queue is a fixed-size ring, so a caller that walks in with it nearly full
/// loses its own oldest entries to eviction while this runs, before anything
/// here gets to pop what it queued. What is still in the ring is restored;
/// what the ring dropped is gone.
///
/// @param der the encoding of a signed master list, as published.
/// @return the anchors the list carries -- never an empty set, and see
///         MasterList::cscaDer for what their bytes are and are not -- or the
///         first check that failed.
///
/// Returns encoded certificates rather than `X509*` for the same reason
/// `passive_auth.h` does: this header carries no OpenSSL type, so it stays
/// includable across the eMRTD plugin's dlopen boundary.
[[nodiscard]] std::expected<MasterList, MasterListError> parseCscaMasterList(const std::vector<uint8_t>& der);

/// @brief A master list whose signature held, and what that established about
///        who signed it.
struct VerifiedMasterList
{
    /// The anchors, exactly as parseCscaMasterList() returns them. See
    /// MasterList::cscaDer for what their bytes are and are not; verification
    /// changes none of that, and in particular does not canonicalise them.
    MasterList list;

    /// SHA-256 over the DER of a signer's SubjectPublicKeyInfo. Always filled
    /// when a value is returned.
    ///
    /// **Whose.** With a pin, the signer that MATCHED it -- so this equals
    /// `expectedSpkiSha256`, and is a fingerprint the call established
    /// something about. Without one, the first SignerInfo in the object's own
    /// encoded order, which is what a caller shows a person in order to be
    /// told whether to pin it.
    ///
    /// It is deliberately not "the first signer" in both cases. SignerInfos
    /// are a DER `SET OF`, so which one lands first is decided by the encoding,
    /// and anyone may append a signer of their own to a list; on a pinned call
    /// the first signer may therefore be a key this function checked nothing
    /// about, and handing that back is how a caller comes to store it.
    ///
    /// Over the SubjectPublicKeyInfo and not over the certificate, so the same
    /// key reissued in a new certificate keeps the same fingerprint. A caller
    /// pinning this does not have to re-pin at every renewal, which pinning the
    /// certificate would force.
    std::vector<uint8_t> signerSpkiSha256;

    /// Whether the fingerprint was COMPARED with one the caller supplied, as
    /// opposed to merely reported.
    ///
    /// False means the call established that somebody signed this list and
    /// nothing at all about who -- no chain is built, so an attacker who signs
    /// a list of their own anchors with a key of their own gets exactly the
    /// same `false` that the real publisher gets. That is a weaker claim than
    /// a pinned check, and it is carried here rather than folded into the
    /// return value so that a caller who forgets to pass a pin cannot mistake
    /// it for one: without this field both look like success.
    bool identityChecked = false;

    /// The certificate that SIGNED the list, as it was encoded. Always filled
    /// when a value is returned.
    ///
    /// **Whose**, and the answer is the same one signerSpkiSha256 gives: with
    /// a pin, the signer that MATCHED it; without one, the first SignerInfo in
    /// the object's own encoded order. The two fields describe ONE
    /// certificate, so fingerprinting this yields signerSpkiSha256 back.
    ///
    /// Taken from the signers a successful verification resolved, never from
    /// the object's certificate bag: the bag is unauthenticated and anyone may
    /// drop anyone's certificate into it, so a certificate lifted from there
    /// would be a stranger's as readily as the publisher's.
    ///
    /// It is carried because the caller that follows a publisher through a key
    /// rotation needs it. signerChainsToAnyAnchor() asks whether the NEW signer
    /// chains to an anchor the PREVIOUS list carried, and it takes a bare
    /// certificate -- which without this field the caller would have to obtain
    /// out of band, although it is already inside the bytes just handed over.
    std::vector<uint8_t> signerCertDer;

    /// When the list was signed, out of the `signingTime` SIGNED attribute of
    /// that same signer's SignerInfo, as seconds since the Unix epoch.
    ///
    /// **Signed, which is what makes it worth reading.** signingTime is part of
    /// `signedAttrs`, so the signature covers it and the publisher is committed
    /// to it once the signature has held. The same attribute among the UNSIGNED
    /// ones is attacker-controlled, and a date taken from there would be worse
    /// than none: it would look like protection while being whatever the last
    /// hand to touch the file chose.
    ///
    /// **EMPTY when the list carries no such attribute.** That is a property of
    /// the input, not a shortcoming here: nothing is invented, and a list is
    /// not refused for lacking a date -- one without a signingTime is a
    /// perfectly valid CMS object. The consequence is real and belongs to the
    /// caller: **refusing a replayed list is impossible without a date to
    /// compare**, so an undated list leaves a publisher free to hand back a
    /// strictly OLDER set of anchors -- one that restores a withdrawn anchor,
    /// or that drops a country's current one. What to do about that is the
    /// caller's decision; this function only reports what the object says.
    ///
    /// Empty as well when the attribute is present but no single time can be
    /// read out of it: more than one signingTime, more than one value inside
    /// one, or a value that is neither a UTCTime nor a GeneralizedTime. None of
    /// those is "some time", and none may be passed on as one.
    std::optional<int64_t> signingTimeEpochSeconds;
};

/// @brief Verifies an ICAO CSCA master list and says whether it was signed by
///        the signer the caller named.
///
/// In this order:
/// 1. `der` is decoded as one CMS ContentInfo -- `NotAMasterList` if it does
///    not decode at all.
/// 2. Every SignerInfo is verified over the content the object carries --
///    `BadSignature` if any of them does not hold.
/// 3. If `expectedSpkiSha256` is not empty, **some** signer's
///    SubjectPublicKeyInfo fingerprint must equal it -- `SignerMismatch` if
///    none does. `identityChecked` records whether this step ran.
///    "Signer" means a certificate that verified a SignerInfo of this object,
///    never one the object merely carries: a CMS certificate bag is
///    unauthenticated, so a stranger may plant the trusted publisher's
///    certificate beside a list of their own without touching any signature.
///    The claim established here is "the pinned key signed this", not "the
///    pinned certificate travels with this".
/// 4. The anchors are read with parseCscaMasterList(), whose verdict is
///    returned unchanged -- `NotAMasterList`, `Malformed` or `Empty` all still
///    reach the caller, from a list that verified.
///
/// **Step 4 is a barrier, not a formality.** Only the signed `contentType`
/// attribute is under the signature; the `eContentType` field beside it is not.
/// So an object genuinely signed by the very signer a caller pinned, over
/// genuine master-list bytes, under some other content type, and relabelled
/// afterwards, passes steps 2 and 3 outright. parseCscaMasterList comparing
/// those two places is the only thing that stops it, and it is the reason
/// nothing here may be reordered into a fast path that skips the parse once a
/// pin has been met.
///
/// **Steps 2 and 3 are in that order deliberately.** Comparing the fingerprint
/// first would answer "does this fingerprint match" for a list whose signature
/// does not hold -- a question with no security content, since anyone may copy
/// a certificate into an object they did not sign. So a list that both fails
/// its signature and names an unexpected signer is `BadSignature`, not
/// `SignerMismatch`.
///
/// **No chain is built.** The signer's certificate is not chained to any store,
/// and is not checked for expiry, key usage, extended key usage, basic
/// constraints or revocation. Identity rests entirely on the fingerprint, which
/// the caller has to have obtained some other way -- out of band, or by showing
/// VerifiedMasterList::signerSpkiSha256 to a person who can recognise it. This
/// function does not remember a fingerprint between calls; a caller that wants
/// pinning across imports has to store it.
///
/// That is not an omission on two counts. A master list is what supplies trust
/// anchors, so at first import there is nothing to chain it to -- and, more to
/// the point, once identity rests on a pinned key the certificate around it is
/// a **container for the key, not a credential**: every one of those checks
/// says something about the container. Two of them would refuse lists that are
/// perfectly good. Expiry, because a master list outlives by years the key that
/// signed it, so a signer whose certificate has lapsed is the ordinary case
/// rather than the suspicious one. Extended key usage, because CMS_verify
/// applies the `smime_sign` purpose, which demands `emailProtection`: a signer
/// carrying no EKU at all passes that, so it is precisely the ICAO-profiled
/// certificate -- the real one -- that such a check would turn away.
///
/// What `BadSignature` covers, all of which are "nothing here vouches for
/// these anchors" rather than distinct diagnoses:
/// - a signature or a content digest that does not verify, for any signer, not
///   only the first;
/// - an object that is not a SignedData at all, and a SignedData carrying no
///   SignerInfo -- neither of which parseCscaMasterList() would have called a
///   signature problem, but neither of which has a signature to check;
/// - a detached signature, whose content is not in the object, so there is
///   nothing to verify it against;
/// - a signer whose certificate the object does not carry, since the key to
///   check the signature with is then missing.
///
/// Verification runs before the content is read, so these answers displace the
/// ones parseCscaMasterList() gives for the same bytes: a detached list is
/// `BadSignature` here and `Malformed` there, and a signerless one is
/// `BadSignature` here and `NotAMasterList` there. Nothing is accepted here
/// that is rejected there.
///
/// An empty `expectedSpkiSha256` means "do not compare", and is the only way
/// to ask for that. A fingerprint is 32 bytes; anything of another length can
/// match nothing, and is `SignerMismatch` rather than a match against the part
/// that was supplied.
///
/// Rejections are silent, as in parseCscaMasterList(): the returned error is
/// the whole diagnosis. `std::bad_alloc` can still escape.
///
/// The OpenSSL error queue is left exactly as the caller had it, on both the
/// success and the rejection paths -- with one limit no bracket can lift. The
/// queue is a fixed-size ring, so a caller that walks in with it nearly full
/// loses its own oldest entries to eviction while this runs, before anything
/// here gets to pop what it queued. What is still in the ring is restored;
/// what the ring dropped is gone.
///
/// @param der the encoding of a signed master list, as published.
/// @param expectedSpkiSha256 SHA-256 over the DER of the SubjectPublicKeyInfo
///        of the signer the caller will accept, or empty to accept any signer
///        and only report the one seen.
/// @return the anchors together with what was established about the signer, or
///         the first check that failed.
[[nodiscard]] std::expected<VerifiedMasterList, MasterListError>
parseAndVerifyMasterList(const std::vector<uint8_t>& der, const std::vector<uint8_t>& expectedSpkiSha256);

/// @brief Computes the pin parseAndVerifyMasterList() compares against, from
///        the publisher's certificate.
///
/// **This is the only supported way to produce that value.** The whole trust
/// model of parseAndVerifyMasterList() rests on the caller having the right 32
/// bytes, and there are two obvious ways to get them wrong.
///
/// Not the hash of the certificate. A publisher renews its certificate while
/// keeping its key, and every renewal would then change the pin -- so a caller
/// that hashed the certificate would have to re-pin at each one, out of band,
/// or start refusing genuine lists. The key is what the claim is about; the
/// certificate is a container for it. VerifiedMasterList::signerSpkiSha256 says
/// the same thing from the other side.
///
/// Not the SubjectPublicKeyInfo slice as the certificate carries it. That is a
/// byte range chosen by whoever encoded the certificate, and two encodings of
/// one key would fingerprint differently. This hashes the SubjectPublicKeyInfo
/// re-encoded with `i2d`, which is canonical, so the same key gives the same 32
/// bytes whatever it arrived in.
///
/// @param certDer one certificate, as encoded -- the publisher's, obtained out
///        of band. It must be exactly one certificate with nothing trailing it;
///        anything else is `std::nullopt`. BER is accepted, since the answer
///        does not depend on the encoding.
/// @return the 32 bytes to hand parseAndVerifyMasterList() as
///         `expectedSpkiSha256`, or nothing if @p certDer is not a certificate.
///         Never an empty vector: a value means a fingerprint.
///
/// Silent like everything else here, and the same error-queue promise: the
/// OpenSSL error queue is left as the caller had it.
[[nodiscard]] std::optional<std::vector<uint8_t>> spkiSha256FromCertificateDer(const std::vector<uint8_t>& certDer);

/// @brief Loads the certificates found in @p dir as DER-encoded blobs.
///
/// Reads plain files directly, unlike OpenSSL's own directory loader, which
/// only finds certificates a `c_rehash` run has symlinked. Multiple
/// certificates per file are read only from a concatenated PEM bundle --
/// every certificate it carries, not just the first, since that is the
/// ordinary shape a published CSCA set is distributed in. A file that is
/// not PEM is tried as DER instead, which yields at most its first
/// certificate: concatenated DER in one file is not a format anything
/// publishes, so this asymmetry is deliberate, not an oversight.
///
/// @param dir path to a directory of certificates, any file name: a PEM
///        file may hold more than one certificate, a DER file yields only
///        its first.
/// @param outReadable when non-null, set to `true` once @p dir has been
///        opened and every regular-file entry in it -- the only kind this
///        function reads -- could be opened and, where it parsed as a
///        certificate, returned. A subdirectory or other non-regular entry
///        is skipped without affecting this flag either way; a directory
///        holding only such entries still reports `true` with nothing
///        returned. Set to `false` when @p dir does not exist, is not a
///        directory, or could not be fully read -- including a directory
///        that lists fine but contains a regular-file entry that could not
///        be opened (e.g. a restrictive file mode) or an entry that could
///        not even be resolved to a type (e.g. a dangling symlink). This is
///        how a caller tells "genuinely holds no anchors" apart from
///        "could not be read": an empty return alone means either.
/// @return the DER encoding of every certificate found, in whatever order
///         the platform's directory listing happens to produce -- callers
///         must not rely on it being sorted or stable across calls. DER
///         canonically, not as the file spelled it: every certificate is
///         re-encoded from what was parsed, so the bytes returned may differ
///         from the file's for a file that carried BER, and one logical
///         certificate yields one encoding however many ways it was written
///         down. That is what makes fingerprinting one of these, or looking
///         one up in a revocation list, mean anything. Only the
///         failures @p outReadable documents (an entry that could not be
///         opened, resolved, or re-encoded) are reported through it rather
///         than thrown; a file that simply does not parse as a certificate
///         is skipped silently, not reported as unreadable. Neither is
///         covered by an exception across the eMRTD plugin's dlopen
///         boundary; this does not cover allocation failure
///         (`std::bad_alloc`), which can still escape like it can from any
///         other `std::string`/`std::vector` use.
///
/// Returns DER, not `X509*`, for the same reason everything else here does:
/// this header carries no OpenSSL type and must not start doing so, because
/// the eMRTD plugin includes it across a dlopen boundary. Certificate
/// construction stays in the `.cpp`.
[[nodiscard]] std::vector<std::vector<uint8_t>> loadAnchorDerFromDirectory(const std::string& dir,
                                                                           bool* outReadable = nullptr);

/// @brief What came of holding a document's signer up against the trust anchors
///        a caller has configured.
///
/// Five answers rather than two, because three of them are refusals that mean
/// different things to whoever reads them. `NotConfigured` and
/// `AnchorsUnusable` describe the caller's own setup and say nothing about the
/// document. `NoAnchorForIssuer` and `Failed` both describe the document, and
/// the gap between them is the gap between "we hold nothing from the authority
/// this document names" and "this document does not chain to what we do hold".
/// Only the second is an accusation; collapsing the two is how a store nobody
/// finished configuring comes to read as a forgery, and how a forgery comes to
/// read as a store nobody finished configuring.
enum class CscaVerdict {
    /// No anchor source was configured, so nothing was checked. Never a
    /// judgement on the document: on this path the document is not read at all.
    NotConfigured,
    /// A source was configured and not one usable anchor came out of it.
    /// Deliberately not the same answer as `NotConfigured`: somebody meant to
    /// establish trust here and it is not working, which is a thing to fix
    /// rather than a thing to leave alone.
    AnchorsUnusable,
    /// Anchors are held, and no signer of this document names any of them as
    /// its issuer. Nothing is alleged about the document.
    NoAnchorForIssuer,
    /// Every signer of the document chains to an anchor held. See below for
    /// what this does NOT establish -- it is a narrower claim than "the
    /// document is genuine".
    Passed,
    /// A chain was attempted against the anchors held, and it did not hold.
    Failed,
};

/// @brief Judges a document's security object against a set of trust anchors.
///
/// Pure: it reads its arguments, touches nothing else, and remembers nothing
/// between calls.
///
/// The answers are reached in this order, and the order is part of the
/// contract:
///
/// 1. `anchorsPathWasGiven` is false -- `NotConfigured`, whatever @p sodDer
///    and @p anchorsDer hold. The flag is the caller's own statement about its
///    configuration and is believed: a caller that hands over anchors while
///    saying no source was configured is answered `NotConfigured`, not judged
///    against those anchors. That is deliberate. This function cannot tell
///    where the anchors came from, so if the flag and the vector disagree, the
///    flag is the one that was written down on purpose, and the neutral answer
///    is the one that neither vouches for nor accuses a document.
/// 2. No element of @p anchorsDer decodes as a certificate -- `AnchorsUnusable`.
///    An element that does not decode is passed over rather than being fatal:
///    it cannot match the issuer comparison below and it does not enter the
///    store, so one unreadable file among many costs only that file.
///    `AnchorsUnusable` is what is left when passing over them all leaves
///    nothing, and an empty @p anchorsDer reaches it by the same route.
/// 3. From here on the document is read, and the configuration answers can no
///    longer be reached.
///
/// What is then done with the document, in order:
///
/// 4. @p sodDer is decoded as one CMS ContentInfo, and its SignerInfos are
///    resolved by verifying it with `CMS_NO_SIGNER_CERT_VERIFY` -- signatures
///    and signed attributes checked, no chain built, since there is nothing to
///    build one against yet. Anything that stops this is `Failed`: bytes that
///    are not a CMS at all, empty input, an object that is not a SignedData, a
///    SignedData carrying no SignerInfo, a detached one whose content is not
///    there to verify against, a signature that does not hold, and a signer
///    whose certificate the object does not carry, so that there is no key to
///    check it with.
///
///    Bytes trailing the ContentInfo are the one malformation NOT refused
///    here: what follows the object is not read, and the object itself is
///    judged as it stands. A security object is read off a chip by a caller
///    that knows how long it is, and this function's subject is who signed it
///    rather than how it was framed.
///
///    `Failed` and not `NoAnchorForIssuer` for every one of those, and the
///    order is what makes it so. A document whose signature does not hold has
///    no established signer, so it has no established issuer either, and
///    answering "we hold no anchor for its issuer" would be reporting on a
///    name nothing vouches for.
///
///    The signers are taken from `CMS_get0_signers` after that verification,
///    never from the certificate bag the object carries. The bag is
///    unauthenticated and anybody may drop anybody's certificate into it, so a
///    bag reading would answer "does this document carry a certificate from an
///    authority we hold" instead of "was this document signed by one".
/// 5. Every signer's issuer name is compared with every anchor's subject name.
///    If not one pair matches -- `NoAnchorForIssuer`. Names are compared whole,
///    as DNs; the country attribute is not looked at on its own, so two
///    authorities of one country are two different anchors here.
/// 6. The document is verified again, this time against a store holding the
///    anchors. `Passed` if that verification succeeds, `Failed` otherwise.
///
/// **Step 5 refines the refusal; it never grants anything.** Only step 6
/// decides that a document is trusted, so a document whose issuer name matches
/// an anchor and whose signature was made by some other key is `Failed`. It
/// does narrow what can be accepted, in one way worth stating: it assumes the
/// ICAO profile, in which a document signer is issued directly by a country
/// signing certificate. A document signer that chains to an anchor through an
/// intermediate the caller does not hold names that intermediate as its issuer,
/// and is answered `NoAnchorForIssuer` even though a longer path exists. That
/// is a narrowing towards refusal, not towards acceptance.
///
/// **An anchor does not have to be self-signed, and any anchor in the set may
/// terminate a chain.** That is a promise about @p anchorsDer, not an
/// implementation detail: a certificate a caller has configured as an anchor is
/// trusted because it was configured, and nothing here asks it to have signed
/// itself as well.
///
/// The stronger form of that, measured rather than assumed: **an anchor's own
/// signature is never examined here, whoever made it.** A certificate in
/// @p anchorsDer whose signatureValue is corrupt still terminates a chain, and
/// still yields `Passed` for a document that verifies against its key. That is
/// not an oversight to be repaired later -- it is what a trust anchor is. The
/// question this function answers is whether the document was signed by a key
/// the caller configured, and a signature the anchor carries over itself says
/// nothing about that. Callers who need an anchor to be internally consistent
/// must check it where anchors are accepted, not here.
///
/// It is what lets a **CSCA link certificate** be an anchor. A country that
/// rotates its country signing certificate issues one: the same subject and the
/// same public key as the new self-signed CSCA, signed by the OUTGOING key, so
/// that a verifier still holding the old certificate can reach the new key over
/// a path it can check. ICAO master lists carry these beside the self-signed
/// ones, so they arrive in @p anchorsDer as ordinary content. A link
/// certificate is not self-signed, and a verification that insisted on ending
/// at one would answer `Failed` -- the accusation -- to a genuine document from
/// a country that had rotated, whenever the link certificate is the only anchor
/// held for that authority or merely the one reached first among anchors
/// sharing its subject.
///
/// Reached first is not a thing a caller can control, which is the other half
/// of why this matters. Neither producer of an anchor set promises an order:
/// parseCscaMasterList() returns the list's own encoded order and a directory
/// loader returns whatever the platform listed, so a verdict that depended on
/// which same-subject anchor a store lookup happened to return first would be a
/// verdict decided by an encoder or a filesystem.
///
/// **Two verification defaults are turned off, and both would otherwise refuse
/// genuine documents.**
/// - The purpose is pinned to "any". Verification through CMS applies the
///   `smime_sign` purpose, which passes a certificate carrying no extended key
///   usage at all but rejects one whose extended key usage is present and does
///   not include `emailProtection`. ICAO profiles an extended key usage on
///   exactly the document signer, so it is the real certificate, not the bare
///   one, that the default turns away.
/// - The time check is turned off. A document signer's key lives months while
///   the documents it signed live ten years, so a signer that has since lapsed
///   is the ordinary case rather than the suspicious one.
///
/// **This verdict therefore contains no statement about time.** `Passed` says
/// the chain holds with the clock ignored, at both ends: an expired document
/// signer passes, and so does an expired -- or not yet valid -- anchor. The
/// check this replaces is not "is the chain valid now" but "was it valid when
/// the document was signed", and answering that needs a signing time this
/// function is not given. When one is available, the time flag gives way to a
/// verification time and the sentence a caller shows a person may become
/// stronger; until then it must not claim more than the above.
///
/// What is still enforced, so that "any purpose" is not read as "no checks":
/// basic constraints, so a leaf certificate cannot act as a CA in the middle of
/// the chain; the key usage that lets an issuer sign certificates; and the
/// signatures at every link.
///
/// **What `Passed` does not establish.** It is one half of passive
/// authentication and not the whole of it. It says nothing about what was
/// signed: the encapsulated content type is not examined, so an object of some
/// other kind, genuinely signed by a document signer of a country whose anchor
/// is held, passes here. It says nothing about the data groups on the chip
/// hashing to the values in the security object. And revocation is not
/// consulted, so a signer withdrawn by its own authority still chains. A caller
/// establishes those separately; this answers who signed, not what.
///
/// Rejections are silent, as elsewhere in this header: the returned verdict is
/// the whole diagnosis, and no exception is thrown to describe one.
/// `std::bad_alloc` can still escape, as it can from any other `std::vector`
/// use.
///
/// The OpenSSL error queue is left exactly as the caller had it, on every path
/// -- with the same limit the functions above carry: the queue is a fixed-size
/// ring, so a caller that walks in with it nearly full loses its own oldest
/// entries to eviction. What is still in the ring is restored.
///
/// @param sodDer the encoding of the document security object, as read from
///        the chip.
/// @param anchorsDer the anchors to judge against, each as an encoded
///        certificate -- from parseCscaMasterList(), from
///        parseAndVerifyMasterList(), or from
///        loadAnchorDerFromDirectory(). None of them has to be self-signed,
///        and their order is not read as a preference; see above.
/// @param anchorsPathWasGiven whether a source of anchors was configured at
///        all. It is what separates `NotConfigured` from `AnchorsUnusable`,
///        which an empty @p anchorsDer cannot do on its own.
/// @return which of the five answers this document and this configuration came
///         to.
[[nodiscard]] CscaVerdict evaluateCscaChain(const std::vector<uint8_t>& sodDer,
                                            const std::vector<std::vector<uint8_t>>& anchorsDer,
                                            bool anchorsPathWasGiven);

/// @brief Whether one certificate chains to any of a set of trust anchors.
///
/// Pure, like evaluateCscaChain(): it reads its arguments, touches nothing
/// else, and remembers nothing between calls.
///
/// evaluateCscaChain() asks the neighbouring question about a DOCUMENT, and
/// cannot be asked this one: it is handed a security object, resolves the
/// signers by verifying it, and only then builds a chain. A caller holding a
/// certificate and no document has nothing to hand it. That caller is the one
/// importing a master list: the rule it needs is **"accept a new publisher if
/// it chains to an anchor the list already trusted carried"**, which is how a
/// country's rotation is followed without a person re-pinning a fingerprint out
/// of band. It is answered here rather than by the caller because the
/// alternative is every caller growing an OpenSSL dependency and a path builder
/// of its own -- including the PARTIAL_CHAIN flag below, whose absence is
/// exactly the defect this arrangement exists to avoid.
///
/// **The same store as evaluateCscaChain(), built by the same function**, so
/// the same two verification defaults are off for the same reasons:
/// - The purpose is pinned to "any", because the `smime_sign` default rejects a
///   certificate whose extended key usage is present and omits
///   `emailProtection` -- so it is the ICAO-profiled certificate, the real one,
///   that the default turns away.
/// - The time check is off, so **this answer carries no statement about time**,
///   at either end: an expired signer chains, and so does an expired -- or not
///   yet valid -- anchor. A signer's key lives months while what it signed
///   lives years, so a lapsed signer is the ordinary case. A caller that needs a
///   date checked has to check it, and must not read one into this.
///
/// **Any anchor may terminate the chain, self-signed or not** -- the store sets
/// `X509_V_FLAG_PARTIAL_CHAIN`, and it is load-bearing rather than tidy. A CSCA
/// LINK CERTIFICATE carries the same subject and the same public key as a
/// country's new self-signed CSCA but is signed by the OUTGOING key, so it is
/// not self-signed; ICAO master lists carry them beside the self-signed ones.
/// Without the flag OpenSSL ends a chain only at a self-signed certificate and
/// goes looking for the issuer of anything else, so a caller whose anchor for a
/// country is a link certificate -- only it, or it ahead of the self-signed
/// twin a store lookup cannot tell apart -- is answered `false` about a signer
/// that authority genuinely issued. That is the whole case the rotation rule
/// exists to serve, so refusing it would leave the function with no subject.
///
/// An anchor's own signature is never examined, as in evaluateCscaChain(): a
/// certificate is an anchor because the caller configured it, and a signature
/// it carries over itself says nothing about whether the caller configured it.
///
/// What is still enforced, so that "any purpose" is not read as "no checks":
/// every signature in the chain, the basic constraints that keep a leaf from
/// acting as a CA in the middle of one, and the key usage that lets an issuer
/// sign certificates. Revocation is not consulted.
///
/// One question, two answers, and deliberately not evaluateCscaChain()'s five:
/// there is no document here to accuse, so "no anchors were configured", "none
/// of them decoded" and "it does not chain" are all `false`. A caller that has
/// to tell those apart knows its own configuration and can say so without being
/// told.
///
/// Rejections are silent, as everywhere else in this header. `std::bad_alloc`
/// can still escape.
///
/// The OpenSSL error queue is left exactly as the caller had it, on every path,
/// with the same limit the functions above carry: the queue is a fixed-size
/// ring, so a caller that walks in with it nearly full loses its own oldest
/// entries to eviction. What is still in the ring is restored.
///
/// @param signerCertDer the certificate to judge, as encoded. Exactly one
///        certificate; BER is accepted, since `d2i` accepts it. Empty, trailing
///        bytes, or anything that is not a certificate is `false`.
/// @param anchorsDer the anchors to judge against, each as an encoded
///        certificate -- from parseCscaMasterList(), from
///        parseAndVerifyMasterList(), or from loadAnchorDerFromDirectory().
///        An element that does not decode is passed over rather than being
///        fatal, exactly as in evaluateCscaChain(); an empty set, and a set of
///        which nothing decoded, are both `false`.
/// @return whether a path was built from @p signerCertDer to some anchor. A
///         certificate that IS one of the anchors chains to itself.
[[nodiscard]] bool signerChainsToAnyAnchor(const std::vector<uint8_t>& signerCertDer,
                                           const std::vector<std::vector<uint8_t>>& anchorsDer);

} // namespace emrtd::crypto

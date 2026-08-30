// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief An ICAO CSCA master list, and the passports that do or do not chain
///        to it, built in the test process instead of shipped as bytes.
///
/// A real master list may not live in this repository, and a redacted one would
/// prove less than a synthetic one: every fixture here is assembled from the
/// format itself, which is also what the tests are about.
///
/// The generator is deliberately awkward in a few places, and each awkwardness
/// closes one way a convenient fixture would let a broken implementation pass.
/// They are called out on the declarations below; please read them before
/// simplifying anything here.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace LibreSCRS::Test {

/// @brief A signed CSCA master list together with what it should be read as.
struct SyntheticMasterList
{
    std::vector<uint8_t> der;                  ///< CMS SignedData over CscaMasterList
    std::vector<std::vector<uint8_t>> cscaDer; ///< the anchors the list CARRIES, in the list's own
                                               ///< DER SET OF order, i.e. sorted by encoding
    std::vector<uint8_t> signerSpkiSha256;     ///< 32 B, SHA-256 over the signer's SubjectPublicKeyInfo
    std::size_t eContentTamperOffset = 0;      ///< see makeTamperedMasterList
};

/// @param cscaCount how many CSCAs the list carries; 0 is allowed (an empty,
///        properly signed list).
/// @param signerNotAfter when not empty, the LIST SIGNER expires then (an
///        ASN1_TIME string). Same form and the same pitfalls as makeSod's
///        dscNotAfter: prefer the 13-character UTCTime "YYMMDDHHMMSSZ", and
///        mind that RFC 5280 §4.1.2.5 reads YY 50..99 as 19YY, so
///        "500101000000Z" means 1950. An expired list signer is NORMAL — a
///        master list outlives by years the key that signed it — and a verifier
///        that establishes the signer by a pinned fingerprint rather than by a
///        chain has no reason to look at the date at all. Every certificate
///        here starts fifteen years back, so a past notAfter still leaves a
///        window the certificate was valid in.
/// @param signerEku when not empty, the LIST SIGNER carries this EKU OID. It
///        exists for the same reason makeSod's dscEku does, pointed the other
///        way: CMS_verify applies the `smime_sign` purpose, which passes a
///        certificate with NO extended key usage but rejects one whose EKU is
///        present and does not contain emailProtection. ICAO profiles an EKU on
///        a master list signer (2.23.136.1.1.3), so it is exactly the
///        real-world signer, not the bare one, that such a check would refuse.
/// CRITICAL: the list signer is issued by a SEPARATE CA that the list does not
/// carry. Were the signer to chain to an anchor inside the list, an
/// implementation that verified a list against its own contents would pass
/// every test here — and that circular check is exactly what was rejected.
[[nodiscard]] SyntheticMasterList makeMasterList(int cscaCount, const std::string& signerNotAfter = {},
                                                 const std::string& signerEku = {});

/// @brief The same anchors BYTE FOR BYTE, only a different signing key.
/// Were the anchors regenerated too, the fingerprint-mismatch test would also
/// pass for an implementation that fingerprints cscaDer[0] instead of the
/// signer.
/// @note The anchors are sorted into DER SET OF order rather than trusted to
///       arrive in it, so a HAND-BUILT unsorted @p base comes back reordered
///       and an anchorIndex into it no longer names the same anchor. Anything
///       from makeMasterList() is already sorted, so nothing moves.
[[nodiscard]] SyntheticMasterList makeMasterListWithOtherSigner(const SyntheticMasterList& base);

/// @brief A CSCA rotation: the outgoing self-signed CSCA, the incoming
///        self-signed CSCA, and the LINK CERTIFICATE that joins them, all three
///        carried by one signed master list.
///
/// **What a link certificate is**, since no document in this project explains
/// it. A country that rotates its country signing certificate cannot assume
/// every verifier in the world has already fetched the new one, so beside the
/// new self-signed CSCA it issues a link certificate: the SAME subject and the
/// SAME public key as the new CSCA, but signed by the OUTGOING key. A verifier
/// that still holds only the old CSCA can then reach the new key over a path it
/// is able to check. ICAO 9303-12 master lists carry these beside the
/// self-signed ones; they are the ordinary content of a country that has
/// rotated, not an edge case.
///
/// **Why the fixture needs one.** A link certificate is NOT self-signed, and
/// that is the property no other certificate this file produces has. An X.509
/// path builder terminates a chain only at a self-signed certificate unless it
/// is told that any configured anchor may terminate one — so a verifier holding
/// a country's link certificate and nothing else, or holding it beside the new
/// self-signed one and reaching for it first, answers "this does not chain" to
/// a perfectly genuine passport. Nothing else here can produce that input.
///
/// The two self-signed CSCAs carry different subject names, as two generations
/// of an authority's certificate may; the link certificate's subject is the
/// INCOMING one's, because that is what it is a link to.
/// @note The incoming CSCA's private key is remembered for BOTH the incoming
///       self-signed certificate and the link certificate, because it is one
///       key under two encodings. makeSod() therefore issues a document signer
///       from either index, and the two anchors are interchangeable to a path
///       builder by design — which is exactly what makes the order they arrive
///       in a thing a verdict must not depend on.
struct SyntheticCscaRotation
{
    SyntheticMasterList list; ///< carries all three anchors, in the list's own DER SET OF order
    int outgoingIndex = 0;    ///< index into list.cscaDer of the OUTGOING self-signed CSCA
    int incomingIndex = 0;    ///< index of the INCOMING self-signed CSCA
    int linkIndex = 0;        ///< index of the LINK certificate
};

[[nodiscard]] SyntheticCscaRotation makeMasterListWithLinkCertificate();

/// @brief A properly signed CMS carrying a DIFFERENT eContentType (id-data,
///        1.2.840.113549.1.7.1).
/// Without this, "not a master list" is only ever tested with garbage that
/// fails d2i, so a parser that NEVER looks at the content type passes.
[[nodiscard]] std::vector<uint8_t> makeSignedNonMasterList();

/// @brief A copy of @p ml with one byte flipped INSIDE the signed content, at
///        `eContentTamperOffset`.
/// The byte is the LAST byte of the serialNumber INTEGER of the first CSCA in
/// the list's SET OF, so the length is unchanged, the encoding stays minimal,
/// and the anchors stay in DER SET OF order — otherwise the implementation
/// answers "malformed" instead of "bad signature" and the perturbation proves
/// the wrong thing.
/// @note Only `der` changes; `cscaDer` still holds the untampered anchors, so a
///       test can show what the list was supposed to carry. Throws when @p ml
///       carries no anchor to tamper with.
/// @note The flipped byte is inside a certificate, so it also invalidates that
///       anchor's OWN self-signature. A loader that self-verifies every anchor
///       it parses will report a bad anchor rather than a bad list signature;
///       both are rejections, but they are not the same verdict.
[[nodiscard]] SyntheticMasterList makeTamperedMasterList(const SyntheticMasterList& ml);

/// @brief An UNHASHED directory holding one `<i>.pem` per anchor.
/// @return the directory path; it is created under
///         std::filesystem::temp_directory_path() and the caller deletes it.
[[nodiscard]] std::string writePemDir(const std::vector<std::vector<uint8_t>>& certsDer);

/// @brief A SOD (CMS SignedData over an LDSSecurityObject) signed by a DSC that
///        `ml.cscaDer[anchorIndex]` issued.
/// @param dscEku when not empty, the DSC carries this EKU OID. It exists
///        because CMS_verify applies the `smime_sign` purpose, which rejects
///        any certificate whose EKU does not contain emailProtection — and ICAO
///        9303-12 profiles an EKU on exactly the DSC. Without this test, real
///        passports fail.
/// @param dscNotAfter when not empty, the DSC expires then (an ASN1_TIME
///        string). Prefer the 13-character UTCTime form, "YYMMDDHHMMSSZ", e.g.
///        "200101000000Z": ASN1_TIME_set_string honours the width it is given,
///        and the 15-character form yields a GeneralizedTime, which RFC 5280
///        §4.1.2.5 forbids before 2050. Mind the pivot that form carries — the
///        same clause reads YY 50..99 as 19YY, so "500101000000Z" silently
///        means 1950, not 2050. An expired DSC on a valid passport is
///        NORMAL: its key lives for months, the passport for ten years. Every
///        certificate here starts fifteen years back, so such a chain can also
///        be verified AT SIGNING TIME, which is how that passport is accepted.
/// @note Only works on anchors THIS process minted with makeMasterList(): a DSC
///       has to be ISSUED by the anchor, and SyntheticMasterList carries
///       certificates, not private keys, so the generator remembers the key of
///       every anchor it produced, keyed on that anchor's own encoding.
///       Rebuilding the list from writePemDir() output is therefore fine — that
///       round trip is byte-identical, so the key is still found. What THROWS
///       is an anchor this process never minted: one read from a real trust
///       store, or carried over from an earlier run.
[[nodiscard]] std::vector<uint8_t> makeSod(const SyntheticMasterList& ml, int anchorIndex,
                                           const std::string& dscEku = {}, const std::string& dscNotAfter = {});

/// @brief The data groups the security object of every SOD here hashes, keyed
///        by number and holding the exact bytes that were hashed.
///
/// A caller that wants a passive-authentication run to come out consistent has
/// to hand a verifier THESE bytes — or serve them from a scripted card. They
/// live here rather than being written down again at each call site, because
/// two copies are two things to keep in step, and a drifted copy fails as a
/// hash mismatch a long way from the line that caused it.
/// @note DG1 here is a minimal data group, NOT an MRZ: nothing in this fixture
///       is about what a data group contains.
[[nodiscard]] std::map<int, std::vector<uint8_t>> sodDataGroups();

/// @brief A SOD signed by a SELF-SIGNED DSC belonging to no anchor at all — the
///        forgery. Its issuer equals its own subject, so the DN prefilter
///        rejects it BEFORE any chain is built.
[[nodiscard]] std::vector<uint8_t> makeForgedSod();

/// @brief A SOD whose DSC is self-signed but whose `issuer` is OVERWRITTEN with
///        the subject of anchor @p anchorIndex. The prefilter matches, so the
///        document reaches the chain check, and only the signature brings it
///        down.
/// Without this nothing produces a "chain built, verification failed" verdict,
/// and an implementation that answers "passed" as soon as a DN matches passes
/// the whole suite.
/// @note Unlike makeSod(), only the anchor's NAME is impersonated, so no
///       private key is needed and a @p ml rebuilt from disk works fine.
[[nodiscard]] std::vector<uint8_t> makeSodWithImpersonatedIssuer(const SyntheticMasterList& ml, int anchorIndex);

/// @brief What makeSodWithImpostorPrependedToCertificateBag() staged, and what
///        a test needs in order to say which of the two names is the true one.
struct SyntheticSodWithImpostor
{
    std::vector<uint8_t> der;                ///< the SOD; its signature still verifies
    std::map<int, std::vector<uint8_t>> dgs; ///< the data groups its security object hashes, by number
    std::string realSignerCommonName;        ///< common name of the certificate that SIGNED it
    std::string impostorCommonName;          ///< common name of the certificate sitting FIRST in the bag
};

/// @brief A SOD that is genuine in every way a holder can check, carrying one
///        extra certificate in its bag -- and that certificate comes first.
///
/// SignedData.certificates sits outside both the eContent and the signed
/// attributes, so nothing signs it and anybody may add to it. This is the
/// document an attacker makes out of a passport he has merely READ: he appends
/// a certificate of his own, the signature still verifies, the data group hash
/// still matches, and the real signer still chains to a real authority. The
/// only thing he has changed is what a reader that takes the signer from the
/// bag will report.
///
/// @note "First" is a fact about the ENCODING, not an insertion order a caller
///       can pick: a DER SET OF is sorted by its members' encodings, and
///       OpenSSL sorts it on the way out whatever order things were added in.
///       The impostor is therefore given a common name far shorter than the
///       document signer's -- 25 characters over the two names it carries,
///       against at most a couple of bytes of ECDSA signature-length variance
///       -- so that its encoding is the smaller one. The function then
///       RE-READS the bag it produced and throws unless the impostor really is
///       at index 0: a fixture whose names drifted in length would otherwise
///       quietly stop staging the attack, and the test over it would go green
///       on the very code it exists to fail.
/// @note Like makeSod(), the document signer is ISSUED by
///       `ml.cscaDer[anchorIndex]`, so this works only on a list this process
///       minted; see the note there. The impostor needs no such thing -- it is
///       self-signed and related to nothing.
[[nodiscard]] SyntheticSodWithImpostor makeSodWithImpostorPrependedToCertificateBag(const SyntheticMasterList& ml,
                                                                                    int anchorIndex);

} // namespace LibreSCRS::Test

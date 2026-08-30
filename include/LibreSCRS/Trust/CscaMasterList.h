// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Reading an ICAO CSCA master list into trust anchors, and deciding
///        whether to believe the list.
///
/// Three functions and no state. They are what a host needs in order to import
/// an ICAO 9303-12 country-signing master list: verify the object, learn who
/// signed it, and -- when the publisher's key has changed -- decide whether the
/// new signer descends from an authority the previous list already carried.
///
/// @par Why this is published rather than left to the caller
/// All three are thin views onto machinery LibreMiddleware already runs for
/// passive authentication. A host that grew its own would grow an OpenSSL
/// dependency, a CMS verifier and a path builder alongside it, and would have
/// to rediscover the two verification defaults and the one path-building flag
/// that decide whether genuine documents are accepted. Those decisions are
/// documented on each function below because a caller cannot check them from
/// outside.
///
/// @par This header declares no OpenSSL type, and must not
/// Anchors, certificates and fingerprints all cross this boundary as bytes. The
/// internal header behind it is OpenSSL-free because the eMRTD plugin includes
/// it across a `dlopen` boundary; the public one carries the stronger form of
/// the same obligation, since a consumer that included a trust header would
/// otherwise inherit LibreMiddleware's bundled OpenSSL declarations into its own
/// translation units.
///
/// @par Thread-safety
/// All three are pure functions per API-POLICY §8: they read their arguments,
/// touch no shared state, and remember nothing between calls. Concurrent calls
/// are race-free.
///
/// @since 4.3

#include <LibreSCRS/Export.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <vector>

namespace LibreSCRS::Trust {

/// @brief The number of bytes in a signer fingerprint: SHA-256, so 32.
/// @since 4.3
inline constexpr std::size_t kSpkiSha256Size = 32;

/// @brief Why a CSCA master list could not be turned into a set of anchors.
///
/// @note Every value is a refusal. There is no "unknown" case: a call either
///       yields anchors or names the first check that failed.
/// @since 4.3
enum class MasterListError : std::uint8_t {
    /// The bytes are not a master list at all. Also the answer for empty input,
    /// for bytes that are not exactly one CMS ContentInfo, for a ContentInfo
    /// that is not a SignedData, and for a signed `contentType` attribute that
    /// disagrees with the `eContentType` field beside it.
    NotAMasterList = 0,
    /// A master list that verified and carries no certificate.
    Empty = 1,
    /// The object is a master list, but its content cannot be read: detached,
    /// so the list is not in it at all; or not decodable as a `CscaMasterList`;
    /// or holding an element that is not a certificate.
    Malformed = 2,
    /// The signature over the list does not verify -- for any signer, not only
    /// the first. Also the answer when there is no signature to check: a
    /// detached object, one carrying no SignerInfo, and one whose signer
    /// certificate it does not carry.
    BadSignature = 3,
    /// The list verifies, but not against the signer the caller pinned.
    SignerMismatch = 4,
};

/// @brief A master list whose signature held, and what that established about
///        who signed it.
/// @since 4.3
struct VerifiedMasterList
{
    /// @brief The anchors the list carries, each as an encoded certificate, in
    ///        the list's own encoded order.
    ///
    /// Includes CSCA **link certificates**, which ICAO master lists carry beside
    /// the self-signed roots and which are not self-signed themselves. They are
    /// ordinary anchors and must be kept: dropping them is how a country that
    /// has rotated its country signing certificate starts being refused.
    ///
    /// Each element parsed as a certificate but is not guaranteed to be DER:
    /// the bytes are the slice the list carried, handed on as found rather than
    /// canonicalised, because at parse time nothing has verified the input and
    /// re-encoding would replace the bytes a later check is about. A consumer
    /// that hashes, fingerprints or de-duplicates an anchor must re-encode it
    /// first -- or use spkiSha256FromCertificateDer(), which re-encodes for
    /// exactly this reason.
    std::vector<std::vector<std::uint8_t>> anchors;

    /// @brief SHA-256 over the DER of a signer's SubjectPublicKeyInfo.
    ///
    /// **Whose.** With a pin, the signer that MATCHED it. Without one, the first
    /// SignerInfo in the object's own encoded order -- which is what a caller
    /// shows a person in order to be told whether to pin it.
    ///
    /// It is deliberately not "the first signer" in both cases. SignerInfos are
    /// a DER `SET OF`, so which one lands first is decided by the encoding, and
    /// anybody may append a signer of their own to a published list. On a pinned
    /// call the first signer may therefore be a key nothing was checked about,
    /// and handing that back is how a caller comes to store it.
    std::array<std::uint8_t, kSpkiSha256Size> signerSpkiSha256{};

    /// @brief Whether the fingerprint was COMPARED with one the caller supplied,
    ///        as opposed to merely reported.
    ///
    /// False means the call established that somebody signed this list and
    /// nothing at all about who: no chain is built, so an attacker who signs a
    /// list of their own anchors with a key of their own gets exactly the same
    /// `false` the real publisher gets. It is carried here rather than folded
    /// into the return value so a caller who forgot to pass a pin cannot mistake
    /// it for one -- without this field both look like success.
    bool identityChecked = false;

    /// @brief The certificate that SIGNED the list, as it was encoded. Always
    ///        filled when a value is returned.
    ///
    /// **Whose**, and the answer is the one signerSpkiSha256 gives: with a pin,
    /// the signer that MATCHED it; without one, the first SignerInfo in the
    /// object's own encoded order. The two fields describe ONE certificate, so
    /// spkiSha256FromCertificateDer() over this yields signerSpkiSha256 back.
    ///
    /// Taken from the signers a successful verification resolved, never from
    /// the object's certificate bag: the bag is unauthenticated and anyone may
    /// drop anyone's certificate into it.
    ///
    /// It is here for the caller following a publisher through a key rotation.
    /// signerChainsToAnyAnchor() asks whether the NEW signer chains to an anchor
    /// the PREVIOUS list carried, and it takes a bare certificate -- which
    /// without this field a host would have to be given out of band, or dig out
    /// of the CMS itself, although it is already inside the bytes it just
    /// handed to this function.
    std::vector<std::uint8_t> signerCertDer;

    /// @brief When the list was signed, out of the CMS `signingTime` SIGNED
    ///        attribute of that same signer, as seconds since the Unix epoch.
    ///
    /// **Signed, which is what makes it worth reading.** `signingTime` is part
    /// of `signedAttrs`, so the signature covers it and the publisher is
    /// committed to it once the signature has held. The same attribute among
    /// the UNSIGNED ones is attacker-controlled, and a date taken from there
    /// would be worse than none: it would look like protection while being
    /// whatever the last hand to touch the file chose.
    ///
    /// **EMPTY when the list carries no such attribute.** That is a property of
    /// the input rather than a shortcoming of this function: nothing is
    /// invented, and a list is not refused for lacking a date -- one without a
    /// `signingTime` is a perfectly valid CMS object. The consequence is real
    /// and it belongs to the caller: **refusing a replayed list is impossible
    /// without a date to compare it against**, so an undated list leaves a
    /// publisher free to hand back a strictly OLDER set of anchors -- one that
    /// restores an anchor since withdrawn, or that drops a country's current
    /// one. What to do about that is the caller's decision; this function only
    /// reports what the object says.
    ///
    /// Empty as well when the attribute is present but no single time can be
    /// read out of it: more than one `signingTime`, more than one value inside
    /// one, or a value that is neither a UTCTime nor a GeneralizedTime. None of
    /// those is "some time", and none may be passed on as one.
    std::optional<std::int64_t> signingTimeEpochSeconds;
};

/// @brief Verifies an ICAO CSCA master list and says whether it was signed by
///        the signer the caller named.
///
/// In this order:
/// 1. @p der is decoded as one CMS ContentInfo -- `NotAMasterList` if it does
///    not decode.
/// 2. Every SignerInfo is verified over the content the object carries --
///    `BadSignature` if any does not hold.
/// 3. If @p expectedSpkiSha256 is given, SOME signer's SubjectPublicKeyInfo
///    fingerprint must equal it -- `SignerMismatch` otherwise. "Signer" means a
///    certificate that verified a SignerInfo of this object, never one the
///    object merely carries: a CMS certificate bag is unauthenticated, so a
///    stranger may plant the trusted publisher's certificate beside a list of
///    their own without touching any signature. The claim established is "the
///    pinned key signed this", not "the pinned certificate travels with this".
/// 4. The anchors are read, and a failure there is returned unchanged --
///    `NotAMasterList`, `Malformed` and `Empty` all still reach the caller from
///    a list whose signature held.
///
/// **Step 4 is a barrier, not a formality.** Only the signed `contentType`
/// attribute is under the signature; the `eContentType` field beside it is not.
/// An object genuinely signed by the very signer a caller pinned, over genuine
/// master-list bytes, under some other content type and relabelled afterwards,
/// passes steps 2 and 3 outright. Comparing those two places is the only thing
/// that stops it.
///
/// **Steps 2 and 3 are in that order deliberately.** Comparing the fingerprint
/// first would answer "does this fingerprint match" for a list whose signature
/// does not hold -- a question with no security content, since anybody may copy
/// a certificate into an object they did not sign. So a list that both fails its
/// signature and names an unexpected signer is `BadSignature`.
///
/// **No chain is built.** The signer's certificate is not chained to any store,
/// and is not checked for expiry, key usage, extended key usage, basic
/// constraints or revocation. Identity rests entirely on the fingerprint, which
/// the caller has to have obtained some other way -- out of band, or by showing
/// VerifiedMasterList::signerSpkiSha256 to a person who can recognise it. This
/// function remembers nothing between calls; pinning across imports is the
/// caller's to store.
///
/// That is not an omission. A master list is what supplies trust anchors, so at
/// first import there is nothing to chain it to; and once identity rests on a
/// pinned key, the certificate around it is a container for the key rather than
/// a credential. Two of those checks would refuse perfectly good lists. Expiry,
/// because a master list outlives by years the key that signed it. Extended key
/// usage, because the CMS default demands `emailProtection`, and a signer
/// carrying no extended key usage at all passes that -- so it is precisely the
/// ICAO-profiled certificate, the real one, that such a check turns away.
///
/// A caller following a publisher that has rotated its key uses
/// signerChainsToAnyAnchor() for the decision this function does not make.
///
/// Rejections are silent: the returned error is the whole diagnosis, and
/// nothing is logged. `std::bad_alloc` can still escape.
///
/// @param der the encoding of a signed master list, as published.
/// @param expectedSpkiSha256 the fingerprint of the signer the caller will
///        accept, from spkiSha256FromCertificateDer() or from an earlier
///        VerifiedMasterList::signerSpkiSha256; or `nullptr` to accept any
///        signer and only report the one seen. `nullptr` is the only way to ask
///        for that, and it is recorded in
///        VerifiedMasterList::identityChecked. Not retained beyond the call.
/// @return the anchors together with what was established about the signer, or
///         the first check that failed.
/// @since 4.3
[[nodiscard]] LIBRESCRS_PUBLIC_API std::expected<VerifiedMasterList, MasterListError>
parseAndVerifyMasterList(const std::vector<std::uint8_t>& der,
                         const std::array<std::uint8_t, kSpkiSha256Size>* expectedSpkiSha256);

/// @brief Computes the pin parseAndVerifyMasterList() compares against, from
///        the publisher's certificate.
///
/// **This is the only supported way to produce that value**, and there are two
/// obvious ways to get it wrong.
///
/// Not the hash of the certificate. A publisher renews its certificate while
/// keeping its key, and every renewal would then change the pin -- so a caller
/// that hashed the certificate would have to re-pin at each one, out of band, or
/// start refusing genuine lists. The key is what the claim is about; the
/// certificate is a container for it.
///
/// Not the SubjectPublicKeyInfo slice as the certificate carries it. That is a
/// byte range chosen by whoever encoded the certificate, so two encodings of one
/// key would fingerprint differently. This hashes the SubjectPublicKeyInfo
/// re-encoded canonically, so the same key gives the same 32 bytes whatever it
/// arrived in.
///
/// @param certDer one certificate, as encoded -- the publisher's, obtained out
///        of band. Exactly one certificate with nothing trailing it; anything
///        else is `std::nullopt`. BER is accepted, since the answer does not
///        depend on the encoding.
/// @return the fingerprint to hand parseAndVerifyMasterList(), or nothing if
///         @p certDer is not a certificate.
/// @since 4.3
[[nodiscard]] LIBRESCRS_PUBLIC_API std::optional<std::array<std::uint8_t, kSpkiSha256Size>>
spkiSha256FromCertificateDer(const std::vector<std::uint8_t>& certDer);

/// @brief Whether one certificate chains to any of a set of trust anchors.
///
/// The rule a host needs when a master list arrives signed by a key it has not
/// pinned: **accept the new publisher if it chains to an anchor the list already
/// trusted carried.** That is how a country's rotation is followed without a
/// person re-pinning a fingerprint out of band, and it is the decision
/// parseAndVerifyMasterList() deliberately does not make.
///
/// **Any anchor may terminate the chain, self-signed or not.** A certificate is
/// an anchor because the caller configured it, and nothing here asks it to have
/// signed itself; its own signature is never examined. That is load-bearing
/// rather than tidy. A CSCA **link certificate** carries the same subject and
/// the same public key as a country's new self-signed root but is signed by the
/// OUTGOING key, so it is not self-signed, and ICAO master lists carry them
/// beside the self-signed ones. A path builder that insisted on ending at a
/// self-signed certificate would answer `false` about a signer that authority
/// genuinely issued, whenever the link certificate is the only anchor held for
/// it -- or merely the one reached first among anchors sharing its subject,
/// which is not something a caller can control.
///
/// **This answer contains no statement about time**, at either end of the chain:
/// an expired signer chains, and so does an expired -- or not yet valid --
/// anchor. A signer's key lives months while what it signed lives years, so a
/// lapsed signer is the ordinary case rather than the suspicious one. A caller
/// that needs a date checked must check it and must not read one into this.
///
/// What is still enforced, so that this is not read as "no checks": every
/// signature in the chain, the basic constraints that keep a leaf from acting as
/// a CA in the middle of one, and the key usage that lets an issuer sign
/// certificates. Revocation is not consulted.
///
/// One question and two answers: "no anchors were configured", "none of them
/// decoded" and "it does not chain" are all `false`. A caller that has to tell
/// those apart knows its own configuration and can say so without being told.
///
/// @param signerCertDer the certificate to judge, as encoded. Exactly one
///        certificate; BER is accepted. Empty bytes, or anything that is not a
///        certificate, is `false`.
/// @param anchorsDer the anchors to judge against, each as an encoded
///        certificate -- typically VerifiedMasterList::anchors from the list
///        already trusted. An element that does not decode is passed over
///        rather than being fatal, so one unreadable anchor among many costs
///        only that anchor.
/// @return whether a path was built from @p signerCertDer to some anchor. A
///         certificate that IS one of the anchors chains to itself.
/// @since 4.3
[[nodiscard]] LIBRESCRS_PUBLIC_API bool
signerChainsToAnyAnchor(const std::vector<std::uint8_t>& signerCertDer,
                        const std::vector<std::vector<std::uint8_t>>& anchorsDer);

} // namespace LibreSCRS::Trust

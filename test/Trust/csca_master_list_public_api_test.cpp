// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief The CSCA master-list facade seen from OUTSIDE LibreMiddleware.
///
/// This file is deliberately built the way a separate program is built: no
/// `LIBRESCRS_INTERNAL_BUILD`, no `lib/emrtd-crypto/src` on the include path,
/// and nothing included from `<LibreSCRS/...>` beyond the one public header
/// under test. That is the whole subject of these tests. The same assertions
/// written against `csca_master_list.h` would pass on a build where the public
/// header does not exist and the symbols never leave the archive -- so they
/// would prove nothing about what a separate library can reach, which is the
/// only question this file is asked.
///
/// The other half of the same question is answered by the linker rather than
/// here: `LibreSCRS_Trust` is compiled `-fvisibility=hidden` behind a
/// version-script allowlist, so a declaration that compiles is still not a
/// symbol that can be called. `nm -D` over the INSTALLED
/// `libLibreSCRS_Trust.so` is what separates the two, and this executable
/// linking at all is the cheaper half of that evidence.

// The tripwire, not a formality: this target must never acquire the internal
// define, because with it the internal header stops being #error-guarded and
// every test below could quietly be rewritten against it.
#ifdef LIBRESCRS_INTERNAL_BUILD
#error "This test consumes the PUBLIC facade. Building it as an LM-internal TU defeats its purpose."
#endif

#include <LibreSCRS/Trust/CscaMasterList.h>

// Header hygiene, asserted where it can be seen rather than in a build script:
// the public header must pull in no OpenSSL declaration. The internal header it
// fronts is OpenSSL-free because the eMRTD plugin includes it across a dlopen
// boundary; the public one has the stronger version of that obligation, since
// every consumer of the SDK would otherwise inherit LibreMiddleware's bundled
// OpenSSL headers by including a trust header.
//
// A macro test only, and knowingly so: it catches the ordinary regression --
// somebody adds `#include <openssl/x509.h>` to the public header -- because
// every OpenSSL public header reaches `openssl/opensslv.h`. The exhaustive
// form of this check is a preprocessor dependency scan, which lives outside a
// compiler.
#if defined(OPENSSL_VERSION_NUMBER) || defined(OPENSSL_VERSION_MAJOR) || defined(OPENSSL_VERSION_TEXT)
#error "<LibreSCRS/Trust/CscaMasterList.h> dragged OpenSSL into a consumer translation unit."
#endif

#include "synthetic_masterlist.h"

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace {

using LibreSCRS::Trust::MasterListError;

/// The public fingerprint type beside the fixture's, which is a vector.
std::vector<std::uint8_t> asBytes(const std::array<std::uint8_t, 32>& fingerprint)
{
    return {fingerprint.begin(), fingerprint.end()};
}

std::array<std::uint8_t, 32> asFingerprint(const std::vector<std::uint8_t>& bytes)
{
    std::array<std::uint8_t, 32> out{};
    EXPECT_EQ(bytes.size(), out.size()) << "a fingerprint is 32 bytes or it is not one";
    for (std::size_t i = 0; i < out.size() && i < bytes.size(); ++i) {
        out[i] = bytes[i];
    }
    return out;
}

/// 2009-02-13T23:31:30Z, as seconds since the Unix epoch. A literal seventeen
/// years past, so that a facade reporting the clock rather than the attribute
/// the list carries cannot pass by being approximately right.
constexpr std::int64_t kFixedSigningTimeEpoch = 1234567890;

/// Bytes that are certainly not DER anything.
std::vector<std::uint8_t> rubbish(std::uint8_t fill)
{
    return std::vector<std::uint8_t>(64, fill);
}

// ---------------------------------------------------------------------------
// parseAndVerifyMasterList
// ---------------------------------------------------------------------------

TEST(CscaMasterListPublicApi, ReturnsTheAnchorsAndTheSignerWithNoPin)
{
    // Pins the unpinned branch of CscaMasterList.cpp: a null
    // `expectedSpkiSha256` becomes the empty vector the internal call reads as
    // "do not compare", and `identityChecked` comes back false so a caller
    // cannot mistake "somebody signed this" for "the publisher signed this".
    const auto ml = LibreSCRS::Test::makeMasterList(3);

    const auto verified = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, nullptr);

    ASSERT_TRUE(verified.has_value());
    EXPECT_EQ(verified->anchors, ml.cscaDer) << "the anchors the list carries, in the list's own order";
    EXPECT_EQ(asBytes(verified->signerSpkiSha256), ml.signerSpkiSha256);
    EXPECT_FALSE(verified->identityChecked) << "no pin was supplied, so nothing about the signer was established";
}

TEST(CscaMasterListPublicApi, APinThatMatchesIsRecordedAsChecked)
{
    // The import flow this facade exists for, both halves of it: the first
    // import reports a fingerprint for a person to recognise, and every import
    // after it hands that fingerprint back as the pin.
    const auto ml = LibreSCRS::Test::makeMasterList(2);

    const auto reported = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, nullptr);
    ASSERT_TRUE(reported.has_value());
    const std::array<std::uint8_t, 32> pin = reported->signerSpkiSha256;

    const auto pinned = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, &pin);

    ASSERT_TRUE(pinned.has_value());
    EXPECT_TRUE(pinned->identityChecked) << "identityChecked is what separates a compared pin from a reported one";
    EXPECT_EQ(pinned->signerSpkiSha256, pin);
    EXPECT_EQ(pinned->anchors, ml.cscaDer);
}

TEST(CscaMasterListPublicApi, ThePinIsComputedFromThePublishersCertificate)
{
    // The binding between the two functions, and the reason the second one is
    // published at all: the value spkiSha256FromCertificateDer() produces from
    // the publisher's certificate is the value parseAndVerifyMasterList()
    // compares against. A consumer that computed the pin any other way -- over
    // the certificate rather than over the key, or over the SubjectPublicKeyInfo
    // slice as carried rather than re-encoded -- would get a mismatch here.
    const auto ml = LibreSCRS::Test::makeMasterList(1);
    const auto signerCert = LibreSCRS::Test::masterListSignerCertificateDer(ml);

    const auto pin = LibreSCRS::Trust::spkiSha256FromCertificateDer(signerCert);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(asBytes(*pin), ml.signerSpkiSha256);

    const auto pinned = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, &*pin);
    ASSERT_TRUE(pinned.has_value()) << "the pin computed from the publisher's certificate has to be the one accepted";
    EXPECT_TRUE(pinned->identityChecked);
}

TEST(CscaMasterListPublicApi, AnotherSignersFingerprintIsSignerMismatch)
{
    // Pins MasterListError::SignerMismatch through the enum mirror. Same
    // anchors byte for byte, different signing key, so a facade that reported
    // the fingerprint of the first anchor instead of the signer's would pass
    // the two tests above and fail here.
    const auto mine = LibreSCRS::Test::makeMasterList(2);
    const auto theirs = LibreSCRS::Test::makeMasterListWithOtherSigner(mine);
    ASSERT_EQ(mine.cscaDer, theirs.cscaDer);
    ASSERT_NE(mine.signerSpkiSha256, theirs.signerSpkiSha256);

    const std::array<std::uint8_t, 32> pin = asFingerprint(mine.signerSpkiSha256);

    const auto out = LibreSCRS::Trust::parseAndVerifyMasterList(theirs.der, &pin);

    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), MasterListError::SignerMismatch);
}

TEST(CscaMasterListPublicApi, ATamperedListIsBadSignature)
{
    // Pins MasterListError::BadSignature. The flipped byte is inside the signed
    // content, so the list still parses as a master list and only the signature
    // brings it down.
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto tampered = LibreSCRS::Test::makeTamperedMasterList(ml);
    ASSERT_NE(ml.der, tampered.der) << "the fixture has to have changed something";

    const auto out = LibreSCRS::Trust::parseAndVerifyMasterList(tampered.der, nullptr);

    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), MasterListError::BadSignature);
}

TEST(CscaMasterListPublicApi, ASignedObjectOfAnotherContentTypeIsNotAMasterList)
{
    // Pins MasterListError::NotAMasterList on a properly signed object, not on
    // garbage: the content really is a well-formed CscaMasterList and only the
    // content type gives it away, so a facade fronting a parser that never
    // looked at the content type would pass.
    const auto out = LibreSCRS::Trust::parseAndVerifyMasterList(LibreSCRS::Test::makeSignedNonMasterList(), nullptr);

    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), MasterListError::NotAMasterList);
}

TEST(CscaMasterListPublicApi, RubbishIsNotAMasterList)
{
    const auto out = LibreSCRS::Trust::parseAndVerifyMasterList(rubbish(0x41), nullptr);

    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), MasterListError::NotAMasterList);
}

TEST(CscaMasterListPublicApi, ASignedListCarryingNoAnchorIsEmpty)
{
    // Pins MasterListError::Empty, which is NOT a rejection of the signature:
    // the list verifies and carries nothing.
    //
    // Malformed is the one value of the five with no case here. It needs a
    // signed object whose content is not decodable as a CscaMasterList, which
    // no fixture produces and which the internal suite covers at length; the
    // static_assert mirror gate in CscaMasterList.cpp is what pins its VALUE,
    // and that gate does not weaken with a missing runtime case.
    const auto ml = LibreSCRS::Test::makeMasterList(0);

    const auto out = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, nullptr);

    ASSERT_FALSE(out.has_value());
    EXPECT_EQ(out.error(), MasterListError::Empty);
}

TEST(CscaMasterListPublicApi, TheSignerCertificateComesBackWithTheAnchors)
{
    // The publisher's certificate is inside the bytes the caller just handed
    // over, and without this field a host would have to be given it a second
    // time, out of band, in order to ask signerChainsToAnyAnchor() the rotation
    // question. The exact bytes, because what comes back is fed to a path
    // builder.
    const auto ml = LibreSCRS::Test::makeMasterList(2);
    const auto signerCert = LibreSCRS::Test::masterListSignerCertificateDer(ml);

    const auto verified = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, nullptr);

    ASSERT_TRUE(verified.has_value());
    EXPECT_EQ(verified->signerCertDer, signerCert) << "byte for byte the certificate that signed the list";
    // Through the published pin function, which is how a caller would tie the
    // two fields together itself: one signer, one certificate, one fingerprint.
    const auto pin = LibreSCRS::Trust::spkiSha256FromCertificateDer(verified->signerCertDer);
    ASSERT_TRUE(pin.has_value());
    EXPECT_EQ(*pin, verified->signerSpkiSha256);
}

TEST(CscaMasterListPublicApi, TheSigningTimeIsTheInstantTheListWasSignedAt)
{
    // The date a caller needs in order to refuse a replayed older list. It
    // comes out of the SIGNED attributes, so the signature covers it; the same
    // attribute among the unsigned ones would be whatever the last hand to
    // touch the file chose.
    const auto ml = LibreSCRS::Test::makeMasterListSignedAt(2, kFixedSigningTimeEpoch);

    const auto verified = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, nullptr);

    ASSERT_TRUE(verified.has_value());
    ASSERT_TRUE(verified->signingTimeEpochSeconds.has_value());
    EXPECT_EQ(*verified->signingTimeEpochSeconds, kFixedSigningTimeEpoch);
}

TEST(CscaMasterListPublicApi, AListWithoutASigningTimeIsAcceptedAndCarriesNoInstant)
{
    // Both cases are needed or neither means anything: with only the test
    // above, an empty answer cannot be told from a facade that cannot read the
    // attribute at all. The list is ACCEPTED -- carrying no date is not a
    // fault, and what to do about one is the caller's decision, which it takes
    // with this field empty in front of it.
    const auto ml = LibreSCRS::Test::makeMasterListWithoutSigningTime(2);

    const auto verified = LibreSCRS::Trust::parseAndVerifyMasterList(ml.der, nullptr);

    ASSERT_TRUE(verified.has_value()) << "a list is not refused for carrying no date";
    EXPECT_FALSE(verified->signingTimeEpochSeconds.has_value());
    EXPECT_EQ(verified->anchors, ml.cscaDer) << "and everything else about it still comes back";
}

// ---------------------------------------------------------------------------
// spkiSha256FromCertificateDer
// ---------------------------------------------------------------------------

TEST(CscaMasterListPublicApi, TheFingerprintIsOverTheKeyAndNotOverTheCertificate)
{
    // The documented reason this function exists rather than a certificate
    // hash, measured on the one input in the fixture that can tell the two
    // apart: a CSCA link certificate carries the incoming CSCA's key under a
    // different encoding, a different issuer and a different signature. One key,
    // two certificates, and the pin has to be the same -- otherwise a publisher
    // that renewed its certificate while keeping its key would have to be
    // re-pinned out of band at every renewal.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    const auto& incoming = rotation.list.cscaDer[static_cast<std::size_t>(rotation.incomingIndex)];
    const auto& link = rotation.list.cscaDer[static_cast<std::size_t>(rotation.linkIndex)];
    const auto& outgoing = rotation.list.cscaDer[static_cast<std::size_t>(rotation.outgoingIndex)];
    ASSERT_NE(incoming, link) << "two certificates, or this test compares a thing with itself";

    const auto incomingPin = LibreSCRS::Trust::spkiSha256FromCertificateDer(incoming);
    const auto linkPin = LibreSCRS::Trust::spkiSha256FromCertificateDer(link);
    const auto outgoingPin = LibreSCRS::Trust::spkiSha256FromCertificateDer(outgoing);

    ASSERT_TRUE(incomingPin.has_value());
    ASSERT_TRUE(linkPin.has_value());
    ASSERT_TRUE(outgoingPin.has_value());
    EXPECT_EQ(*incomingPin, *linkPin) << "one key under two certificates is one pin";
    EXPECT_NE(*incomingPin, *outgoingPin) << "and two keys are two pins";
}

TEST(CscaMasterListPublicApi, BytesThatAreNotACertificateHaveNoFingerprint)
{
    EXPECT_FALSE(LibreSCRS::Trust::spkiSha256FromCertificateDer(rubbish(0x5a)).has_value());
    EXPECT_FALSE(LibreSCRS::Trust::spkiSha256FromCertificateDer({}).has_value());
}

// ---------------------------------------------------------------------------
// signerChainsToAnyAnchor
// ---------------------------------------------------------------------------

TEST(CscaMasterListPublicApi, ASignerChainsToTheAnchorThatIssuedIt)
{
    const auto ml = LibreSCRS::Test::makeMasterList(3);
    const auto signer = LibreSCRS::Test::makeCertificateIssuedByAnchor(ml, 1);

    EXPECT_TRUE(LibreSCRS::Trust::signerChainsToAnyAnchor(signer, ml.cscaDer));
}

TEST(CscaMasterListPublicApi, ASignerChainsToNothingInAStrangersAnchorSet)
{
    const auto ours = LibreSCRS::Test::makeMasterList(2);
    const auto theirs = LibreSCRS::Test::makeMasterList(2);
    const auto signer = LibreSCRS::Test::makeCertificateIssuedByAnchor(ours, 0);

    EXPECT_FALSE(LibreSCRS::Trust::signerChainsToAnyAnchor(signer, theirs.cscaDer));
}

TEST(CscaMasterListPublicApi, ALinkCertificateAloneTerminatesTheChain)
{
    // The rotation rule this function was published for, over the facade. A
    // link certificate is not self-signed, so without
    // X509_V_FLAG_PARTIAL_CHAIN in storeOfAnchors() the path builder goes
    // looking for the link's own issuer, does not find it, and answers false --
    // to a signer a country that had rotated genuinely issued.
    const auto rotation = LibreSCRS::Test::makeMasterListWithLinkCertificate();
    const auto& link = rotation.list.cscaDer[static_cast<std::size_t>(rotation.linkIndex)];
    const auto signer = LibreSCRS::Test::makeCertificateIssuedByAnchor(rotation.list, rotation.incomingIndex);

    EXPECT_TRUE(LibreSCRS::Trust::signerChainsToAnyAnchor(signer, {link}))
        << "a configured anchor may end a chain, whether or not it signed itself";
}

} // namespace

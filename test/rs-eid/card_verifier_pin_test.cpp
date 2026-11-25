// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// End-to-end regression guard for the MUP document-signer pin: drives the PUBLIC
// CardVerifier::verifyCard path with synthetic PKCS#7 Security Objects
// signed by different CA branches, and asserts the trust decision. This is the
// exploit-and-fix pair — a citizen-branch signer chains validly to the same root but
// must NOT be attributed to MUP. Synthetic certs use minimal-DER serials so they load
// on modern OpenSSL (unlike the bundled legacy MUP CAs), which is exactly why this
// exercises the pin logic independently of the separate legacy-cert load issue.

#include <gtest/gtest.h>

#include "card_verifier.h"
#include "eidtypes.h"

#include "rs-eid/synthetic_pki.h"

#include <rs_document_profile.h>

#include <openssl/rand.h>

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <utility>
#include <string>
#include <vector>

namespace {

namespace Core = LibreSCRS::RsEId::Core;
using namespace LibreSCRS::RsEId::Test;
using eidcard::VerificationResult;

const Core::DocumentProfile& profileOf(std::string_view code)
{
    for (const auto& p : Core::documentProfiles()) {
        if (p.code == code)
            return p;
    }
    throw std::logic_error("no such profile");
}

// A SOD-shaped object over arbitrary content: verifyCard checks the signer,
// not the content.
std::vector<std::uint8_t> makeSod(X509* leaf, EVP_PKEY* leafKey)
{
    const std::string content = "card-security-object";
    return signContent(leaf, leafKey, {content.begin(), content.end()});
}

VerificationResult runVerifyCard(const std::vector<KeyCert*>& storeCerts, const std::vector<std::uint8_t>& sod)
{
    eidcard::CardVerifier v("");
    for (auto* kc : storeCerts)
        v.addCertificate(derOf(kc->cert.get()));
    Core::RawFiles files;
    files[0x0F1C] = signedObjectFile(0x0F1C, sod);
    return v.verifyCard(profileOf("ID"), files);
}

VerificationResult runVerifyFixedData(const std::vector<KeyCert*>& storeCerts, const Core::RawFiles& files,
                                      std::string_view code = "ID")
{
    eidcard::CardVerifier v("");
    for (auto* kc : storeCerts)
        v.addCertificate(derOf(kc->cert.get()));
    return v.verifyFixedData(profileOf(code), files);
}

} // namespace

// A SOD signed by a document-signer under a "Resursi" CA, chaining to a trusted root,
// is Valid.
TEST(CardVerifierPin, AcceptsResursiSignedSod)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    auto leaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 3);
    auto sod = makeSod(leaf.cert.get(), leaf.key.get());

    EXPECT_EQ(runVerifyCard({&root, &resursi}, sod), VerificationResult::Valid);
}

// THE exploit case: a SOD signed by a certificate under the CITIZEN ("Gradjani") CA
// chains validly to the SAME trusted root, but is NOT a MUP document-signer, so it must
// NOT be Valid. The pin reports Unknown (indeterminate — cannot attribute to MUP), not
// a false "tampered" Invalid.
TEST(CardVerifierPin, RejectsCitizenSignedSodAsUnknown)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto gradjani = issue("MUPCA Gradjani", root.cert.get(), root.key.get(), true, 2);
    auto citizen = issue("Citizen Signing Cert", gradjani.cert.get(), gradjani.key.get(), false, 3);
    auto sod = makeSod(citizen.cert.get(), citizen.key.get());

    // Both the root and the citizen CA are trusted — the chain is cryptographically
    // valid — yet the pin denies the "valid" badge.
    EXPECT_EQ(runVerifyCard({&root, &gradjani}, sod), VerificationResult::Unknown);
}

// A SOD whose signer does not chain to any trusted anchor is Invalid (broken chain).
TEST(CardVerifierPin, RejectsUntrustedSignerAsInvalid)
{
    auto foreignRoot = issue("Some Qualified CA", nullptr, nullptr, true, 1);
    auto foreignResursi = issue("MUPCA Resursi", foreignRoot.cert.get(), foreignRoot.key.get(), true, 2);
    auto leaf = issue("StrongSecurityFormat", foreignResursi.cert.get(), foreignResursi.key.get(), false, 3);
    auto sod = makeSod(leaf.cert.get(), leaf.key.get());

    // Only the intermediate is added, not the root → chain cannot terminate at a trusted
    // anchor. Even though the issuer CN says "Resursi", the chain fails first.
    EXPECT_EQ(runVerifyCard({&foreignResursi}, sod), VerificationResult::Invalid);
}

// The card-DATA attestation path: a resursi-signed SOD whose nine slots match the
// files passes both the pin and the binding → Valid.
TEST(CardVerifierPin, FixedDataResursiSignedWithMatchingHashesIsValid)
{
    ResursiChain chain;
    const auto files = withSignedObjects(profileOf("ID"), citizenFiles(), chain);

    EXPECT_EQ(runVerifyFixedData({&chain.root, &chain.resursi}, files), VerificationResult::Valid);
}

// THE data-path exploit: a citizen-signed SOD whose digests DO match the files. The
// pin rejects it as Unknown BEFORE the digests are looked at — the signer's domain
// comes first.
TEST(CardVerifierPin, FixedDataCitizenSignedWithMatchingHashesIsUnknown)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto gradjani = issue("MUPCA Gradjani", root.cert.get(), root.key.get(), true, 2);
    auto citizen = issue("Citizen Signing Cert", gradjani.cert.get(), gradjani.key.get(), false, 3);

    auto files = citizenFiles();
    const auto& profile = profileOf("ID");
    const auto& sod = profile.sods[0];
    files[sod.fid] =
        signedObjectFile(sod.fid, signSlots(citizen.cert.get(), citizen.key.get(), slotDigests(profile, sod, files)));

    EXPECT_EQ(runVerifyFixedData({&root, &gradjani}, files), VerificationResult::Unknown);
}

// A SOD carrying two signers is rejected (exactly one signer required) — an attacker
// cannot append a second, legitimate-looking signer to smuggle a rogue one, or vice-versa.
TEST(CardVerifierPin, MultiSignerSodIsInvalid)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    auto gradjani = issue("MUPCA Gradjani", root.cert.get(), root.key.get(), true, 3);
    auto resLeaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 4);
    auto citLeaf = issue("Citizen Signing Cert", gradjani.cert.get(), gradjani.key.get(), false, 5);

    auto sod = signWithTwoSigners(resLeaf.cert.get(), resLeaf.key.get(), citLeaf.cert.get(), citLeaf.key.get());

    EXPECT_EQ(runVerifyCard({&root, &resursi, &gradjani}, sod), VerificationResult::Invalid);
}

// A SOD whose bytes were altered after signing fails PKCS7 verification → Invalid, even
// with a genuine resources signer trusted in the store. Guards that the CMS signature is
// actually checked (PKCS7_NOVERIFY suppresses only chain building, not signature verify).
TEST(CardVerifierPin, CorruptedSodIsInvalid)
{
    auto root = issue("Test MUP Root", nullptr, nullptr, true, 1);
    auto resursi = issue("MUPCA Resursi", root.cert.get(), root.key.get(), true, 2);
    auto leaf = issue("StrongSecurityFormat", resursi.cert.get(), resursi.key.get(), false, 3);
    auto sod = makeSod(leaf.cert.get(), leaf.key.get());
    ASSERT_GT(sod.size(), 40u);
    sod[sod.size() - 20] ^= 0xFF; // flip a byte in the trailing signature region

    EXPECT_EQ(runVerifyCard({&root, &resursi}, sod), VerificationResult::Invalid);
}

// --- the nine-slot fixed-data object of ID/IF/RP ---

namespace {

// The citizen card with the signed objects the chain signs over it, and the
// fixed object's slots in the order the profile lists them.
struct NineSlotCard
{
    ResursiChain chain;
    Core::RawFiles files;
    std::vector<std::vector<std::uint8_t>> slots;

    NineSlotCard()
    {
        const auto& profile = profileOf("ID");
        files = withSignedObjects(profile, citizenFiles(), chain);
        slots = slotDigests(profile, profile.sods[0], files);
    }
};

} // namespace

// Same bytes in the same slots: bound, signer pinned to the issuer.
TEST(CardVerifierPin, UnswappedNineSlotsAreValid)
{
    NineSlotCard card;

    EXPECT_EQ(runVerifyFixedData({&card.chain.root, &card.chain.resursi}, card.files), VerificationResult::Valid);
}

// The fifth slot answers to nothing a reader can fetch: whatever it holds is
// counted and not checked.
TEST(CardVerifierPin, CardEdgeFixedNineSlots)
{
    NineSlotCard card;
    ASSERT_EQ(card.slots.size(), 9u);
    ASSERT_EQ(Core::documentProfiles()[0].sods[0].slots[4], Core::kProtectedSlot);
    card.slots[4].assign(32, 0);
    ASSERT_EQ(RAND_bytes(card.slots[4].data(), 32), 1);
    card.files[0x0F1C] = signedObjectFile(0x0F1C, card.chain.sign(card.slots));

    EXPECT_EQ(runVerifyFixedData({&card.chain.root, &card.chain.resursi}, card.files), VerificationResult::Valid);
}

// Both files are covered, but each in the other's slot: the document data was
// moved under the personal-data slot and vice versa. Every digest is present in
// the object, yet neither file is where the issuer put it.
TEST(CardVerifierPin, SwappedCoveredFilesAreInvalid)
{
    NineSlotCard card;
    std::swap(card.files[0x0F02], card.files[0x0F03]);

    EXPECT_EQ(runVerifyFixedData({&card.chain.root, &card.chain.resursi}, card.files), VerificationResult::Invalid);
}

// A covered file the reader could not read is not skipped: skipping belongs to the
// protected slot alone.
TEST(CardVerifierPin, UnreadCoveredFileIsInvalid)
{
    NineSlotCard card;
    card.files.erase(0x0F12);

    EXPECT_EQ(runVerifyFixedData({&card.chain.root, &card.chain.resursi}, card.files), VerificationResult::Invalid);
}

// --- the three signed objects of the official ID ---

namespace {

struct ServiceIdCard
{
    ResursiChain chain;
    Core::RawFiles files;

    ServiceIdCard() : files(withSignedObjects(profileOf("EL"), serviceIdFiles(), chain)) {}

    std::unique_ptr<eidcard::CardVerifier> verifier() const
    {
        auto v = std::make_unique<eidcard::CardVerifier>("");
        for (const auto& der : chain.anchors())
            v->addCertificate(der);
        return v;
    }
    VerificationResult fixed() const
    {
        return verifier()->verifyFixedData(profileOf("EL"), files);
    }
    VerificationResult variable() const
    {
        return verifier()->verifyVariableData(profileOf("EL"), files);
    }
};

void corrupt(Core::RawFiles& files, std::uint16_t fid)
{
    ASSERT_GT(files.at(fid).size(), 60u);
    files.at(fid)[files.at(fid).size() - 20] ^= 0xFF;
}

} // namespace

// 0D08 is the fixed verdict; 0D09 and 0D0A both have to bind for the variable one.
TEST(CardVerifierPin, ServiceIdThreeObjects)
{
    ServiceIdCard card;
    EXPECT_EQ(card.fixed(), VerificationResult::Valid);
    EXPECT_EQ(card.variable(), VerificationResult::Valid);

    ServiceIdCard brokenSealed;
    corrupt(brokenSealed.files, 0x0D0A);
    EXPECT_EQ(brokenSealed.variable(), VerificationResult::Invalid);
    EXPECT_EQ(brokenSealed.fixed(), VerificationResult::Valid);

    ServiceIdCard brokenService;
    corrupt(brokenService.files, 0x0D09);
    EXPECT_EQ(brokenService.variable(), VerificationResult::Invalid);
    EXPECT_EQ(brokenService.fixed(), VerificationResult::Valid);

    ServiceIdCard brokenFixed;
    corrupt(brokenFixed.files, 0x0D08);
    EXPECT_EQ(brokenFixed.fixed(), VerificationResult::Invalid);
    EXPECT_EQ(brokenFixed.variable(), VerificationResult::Valid);
}

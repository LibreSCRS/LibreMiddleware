// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "card_verifier.h"
#include <rs_container.h>
#include <rs_digest_binding.h>
#include <rs_signed_object.h>

#include <LibreSCRS/Logging.h>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>

#include <openssl/pkcs7.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include <algorithm>
#include <set>

namespace eidcard {

namespace Core = LibreSCRS::RsEId::Core;

using LibreSCRS::Internal::Crypto::Pkcs7Ptr;
using LibreSCRS::Internal::Crypto::X509StackBorrowedPtr;

namespace {

// The PKCS#7 inside a signed-object file: container and inner TLV stripped.
// Empty when the file has no complete container.
std::span<const uint8_t> cmsOf(const std::vector<uint8_t>& file)
{
    const auto container = Core::leadingTlv(file);
    if (!container)
        return {};
    return Core::innerTlvPayload(container->subspan(Core::kContainerHeaderSize));
}

const Core::FileSpec* specOf(const Core::DocumentProfile& profile, uint16_t fid)
{
    const auto it = std::ranges::find(profile.files, fid, &Core::FileSpec::fid);
    return it == profile.files.end() ? nullptr : &*it;
}

VerificationResult combine(VerificationResult a, VerificationResult b)
{
    if (a == VerificationResult::Invalid || b == VerificationResult::Invalid)
        return VerificationResult::Invalid;
    if (a == VerificationResult::Unknown || b == VerificationResult::Unknown)
        return VerificationResult::Unknown;
    return VerificationResult::Valid;
}

} // namespace

CardVerifier::CardVerifier(const std::string& certificateFolderPath)
{
    trust.loadFromFolder(certificateFolderPath);
}

void CardVerifier::addCertificate(const std::vector<uint8_t>& derCert)
{
    trust.addCertificate(derCert);
}

CardVerifier::~CardVerifier() = default;

std::vector<uint16_t> CardVerifier::filesFor(const Core::DocumentProfile& profile, Core::SodRole role)
{
    std::set<uint16_t> fids;
    for (const auto& sod : profile.sods) {
        if (sod.role != role)
            continue;
        fids.insert(sod.fid);
        for (const auto slot : sod.slots) {
            if (slot != Core::kProtectedSlot)
                fids.insert(slot);
        }
    }
    return {fids.begin(), fids.end()};
}

// --- Card-level certificate: the signer chain of the first signed object ---

VerificationResult CardVerifier::verifyCard(const Core::DocumentProfile& profile, const Core::RawFiles& files)
{
    try {
        const auto file = files.find(profile.cardCertSodFid);
        if (file == files.end())
            return VerificationResult::Invalid;
        const auto sodData = cmsOf(file->second);
        if (sodData.empty())
            return VerificationResult::Invalid;

        // Pkcs7Ptr / X509StackBorrowedPtr keep their handles alive across every
        // throwable line below. The stack's deleter is sk_X509_free (not
        // sk_X509_pop_free) because PKCS7_get0_signers returns borrowed certs
        // owned by the parent PKCS7.
        const uint8_t* p = sodData.data();
        Pkcs7Ptr pkcs7(d2i_PKCS7(nullptr, &p, static_cast<long>(sodData.size())));
        if (!pkcs7)
            return VerificationResult::Invalid;

        // PKCS7_NOVERIFY skips cert chain validation (done below), but the
        // signature itself IS checked.
        if (PKCS7_verify(pkcs7.get(), nullptr, nullptr, nullptr, nullptr, PKCS7_NOVERIFY) != 1)
            return VerificationResult::Invalid;

        X509StackBorrowedPtr signerCerts(PKCS7_get0_signers(pkcs7.get(), nullptr, 0));
        if (!signerCerts || sk_X509_num(signerCerts.get()) != 1)
            return VerificationResult::Invalid;

        return Core::verifySignerTrust(trust, sk_X509_value(signerCerts.get(), 0));
    } catch (const std::exception& e) {
        LibreSCRS::log::tracef(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verifyCard exception: {}", e.what());
        return VerificationResult::Unknown;
    } catch (...) {
        LibreSCRS::log::trace(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verifyCard unknown exception");
        return VerificationResult::Unknown;
    }
}

VerificationResult CardVerifier::verifyFixedData(const Core::DocumentProfile& profile, const Core::RawFiles& files)
{
    return verifyRole(profile, Core::SodRole::Fixed, files);
}

VerificationResult CardVerifier::verifyVariableData(const Core::DocumentProfile& profile, const Core::RawFiles& files)
{
    return verifyRole(profile, Core::SodRole::Variable, files);
}

VerificationResult CardVerifier::verifyRole(const Core::DocumentProfile& profile, Core::SodRole role,
                                            const Core::RawFiles& files)
{
    try {
        bool any = false;
        auto verdict = VerificationResult::Valid;
        for (const auto& sod : profile.sods) {
            if (sod.role != role)
                continue;
            any = true;
            verdict = combine(verdict, verifySod(profile, sod, files));
        }
        return any ? verdict : VerificationResult::Unknown;
    } catch (const std::exception& e) {
        LibreSCRS::log::tracef(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verify exception: {}", e.what());
        return VerificationResult::Unknown;
    } catch (...) {
        LibreSCRS::log::trace(LibreSCRS::log::TraceChannel::Sign, "[CardVerifier] verify unknown exception");
        return VerificationResult::Unknown;
    }
}

// --- One signed object against the files it covers ---

VerificationResult CardVerifier::verifySod(const Core::DocumentProfile& profile, const Core::SodSpec& sod,
                                           const Core::RawFiles& files)
{
    const auto sodFile = files.find(sod.fid);
    if (sodFile == files.end())
        return VerificationResult::Invalid;
    const auto cms = cmsOf(sodFile->second);
    if (cms.empty())
        return VerificationResult::Invalid;

    // Strictly positional. A slot with no file read is an empty candidate set,
    // which never matches; only the protected slot is skipped.
    std::vector<Core::SlotInput> slots;
    slots.reserve(sod.slots.size());
    for (const auto fid : sod.slots) {
        if (fid == Core::kProtectedSlot) {
            slots.emplace_back(Core::SkipSlot{});
            continue;
        }
        Core::BlockCandidates candidates;
        const auto file = files.find(fid);
        const auto* spec = specOf(profile, fid);
        if (file != files.end() && spec)
            candidates.push_back(Core::sodBlock(*spec, file->second));
        slots.emplace_back(std::move(candidates));
    }

    const auto report = Core::verifySignedObject(cms, slots, trust);

    // Signature and signer come first, as ever: a broken one is Invalid and an
    // outside signer Unknown, whatever the object's shape.
    if (report.signer != VerificationResult::Valid)
        return report.signer;

    // The object has the shape this profile measured: every slot must bind.
    if (report.slotCount == slots.size())
        return report.digestsBound ? VerificationResult::Valid : VerificationResult::Invalid;

    // Another shape that some profile measured, in the place of this one: a
    // genuine object that does not belong here.
    const auto measured = Core::measuredSlotCounts();
    if (std::ranges::find(measured, report.slotCount) != measured.end())
        return VerificationResult::Invalid;

    // A shape nobody measured: not judged, not condemned.
    return VerificationResult::Unknown;
}

} // namespace eidcard

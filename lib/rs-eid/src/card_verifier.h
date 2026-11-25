// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include "eidtypes.h"

#include <rs_document_profile.h>
#include <rs_trust_store.h>

namespace eidcard {

/// Judges a card from the files already read: no card access, so what it says
/// is about the bytes in hand. A covered file that is not among them (absent,
/// protected, unreadable) is a mismatch, never a skip.
class CardVerifier
{
public:
    explicit CardVerifier(const std::string& certificateFolderPath);
    ~CardVerifier();

    CardVerifier(const CardVerifier&) = delete;
    CardVerifier& operator=(const CardVerifier&) = delete;

    // Add a single DER-encoded trusted certificate to the store.
    // Use this when certs are provided as raw bytes (e.g. from Qt resources).
    void addCertificate(const std::vector<uint8_t>& derCert);

    /// The signer chain of the profile's card-certificate object.
    VerificationResult verifyCard(const LibreSCRS::RsEId::Core::DocumentProfile& profile,
                                  const LibreSCRS::RsEId::Core::RawFiles& files);

    /// Every Fixed signed object of the profile: Invalid if any is, else
    /// Unknown if any is, else Valid.
    VerificationResult verifyFixedData(const LibreSCRS::RsEId::Core::DocumentProfile& profile,
                                       const LibreSCRS::RsEId::Core::RawFiles& files);

    /// The same over the Variable objects.
    VerificationResult verifyVariableData(const LibreSCRS::RsEId::Core::DocumentProfile& profile,
                                          const LibreSCRS::RsEId::Core::RawFiles& files);

    /// Files a verdict for @p role reads: the signed objects and what they cover,
    /// except the protected slot.
    static std::vector<std::uint16_t> filesFor(const LibreSCRS::RsEId::Core::DocumentProfile& profile,
                                               LibreSCRS::RsEId::Core::SodRole role);

private:
    VerificationResult verifyRole(const LibreSCRS::RsEId::Core::DocumentProfile& profile,
                                  LibreSCRS::RsEId::Core::SodRole role, const LibreSCRS::RsEId::Core::RawFiles& files);
    VerificationResult verifySod(const LibreSCRS::RsEId::Core::DocumentProfile& profile,
                                 const LibreSCRS::RsEId::Core::SodSpec& sod,
                                 const LibreSCRS::RsEId::Core::RawFiles& files);

    LibreSCRS::RsEId::Core::TrustStore trust;
};

} // namespace eidcard

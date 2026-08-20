// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "rs_digest_binding.h"
#include "rs_trust_store.h"
#include "rs_types.h"

#include <cstdint>
#include <span>

namespace LibreSCRS::RsEId::Core {

/// @brief What a card Security Object says about the files it covers.
///
/// Two axes, kept apart on purpose: "is this signer ours" and "do the covered
/// files sit where the object put them" are different questions, and collapsing
/// them into one verdict loses the distinction between an untrusted issuer and
/// a tampered file.
struct SignedObjectReport
{
    VerificationResult signer = VerificationResult::Invalid;
    bool digestsBound = false;
};

/// @brief Verify a PKCS#7 SignedData whose content is concatenated SHA-256 slots.
///
/// The signed content never leaves this function: handing it back would invite a
/// caller to read attacker-chosen bytes that merely look verified.
///
/// @param cmsDer  DER or BER (indefinite-length) PKCS#7 SignedData.
/// @param blocks  Covered files, in the order the object covers them.
[[nodiscard]] SignedObjectReport verifySignedObject(std::span<const std::uint8_t> cmsDer,
                                                    std::span<const BlockCandidates> blocks, DigestBinding binding,
                                                    const TrustStore& trust);

/// @brief Validate @p signerCert against @p trust and pin it to the document-signer domain.
///
/// The single authority for the card-data trust decision: the Security Object
/// path and the card-certificate path must not answer this differently.
[[nodiscard]] VerificationResult verifySignerTrust(const TrustStore& trust, X509* signerCert);

} // namespace LibreSCRS::RsEId::Core

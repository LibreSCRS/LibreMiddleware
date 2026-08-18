// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief The ONE issuer-resolution predicate shared by every chain walk in
///        libresign (the Trusted-List completion walk and the on-token
///        fallback ordering). A subject-DN match alone is never trusted — a
///        name-colliding impostor that never signed the certificate must not
///        resolve as its issuer — so the predicate requires the candidate's
///        key to actually verify the subject's signature. Keeping the rule in
///        one place means the two walks cannot drift.

#include <openssl/x509.h>

namespace libresign::native_utils {

/// @brief True iff @p issuer's subject DN matches @p subject's issuer DN AND
///        @p issuer's public key verifies @p subject's signature.
///        Deliberately NO validity-window check — mirrors the Trusted-List
///        walk's established behavior (the signer's own expiry is enforced
///        separately; a same-subject/same-key CA renewal pair remains an
///        accepted residual).
[[nodiscard]] inline bool issuerSignedSubject(X509* issuer, X509* subject) noexcept
{
    if (issuer == nullptr || subject == nullptr)
        return false;
    if (X509_NAME_cmp(X509_get_subject_name(issuer), X509_get_issuer_name(subject)) != 0)
        return false;
    EVP_PKEY* issuerKey = X509_get0_pubkey(issuer);
    return issuerKey != nullptr && X509_verify(subject, issuerKey) == 1;
}

/// @brief True iff @p cert is self-signed AND self-verifying (issuer DN ==
///        subject DN, own key verifies own signature) — the only shape the
///        revocation gate may exempt as a chain's root terminal when no
///        Trusted List proved the termination.
[[nodiscard]] inline bool isSelfSignedSelfVerifying(X509* cert) noexcept
{
    if (cert == nullptr)
        return false;
    if (X509_NAME_cmp(X509_get_issuer_name(cert), X509_get_subject_name(cert)) != 0)
        return false;
    EVP_PKEY* key = X509_get0_pubkey(cert);
    return key != nullptr && X509_verify(cert, key) == 1;
}

} // namespace libresign::native_utils

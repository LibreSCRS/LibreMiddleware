// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <cstdint>
#include <span>

namespace libresign {

class SigningKey;

class SigningService
{
public:
    virtual ~SigningService() = default;

    // Configure trust lists and revocation sources.
    // Default implementation is a no-op (native backend uses bundled certs).
    virtual bool configure(const TrustConfig& /*config*/)
    {
        return true;
    }

    virtual bool isAvailable() const = 0;

    /// @brief Sign @p request.document with @p key, a key the caller holds:
    ///        in production the key signs through the card plugin on the
    ///        session the host holds for the reader.
    virtual SigningResult sign(const SigningRequest& request, SigningKey& key) = 0;

    /// @brief Append a new signer, @p key, to a prior signature, producing a
    ///        multi-signature document with the new signer's signature
    ///        alongside the existing ones.
    ///
    /// For ENVELOPED packagings (PAdES, XAdES-Enveloped, JAdES-Enveloped,
    /// ASiC-E) @p originalDocument may be empty — the original payload is
    /// recoverable from @p priorSignature. When non-empty, implementations
    /// SHOULD assert it matches the embedded original and reject the call
    /// with @ref SignFailureKind::InvalidDocument on mismatch (tamper detection).
    ///
    /// For DETACHED packagings (CAdES, XAdES-Detached, JAdES-Detached)
    /// @p originalDocument is MANDATORY — RFC 7797 / ETSI EN 319 122 / etc.
    /// detached blobs do not carry the original by spec. Implementations
    /// MUST return @ref SignFailureKind::InvalidInput when the original is
    /// absent.
    ///
    /// Format is INFERRED from @p priorSignature and overrides any value
    /// in @p request.format; level / TSA / visual carry over to the new
    /// signer, and packaging is a hint for ambiguous inputs only.
    virtual SigningResult appendSigner(const SigningRequest& request, std::span<const uint8_t> priorSignature,
                                       std::span<const uint8_t> originalDocument, SigningKey& key) = 0;
};

} // namespace libresign

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token;

class JAdESModule
{
public:
    SigningResult sign(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                       SignatureLevel level, SignaturePackaging packaging, const TSAConfig& tsa);

    /// @brief Append a new signer to an existing JAdES JWS JSON General signature.
    ///
    /// Both packagings are supported:
    /// - **ENVELOPED prior** (`payload` field present and base64url-encoded): the new
    ///   signer signs the same payload as the existing signers; a new entry is
    ///   appended to `signatures[]`. The original document is recovered from the
    ///   prior; @p originalDoc is optional and, when supplied, is verified against
    ///   the decoded prior payload (mismatch returns `InvalidInput`).
    /// - **DETACHED prior** (RFC 7797 §4.2: no `payload` field): the new signer
    ///   signs @p originalDoc with `b64=false` semantics; the output remains a
    ///   detached JWS JSON General with N+1 signature entries over the same
    ///   detached payload. @p originalDoc is mandatory here.
    ///
    /// `B_B`, `B_T` and `B_LT` are supported for the new signer: `sigTst` and
    /// `rVals` are per-signature `etsiU` components (ETSI TS 119 182-1 §5.3)
    /// and are written into the appended entry's own unprotected header,
    /// leaving every prior entry byte-identical.
    ///
    /// `B_LTA` is gated with `PolicyViolation`: an archive timestamp seals a
    /// document state, and appending a signature entry changes that state for
    /// every signer already present, whose own `arcTst` cannot be recomputed
    /// without their PKCS#11 sessions.
    ///
    /// @param prior        JWS JSON General document (with or without `payload`)
    /// @param originalDoc  payload bytes (mandatory for DETACHED, optional for
    ///                     ENVELOPED — verified against decoded payload when supplied)
    /// @param fileName     file name hint (unused on the JAdES path; carried for
    ///                     interface symmetry with sibling modules)
    /// @param token        signing token
    /// @param level        desired level for the new signer (`B_B`, `B_T` or `B_LT`)
    /// @param tsa          TSA config — required from `B_T` upwards
    /// @return @ref SigningResult containing the updated JWS JSON General document
    [[nodiscard]] SigningResult appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                             const std::string& fileName, Pkcs11Token& token, SignatureLevel level,
                                             const TSAConfig& tsa);
};

} // namespace libresign

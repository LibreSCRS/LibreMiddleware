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

class ASiCModule
{
public:
    SigningResult signWithCAdES(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                                SignatureLevel level, const TSAConfig& tsa);

    /// @brief Append a new signer to an existing ASiC-E container.
    ///
    /// ASiC-E containers carry one or more `META-INF/signatureNNN.p7s` (CAdES)
    /// or `META-INF/signaturesNNN.xml` (XAdES) signature files per
    /// ETSI EN 319 162-1 §A.4 (parallel-sequential multi-sign). This method
    /// adds a new CAdES `signature{maxNNN+1}.p7s` to a prior ASiC-E container;
    /// the new signature covers the same single data file the existing signers
    /// covered. The underlying @ref signWithCAdES already implements the
    /// multi-sign mechanic — @ref appendSigner is a thin wrapper that
    /// documents the semantic intent and gives the per-format dispatcher
    /// a uniform API to call.
    ///
    /// @param prior        the existing ASiC-E ZIP bytes (must be a
    ///                     well-formed ASiC-E container with at least one
    ///                     prior signature)
    /// @param originalDoc  may be empty (the signed bytes are read from the
    ///                     container's data file); when non-empty, currently
    ///                     informational only — the new signer signs whatever
    ///                     bytes are in the container's data file
    /// @param token        signing token (already opened + logged in)
    /// @param level        desired signature level for the new signature
    /// @param tsa          TSA config for the new signature
    /// @return @ref SigningResult containing the new ASiC-E ZIP bytes, or
    ///         a failure with @ref SignFailureKind::InvalidInput when
    ///         @p prior is empty
    [[nodiscard]] SigningResult appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                             Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa);
};

} // namespace libresign

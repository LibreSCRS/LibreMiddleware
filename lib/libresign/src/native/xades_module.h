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
#include <string_view>
#include <vector>

namespace libresign {

class Pkcs11Token;

class XAdESModule
{
public:
    SigningResult sign(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                       SignatureLevel level, SignaturePackaging packaging, const TSAConfig& tsa);

    /// @brief Append a new signer to an existing XAdES signature.
    ///
    /// Handles two cases, distinguished by the root element of @p prior:
    /// - **ENVELOPED prior** (root is the host document, with one or more
    ///   embedded `ds:Signature` children): the new `ds:Signature` is added
    ///   as another sibling at the document root. Same mechanic as the
    ///   pre-4.2 auto-detect multi-sign path, now reachable through an
    ///   explicit entry point.
    /// - **DETACHED prior** (root is `ds:Signature`, or already an
    ///   `asic:Signatures` multi-sig container per ETSI EN 319 132-1 §A.5 /
    ///   EN 319 162-1): the prior + new signatures are wrapped together in
    ///   an `asic:Signatures` element so the multi-sig output is itself a
    ///   valid XML document.
    ///
    /// @param prior         the prior XML signature document
    /// @param originalDoc   the original payload bytes; required for
    ///                      DETACHED, may be empty for ENVELOPED (the host
    ///                      document is recoverable from @p prior itself)
    /// @param fileName      file name used for the new signature's
    ///                      `ds:Reference` URI in the DETACHED case
    /// @param token         signing token
    /// @param level         desired XAdES level for the new signature
    /// @param tsa           TSA configuration (required for B-T and above)
    /// @return @ref SigningResult; on failure carries a @ref SignFailureKind
    /// @throws nothing (failures returned via @ref SigningResult)
    [[nodiscard]] SigningResult appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                             const std::string& fileName, Pkcs11Token& token, SignatureLevel level,
                                             const TSAConfig& tsa);

private:
    /// Internal sign variant with an optional Id suffix override.
    ///
    /// When @p forcedIdSuffix is empty the DETACHED path defaults to "1" and
    /// the ENVELOPED path scans the input XML for occupied Signature-N /
    /// SignedProperties-N / SignatureValue-N / Reference-N Ids and picks the
    /// smallest free N. When non-empty, the supplied suffix is used verbatim
    /// (caller is responsible for ensuring it does not collide).
    ///
    /// Required by appendSigner DETACHED so the new signature mints unique
    /// Ids against the prior asic:Signatures wrapper BEFORE signing — Id
    /// values participate in the digested SignedProperties + SignedInfo
    /// canonicalisations, so post-hoc rename of Ids would invalidate the
    /// signature.
    SigningResult signWithSuffix(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                                 SignatureLevel level, SignaturePackaging packaging, const TSAConfig& tsa,
                                 std::string_view forcedIdSuffix);
};

} // namespace libresign

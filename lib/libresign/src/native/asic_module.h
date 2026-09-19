// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token;

namespace detail {

/// One entry of an ASiC-E container, as read back out of the ZIP.
struct AsicEntry
{
    std::string name;
    std::vector<uint8_t> data;
};

/// What a well-formed ASiC-E container yields: the single data file every
/// signer covers, every `META-INF/*` entry preserved byte for byte, and the
/// next free signature number.
struct ParsedAsic
{
    std::string dataFileName;             // first non-META-INF, non-mimetype entry
    std::vector<uint8_t> dataFileBytes;   // its content
    std::vector<AsicEntry> preservedMeta; // every META-INF/* entry (sigs + manifests + anything else)
    int nextSigNum = 1;                   // max existing signatureNNN/ASiCManifestNNN + 1
};

/// Read an ASiC-E container the user brought.
///
/// Returns a @ref ParsedAsic when @p data is a well-formed ASiC-E container
/// with exactly one data file and at least one prior signature/manifest pair,
/// and `nullopt` for anything else -- a non-ZIP input, the wrong mimetype,
/// zero or several data files, or an entry that fails the zip-slip and size
/// caps. Every byte of @p data is the user's choice and nothing has verified a
/// signature at this point, which is why it is reachable from a fuzz harness:
/// the decoder behind it is the vendored ZIP implementation.
///
/// Declared here rather than left in an anonymous namespace so a harness can
/// call it. The demangled name carries no exported type, so the version
/// script's `*LibreSCRS::*` glob does not pick it up.
std::optional<ParsedAsic> tryParseAsic(const std::vector<uint8_t>& data);

/// What a container that @ref tryParseAsic refused actually is.
///
/// `tryParseAsic` returning `nullopt` conflates two very different inputs: a
/// PDF or a generic blob, which should be wrapped and signed fresh, and a
/// recognisable ASiC-E container carrying several root data files, which
/// re-signing cannot express and which deserves to be told apart by name.
enum class AsicProbe {
    NotAsicE,              ///< no readable mimetype entry, or not the ETSI literal
    NoPriorSignature,      ///< recognisable ASiC-E with nothing to join: sign it fresh
    MultipleRootDataFiles, ///< recognisable ASiC-E, more root data files than one
    EntryTooLarge,         ///< recognisable ASiC-E, an entry declares more than the per-entry cap
    Unreadable,            ///< recognisable ASiC-E WITH prior signatures that the reader refused
};

/// The per-entry ceiling the reader applies, so a caller can say the number.
std::size_t maxContainerEntryBytes();

/// Answer that question, over the same bytes and with the same caps.
///
/// The distinction that matters to the signing path is not why the reader
/// refused but whether there was anything to join. A container with no
/// signature in it is signed fresh, and that is right. A container that DOES
/// carry prior signatures and could not be read must not be signed fresh: doing
/// so wraps it as a new document, so the holder sees success and a validator
/// sees one signature where there were several. Naming only the two reasons this
/// probe could enumerate left every other reason -- the running size budget, the
/// entry count, a name that fails validation, an entry that does not decode --
/// falling through silently.
///
/// Declared here rather than left inline in the signing path so a test and a
/// harness can reach it. The signing path used to inline this, which is how an
/// uncapped extraction survived beneath a capped one: the measurement drove
/// @ref tryParseAsic and this ran only when that had already refused.
AsicProbe probeAsic(const std::vector<uint8_t>& data);

} // namespace detail

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
    ///         a failure with @ref SignFailureKind::InvalidDocument when
    ///         @p prior is empty
    [[nodiscard]] SigningResult appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                             Pkcs11Token& token, SignatureLevel level, const TSAConfig& tsa);
};

} // namespace libresign

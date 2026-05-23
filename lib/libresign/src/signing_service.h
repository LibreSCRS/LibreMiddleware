// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <LibreSCRS/Secure/Buffer.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string_view>

namespace LibreSCRS::SmartCard {
class CardSession;
}

namespace libresign {

// Helper for callers that have the PIN as a std::string_view (e.g. test
// fixtures with string literals). Production callers SHOULD store the PIN in
// a @ref LibreSCRS::Secure::Buffer and forward it directly — the buffer's
// cleansing-on-destroy contract is enforced at the type system, so no caller
// discipline is required beyond keeping the buffer in scope across the call.
inline LibreSCRS::Secure::Buffer as_pin(std::string_view pin)
{
    return LibreSCRS::Secure::Buffer(pin);
}

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

    // PKCS#11 path — backend drives the card session.
    //
    // pin: @ref LibreSCRS::Secure::Buffer borrowed from the caller. Its
    //      storage is cleansed on destruction (cleansing-on-destroy is part of
    //      the type contract — no caller-side discipline required). The
    //      service implementation MUST NOT retain a pointer into the buffer
    //      past return and MUST cleanse any intermediate copies it creates
    //      internally (e.g. a std::string materialised for a JSON payload).
    //
    // readerName: the FULL PCSC reader name the caller wants to sign on.
    // Mandatory: legacy auto-pick paths (`tokenLabel = ""` → slots[0])
    // were removed in 4.0 — they routed PIN to whatever card the PCSC
    // daemon enumerated first, which broke under any multi-card setup
    // (the user's eID at port 02 vs another card at port 00 = silent
    // PIN-to-wrong-card → spurious "wrong PIN"). The signing engine
    // resolves the slot via FNV-1a hash of @p readerName embedded in
    // the LM PKCS#11 module's slotDescription — see
    // `lib/pkcs11/include/pkcs11/internal/slot_hash.h`.
    //
    // The PACE/BAC SecureChannel established by the host's display flow
    // is preserved across the libresign call boundary automatically: the
    // CardSession that owns the live channel auto-registers in the
    // process-local SessionPresence on `activateChannelWithSm` success,
    // and the in-process PKCS#11 provider's probe path adopts it from
    // there instead of opening a second standalone session. Callers
    // must keep at least one `std::shared_ptr<CardSession>` ref alive
    // across the sign call so the registry's `weak_ptr` lookup resolves.
    /// @since 4.2
    virtual SigningResult sign(const SigningRequest& request, const std::string& pkcs11ModulePath,
                               const LibreSCRS::Secure::Buffer& pin, const std::string& keyAlias,
                               const std::string& readerName) = 0;

    /// @brief Append a new signer to a prior signature, producing a multi-
    ///        signature document with the new signer's signature alongside
    ///        the existing ones.
    ///
    /// For ENVELOPED packagings (PAdES, XAdES-Enveloped, JAdES-Enveloped,
    /// ASiC-E) @p originalDocument may be empty — the original payload is
    /// recoverable from @p priorSignature. When non-empty, implementations
    /// SHOULD assert it matches the embedded original and reject the call
    /// with @ref SignFailureKind::InvalidInput on mismatch (tamper detection).
    ///
    /// For DETACHED packagings (CAdES, XAdES-Detached, JAdES-Detached)
    /// @p originalDocument is MANDATORY — RFC 7797 / ETSI EN 319 122 / etc.
    /// detached blobs do not carry the original by spec. Implementations
    /// MUST return @ref SignFailureKind::InvalidInput when the original is
    /// absent.
    ///
    /// Format is INFERRED from @p priorSignature and overrides any value
    /// in @p request.format.
    ///
    /// @param request          signing request — level / TSA / visual carry
    ///                         over to the new signer; format is overridden
    ///                         by inference, packaging is a hint for
    ///                         ambiguous inputs only.
    /// @param priorSignature   the existing signed document / signature
    ///                         container being extended.
    /// @param originalDocument the original payload (DETACHED: mandatory;
    ///                         ENVELOPED: empty or tamper-check assertion).
    /// @param pin              caller-owned, cleansing-on-destroy; same
    ///                         contract as @ref sign.
    /// @param pkcs11Module     PKCS#11 driver path.
    /// @param keyAlias         CKA_LABEL of the signer key on @p readerName.
    /// @param readerName       full PCSC reader name; same multi-card
    ///                         routing contract as @ref sign. The
    ///                         SessionPresence registry handles the
    ///                         display-flow PACE handoff transparently;
    ///                         see @ref sign for the lifetime contract
    ///                         the host must honour for that to work.
    /// @return SigningResult — same shape as @ref sign.
    /// @since 4.2
    virtual SigningResult appendSigner(const SigningRequest& request, std::span<const uint8_t> priorSignature,
                                       std::span<const uint8_t> originalDocument, const LibreSCRS::Secure::Buffer& pin,
                                       const std::string& pkcs11Module, const std::string& keyAlias,
                                       const std::string& readerName) = 0;

    virtual bool isAvailable() const = 0;
};

} // namespace libresign

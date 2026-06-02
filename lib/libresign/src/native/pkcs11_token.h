// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "pkcs11_module_manager.h"

#include <LibreSCRS/Secure/Buffer.h>

#include <cstdint>
#include <memory>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::SmartCard {
class CardSession;
}

namespace libresign {

class Pkcs11Token
{
public:
    // pin: @ref LibreSCRS::Secure::Buffer borrowed from the caller. The token
    // does not retain a pointer into the buffer past construction; the bytes
    // are passed straight to C_Login which copies them into the PKCS#11
    // module. The buffer's cleansing-on-destroy contract is enforced at the
    // type system — no caller-side discipline required.
    //
    // module: live handle into the process-shared loaded module cache
    // owned by @ref Pkcs11ModuleManager. The Token does NOT drive
    // @c dlopen / @c dlclose / @c C_Initialize / @c C_Finalize — those
    // are the manager's responsibility. The handle keeps the underlying
    // mapping alive for the Token's lifetime; multiple concurrent Tokens
    // built from the same module share one initialised CK_FUNCTION_LIST.
    //
    // readerName: the FULL PCSC reader name the caller wants to sign
    // on. The constructor enumerates the loaded module's slots, parses
    // each `slotDescription`'s `[<8-hex-hash>]` prefix (set by LM's
    // PKCS#11 module — see
    // `lib/pkcs11/include/pkcs11/internal/slot_hash.h`), and matches
    // against the caller's readerName via the same FNV-1a hash.
    //
    // Single mandatory ctor: no legacy `int slotIndex = -1` path that
    // silently picked `slots[0]` and routed PIN to whatever card the
    // PCSC daemon enumerated first (broken under any multi-card setup);
    // no `tokenLabel` substring-match path either.
    //
    // Throws `std::runtime_error` on:
    //   * no slot in the loaded module matches @p readerName, or
    //   * the loaded module's `slotDescription` does not carry the
    //     LibreSCRS hash-bracket convention (third-party PKCS#11 modules
    //     are not supported on this signing path; their slot lookup
    //     would have to fall back to a different identification scheme).
    //
    // The host's display-flow CardSession (if any) is found by the loaded
    // module's @c C_GetSlotList probe via the process-local SessionPresence
    // registry — the host populates that registry transparently when
    // @c CardSession::activateChannelWithSm commits a PACE/BAC handshake,
    // and the caller's `shared_ptr<CardSession>` simply has to outlive
    // this Token construction so the registry's `weak_ptr` lookup
    // resolves to a live entry.
    //
    // keyId: card-side CKA_ID of the signing key/cert pair. When non-empty
    // the private-key search selects by CKA_ID (the reuse-safe exact-key
    // discriminator) and refuses ambiguity — >1 matching key throws
    // @ref SignFailureException with @ref SignFailureKind::KeyAmbiguous; the
    // @p keyAlias is then a display hint only. When empty, the legacy
    // CKA_LABEL (or signing-capable auto-select) path runs — the label is
    // NOT unique on multi-cert cards, so callers that must sign with one
    // exact key pass @p keyId.
    /// @since 4.1
    Pkcs11Token(Pkcs11ModuleHandle module, const LibreSCRS::Secure::Buffer& pin, const std::string& keyAlias,
                const std::string& readerName, const std::vector<uint8_t>& keyId = {});

    /// @brief Strong-typed wrapper for the test-only raw-slot-ID ctor.
    ///
    /// Production code MUST go through the `readerName` ctor — it
    /// performs hash-based slot lookup against the LM PKCS#11 module's
    /// embedded slot identity. The tag below is used by the SoftHSM2-
    /// backed module-level tests (CAdES, PAdES, XAdES, JAdES, ASiC,
    /// signing_provider) which load SoftHSM2 directly and don't have
    /// a reader-name-shaped slot identity to match against.
    struct TestSlotId
    {
        unsigned long slotId; // PKCS#11 CK_SLOT_ID is `unsigned long`
        explicit constexpr TestSlotId(unsigned long id) noexcept : slotId(id) {}
    };
    Pkcs11Token(Pkcs11ModuleHandle module, const LibreSCRS::Secure::Buffer& pin, const std::string& keyAlias,
                TestSlotId rawSlotId, const std::vector<uint8_t>& keyId = {});

    ~Pkcs11Token();

    Pkcs11Token(const Pkcs11Token&) = delete;
    Pkcs11Token& operator=(const Pkcs11Token&) = delete;

    /// @brief Sign a hash (CKM_RSA_PKCS path: caller pre-built DigestInfo+hash;
    ///        ECDSA: caller passes raw hash). When @p rawData is non-empty AND
    ///        @p algorithm names a hash (e.g. "SHA256withRSA"), the token first
    ///        tries the combined CKM_SHA*_RSA_PKCS mechanism with @p rawData
    ///        (correct for hash-on-card SSCDs such as Cryptovision SCE 8.0,
    ///        German nPA, several QSCDs); on @c CKR_MECHANISM_INVALID or token
    ///        failure it falls back to the legacy CKM_RSA_PKCS path with the
    ///        pre-built @p hash. Callers that lack the raw bytes (OpenSSL CMS
    ///        provider sign callback) pass an empty span and get the legacy
    ///        behaviour.
    std::vector<uint8_t> sign(std::span<const uint8_t> hash, const std::string& algorithm = "SHA256withRSA",
                              std::span<const uint8_t> rawData = {});
    std::vector<uint8_t> certificate() const;
    std::vector<std::vector<uint8_t>> certificateChain() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl;
};

} // namespace libresign

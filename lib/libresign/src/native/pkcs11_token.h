// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

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
    // pin: byte view into caller-owned, caller-cleansed storage. The token
    // does not retain the view past construction; the bytes are passed
    // straight to C_Login which copies them into the PKCS#11 module.
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
    /// @param sharedSession Optional live CardSession owned by the caller
    ///        (typically the LC display session). When non-null, after
    ///        @c C_Initialize succeeds the token forwards the session to
    ///        the loaded librescrs-pkcs11 module via
    ///        @ref LibreSCRS::Pkcs11::SessionAttachment so the PKCS#15
    ///        provider's @c probe path adopts it instead of opening a
    ///        second standalone session against the same reader. When
    ///        null, the standalone path runs (legacy behaviour).
    /// @since 4.1
    Pkcs11Token(const std::string& modulePath, std::span<const uint8_t> pin, const std::string& keyAlias,
                const std::string& readerName,
                std::shared_ptr<LibreSCRS::SmartCard::CardSession> sharedSession = nullptr);

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
    Pkcs11Token(const std::string& modulePath, std::span<const uint8_t> pin, const std::string& keyAlias,
                TestSlotId rawSlotId);

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

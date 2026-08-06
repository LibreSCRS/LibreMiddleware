// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "pkcs15_types.h"

#include <LibreSCRS/Plugin/CredentialCounters.h>
#include <smartcard/secure_buffer.h>

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::SecureChannel {
class ISecureChannel;
}

namespace pkcs15 {

class PKCS15Card
{
public:
    explicit PKCS15Card(LibreSCRS::SecureChannel::ISecureChannel& channel);

    bool probe();        // Try AID SELECT, then EF.DIR fallback
    bool selectApplet(); // Re-select using the method that worked in probe()

    // CardMap interop: read / seed the discovered state so it survives
    // across PKCS15Card instances against the same physical card.
    // `path` empty == "AID-only SELECT worked"; `selectP2` is the
    // probed SELECT FILE P2 value (0x0C with FCI, 0x00 without).
    [[nodiscard]] const std::vector<uint8_t>& pkcs15PathView() const noexcept
    {
        return pkcs15Path;
    }
    [[nodiscard]] uint8_t fileSelectP2View() const noexcept
    {
        return fileSelectP2;
    }
    void seedDiscoveredState(std::vector<uint8_t> path, uint8_t selectP2) noexcept
    {
        pkcs15Path = std::move(path);
        fileSelectP2 = selectP2;
    }
    PKCS15Profile readProfile();
    TokenInfo readTokenInfo(); // Lightweight: reads only EF(TokenInfo), no certs/keys/PINs
    std::vector<uint8_t> readCertificate(const CertificateInfo& cert);
    PinResult verifyPIN(const PinInfo& pin, std::string_view pinValue);
    PinResult changePIN(const PinInfo& pin, std::string_view oldPin, std::string_view newPin);
    /// @brief RESET RETRY COUNTER (unblock).
    ///
    /// Mirrors changeReferenceData's select/transmit/SW-map shape, swapping
    /// in the RESET RETRY COUNTER builder.
    ///
    /// @param pin    The PUK-protected PIN being unblocked.
    /// @param puk    Current PUK value. NOT run through encodePIN: it
    ///               belongs to a DIFFERENT credential (the PUK) whose
    ///               storedLength/padChar are not carried by @p pin, so
    ///               padding it under the target PIN's own AODF attributes
    ///               would risk corrupting the secret — the raw bytes
    ///               travel as-is.
    /// @param newPin New PIN value; may be empty for reset-only unblock
    ///               styles. Like @p puk, NOT run through encodePIN.
    /// @param p1     RESET RETRY COUNTER P1. Caller-supplied: the
    ///               pkcs15-plugin resolves it from the family quirk
    ///               table's per-unblock-style row — never hardcoded here.
    /// @return The resulting PinResult (retriesLeft attributed to the PUK).
    PinResult resetRetryCounter(const PinInfo& pin, std::string_view puk, std::string_view newPin, uint8_t p1);
    /// @brief CHANGE REFERENCE DATA (transport-PIN activation).
    ///
    /// Shared select/transmit/SW-map body for the ordinary change and the
    /// activation forms — changePIN delegates here with P1=0x00. Unlike
    /// resetRetryCounter, @p oldValue and @p newValue belong to THIS SAME
    /// credential (the transport-born SIGN PIN activating to its holder
    /// value, not a cross-credential PUK/newPin pair), so both run through
    /// encodePIN under @p pin's own storedLength/padChar — exactly like
    /// changePIN's oldPin/newPin.
    ///
    /// @param pin      The transport-born PIN being activated.
    /// @param oldValue Transport PIN value. May be empty for the P1=0x01
    ///                 prior-auth form (the transport value was already
    ///                 consumed by a preceding VERIFY): the old-data block
    ///                 is omitted entirely in that case, NOT padded to
    ///                 storedLength — padding would send a bogus
    ///                 padChar-filled block instead of the ISO command's
    ///                 true "old absent" shape.
    /// @param newValue Holder's new PIN value.
    /// @param p1       CHANGE REFERENCE DATA P1. Caller-supplied: the
    ///                 pkcs15-plugin resolves it from the family quirk
    ///                 table's transportChangeP1 row — never hardcoded
    ///                 here.
    /// @return The resulting PinResult.
    PinResult changeReferenceData(const PinInfo& pin, std::string_view oldValue, std::string_view newValue, uint8_t p1);
    /// @brief ISO ACTIVATE (INS 0x44) for the deactivated SIGN key.
    ///
    /// Mirrors resetRetryCounter/changeReferenceData's select/path/transmit
    /// shape: selects the applet then navigates to @p signPin's own DF —
    /// the SIGN key lives alongside its guarding PIN in the signature DF —
    /// before transmitting.
    ///
    /// @param signPin The SIGN PIN guarding the key's DF (selects the path;
    ///                not itself VERIFYed here — the caller VERIFYs
    ///                separately).
    /// @param p1      ACTIVATE P1. Caller-supplied: the pkcs15-plugin
    ///                resolves it from the family quirk table's
    ///                keyActivate row — never hardcoded here.
    /// @param p2      ACTIVATE P2. Same provenance as @p p1.
    /// @return The resulting PinResult. Unlike
    ///         verifyPIN/changePIN/resetRetryCounter/changeReferenceData,
    ///         ACTIVATE carries no PIN-retry-shaped SW semantics of its own
    ///         (retriesLeft/blocked stay at their sentinel defaults in the
    ///         returned PinResult): @c 9000 is a fresh activation and
    ///         @c 6985 is the idempotent already-active case — BOTH are
    ///         reported as @c success so the caller can map either to an
    ///         already-succeeded outcome; anything else is a failure.
    PinResult activate(const PinInfo& signPin, uint8_t p1, uint8_t p2);
    int getPINTriesLeft(const PinInfo& pin);
    // Read the credential's full DOCP counters. Non-9000 / parse miss ⇒ all
    // absent (graceful). Read-only; never decrements a counter.
    LibreSCRS::Plugin::CredentialCounters readCounters(const PinInfo& pin);
    std::vector<uint8_t> sign(const PrivateKeyInfo& key, std::string_view pin, const PinInfo& pinInfo,
                              const std::vector<uint8_t>& digestInfo, const std::vector<uint8_t>& rawData,
                              SignScheme scheme);

private:
    struct KeyRefInfo
    {
        uint8_t keyTag;
        std::vector<uint8_t> keyRefData;
    };
    static KeyRefInfo resolveKeyRef(const PrivateKeyInfo& key);
    std::vector<uint8_t> tryMsePso(uint8_t sigAlgo, const KeyRefInfo& keyRef, const std::vector<uint8_t>& psoData,
                                   uint16_t expectedSigLen, uint16_t& lastSW);
    /// @brief MSE:Set CT with an OID-style algorithm reference (DO 80 with a
    ///        full BSI TR-03110 / ISO 7816-8 OID instead of the legacy 1-byte
    ///        algo). Required by certain IAS-ECC hash-on-card SSCDs (e.g.
    ///        SCE 8.0-C2V0) and other BSI-aligned QSCD cards which reject
    ///        the single-byte form.
    std::vector<uint8_t> tryMsePsoOid(std::span<const uint8_t> algoOid, const KeyRefInfo& keyRef,
                                      const std::vector<uint8_t>& psoData, uint16_t expectedSigLen, uint16_t& lastSW);
    static LibreSCRS::SmartCard::Internal::SecureBuffer encodePIN(std::string_view pin, const PinInfo& pinInfo);
    // Returns: 1=success, 0=wrong PIN (0x63Cx), -1=other failure
    int verifyPinInline(const PinInfo& pinInfo, const LibreSCRS::SmartCard::Internal::SecureBuffer& pinData);
    static std::vector<uint8_t> extractRawHash(const std::vector<uint8_t>& digestInfo);
    bool selectByPath(std::span<const uint8_t> path, uint8_t selectP2 = 0x00);
    std::vector<uint8_t> readSelectedFile();
    bool probeViaEfDir(); // EF.DIR fallback: read MF/2F00, find PKCS#15 path

    LibreSCRS::SecureChannel::ISecureChannel& channel;
    std::vector<uint8_t> pkcs15Path; // Path discovered from EF.DIR (empty = use AID)
    uint8_t fileSelectP2 = 0x00;     // Discovered during probe/first selectByPath
};

} // namespace pkcs15

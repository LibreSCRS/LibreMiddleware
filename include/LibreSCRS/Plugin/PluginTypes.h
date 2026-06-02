// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Plugin ABI version constant @ref
///        LibreSCRS::Plugin::kCardPluginAbiVersion and the small aggregate
///        types (@ref LibreSCRS::Plugin::SignMechanism,
///        @ref LibreSCRS::Plugin::PINResult,
///        @ref LibreSCRS::Plugin::SignResult, …) shared across plugins
///        without depending on @ref LibreSCRS::Plugin::CardPlugin.
///
/// @par Thread-safety
/// All types in this header are plain value aggregates; thread-compatible
/// per API-POLICY §8.

#include <LibreSCRS/Export.h>

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Plugin {

/// @brief Current plugin ABI revision.
///
/// @note Plugin loaders MUST reject any plugin whose `card_plugin_abi_version()`
///       differs from this value. v7 adds the activation-profile virtuals
///       (`activationProfile` / `seedCredentials`) to @ref
///       LibreSCRS::Plugin::CardPlugin, changing its vtable layout.
inline constexpr std::uint32_t kCardPluginAbiVersion = 7;

/// @brief Capability flags describing what a plugin can do.
///
/// Bitfield letting callers ask specific questions ("does this plugin read
/// identity data?", "does it implement PIN management?") rather than
/// inferring from a single summary flag. Composable via `|`; testable via
/// `hasCapability`.
///
/// Plugins return their flag set from `CardPlugin::capabilities`. Callers
/// wrap the result with `hasCapability` when checking a specific bit, or
/// compare bitwise with `&` / `|` when combining multiple flags.
///
/// @since 4.0
enum class CardCapabilities : std::uint32_t {
    None = 0,                ///< No capabilities advertised (sentinel).
    PKI = 1U << 0,           ///< readCertificates + verifyPIN + sign + discoverKeys work.
    IdentityData = 1U << 1,  ///< readCard returns useful identity/document fields.
    EmrtdCrypto = 1U << 2,   ///< eMRTD-family crypto (BAC/PACE/PA/AA/CA) supported.
    PinManagement = 1U << 3, ///< verifyPIN/changePIN/unblockPIN implemented.
};

/// @brief Bitwise OR for `CardCapabilities` flags.
[[nodiscard]] constexpr CardCapabilities operator|(CardCapabilities a, CardCapabilities b) noexcept
{
    return static_cast<CardCapabilities>(static_cast<std::uint32_t>(a) | static_cast<std::uint32_t>(b));
}
/// @brief Bitwise AND for `CardCapabilities` flags.
[[nodiscard]] constexpr CardCapabilities operator&(CardCapabilities a, CardCapabilities b) noexcept
{
    return static_cast<CardCapabilities>(static_cast<std::uint32_t>(a) & static_cast<std::uint32_t>(b));
}
/// @brief True when @p flag is present in @p set.
[[nodiscard]] constexpr bool hasCapability(CardCapabilities set, CardCapabilities flag) noexcept
{
    return (set & flag) != CardCapabilities::None;
}

/// @brief Card answer-to-reset (ATR) match descriptor.
///
/// Combines the canonical ATR bytes with an optional bit-wise mask. When
/// @ref mask is `std::nullopt`, @ref matches performs a byte-wise exact
/// equality check (and rejects length mismatches). When @ref mask is
/// populated, the candidate ATR must have the same length as @ref bytes,
/// and `(candidate[i] & mask[i]) == (bytes[i] & mask[i])` must hold for
/// every byte.
///
/// @par Design rationale
/// Replaces hand-rolled `canHandle` byte loops in every plugin with a
/// single, declarative descriptor. The `std::optional<mask>` shape — rather
/// than a sentinel "all-ones mask" — makes the "no mask, exact match"
/// intent explicit at construction sites and lets the runtime path skip
/// the per-byte AND in the common case (Stroustrup, *A Tour of C++* 3e
/// §13.5: prefer `optional` over sentinel encodings when the absent state
/// is semantically distinct from any value).
///
/// @since 4.0 — the single source of truth for a plugin's ATR set is its
/// @c manifest.json, which a CMake codegen step lowers to a constexpr
/// `kAtrs` array; the plugin's @ref CardPlugin::supportedAtrs override
/// returns a `std::span` over that array.
struct LIBRESCRS_PUBLIC_API Atr
{
    /// @brief Canonical ATR byte sequence advertised by the plugin.
    std::vector<std::uint8_t> bytes;

    /// @brief Optional bit-wise mask paired with @ref bytes.
    ///
    /// @par Length contract
    /// When @ref mask is engaged, its size MUST equal @ref bytes.size().
    /// @ref matches enforces this defensively (returns @c false on length
    /// mismatch) so a misconstructed @ref Atr cannot match an unrelated
    /// candidate, but plugin manifests are expected to honour the
    /// invariant — the codegen step that lowers @c manifest.json into
    /// the constexpr @c kAtrs array preserves the manifest's byte/mask
    /// pairing verbatim. A length mismatch reaching the matcher means
    /// the manifest itself is malformed.
    std::optional<std::vector<std::uint8_t>> mask;

    /// @brief True iff @p candidate matches this descriptor.
    ///
    /// @note Empty-pattern semantics: an @ref Atr with empty @ref bytes
    ///       matches an empty @p candidate (trivially) and rejects every
    ///       non-empty @p candidate (length mismatch). Plugin manifests
    ///       should not register an empty ATR — the empty ATR matches no
    ///       real card — but the matcher's behaviour is well-defined.
    /// @note Mask-length mismatch (`mask->size() != bytes.size()` when
    ///       @ref mask is engaged) yields @c false rather than undefined
    ///       behaviour; see @ref mask for the upstream invariant.
    [[nodiscard]] bool matches(std::span<const std::uint8_t> candidate) const noexcept;

    /// @brief Defaulted exact-equality on (bytes, mask). Distinct from
    ///        @ref matches: this compares two descriptors for identity,
    ///        not a descriptor against a candidate ATR.
    /// @note Provided for test-fixture and container-key uses; per-byte.
    [[nodiscard]] bool operator==(const Atr&) const noexcept = default;
};

/// @brief Structured outcome classification for PIN operations.
enum class PINResultOutcome : std::uint8_t {
    Unspecified,   ///< Default; caller has not classified the outcome.
    Ok,            ///< PIN operation succeeded.
    UserCancelled, ///< User cancelled the credential prompt.
    MissingFields, ///< Provider returned Ok but required fields were absent.
    InvalidPin,    ///< Card rejected the PIN.
    Blocked,       ///< Card reports the PIN is now blocked.
    PluginError,   ///< Plugin-internal error (e.g., APDU failure).
    Unsupported,   ///< Plugin does not implement this PIN flow (default base impl).
};

/// @brief Result of a PIN verify/change/unblock operation.
///
/// @note Use @ref ok to query the success predicate — it is derived from
///       @ref outcome so the two cannot disagree.
struct PINResult
{
    /// @brief Card-reported retries remaining; @c std::nullopt when unknown.
    std::optional<int> retriesLeft;
    /// @brief True if the card now reports the PIN as blocked.
    bool blocked = false;

    /// @brief Structured outcome classification. The @c Unsupported value
    ///        signals that the plugin's default base implementation was
    ///        hit — i.e. the plugin has not overridden the PIN flow.
    ///        Callers can then distinguish "plugin chose not to implement"
    ///        from a genuine operation failure.
    PINResultOutcome outcome = PINResultOutcome::Unspecified;

    /// @brief Success predicate derived from @ref outcome.
    ///
    /// Equivalent to `outcome == PINResultOutcome::Ok`. Provided as a member
    /// so call-sites read uniformly across `PINResult` and `SignResult` even
    /// though the underlying enum differs.
    ///
    /// @since 4.0
    [[nodiscard]] bool ok() const noexcept
    {
        return outcome == PINResultOutcome::Ok;
    }
};

/// @brief Descriptor for a certificate stored on the card.
struct CertificateData
{
    /// @brief Human-readable label (PKCS#15 CDF label, where available).
    std::string label;
    /// @brief Certificate body in DER encoding.
    std::vector<std::uint8_t> derBytes;
    /// @brief File identifier of the matching private key, when known.
    ///
    /// An engaged optional carries a concrete FID; a disengaged optional
    /// means "no private key associated" or "plugin cannot determine the
    /// FID" and the caller should fall back to label-based matching or
    /// mark the cert as verify-only.
    ///
    /// @since 4.0
    std::optional<std::uint16_t> keyFID;
    /// @brief Key size in bits, when known.
    ///
    /// An engaged optional carries the bit-length reported by the card
    /// (typically 1024 / 2048 / 3072 / 4096 for RSA, or 256 / 384 / 521
    /// for ECDSA).
    ///
    /// @since 4.0
    std::optional<std::uint16_t> keySizeBits;

    /// @brief Card-side CKA_ID of this certificate's key/cert pair — the
    ///        PKCS#15 object identifier (iD), which the PKCS#11 bridge surfaces
    ///        verbatim as @c CKA_ID.
    ///
    /// This is the reuse-safe discriminator to hand to
    /// @ref LibreSCRS::Signing::SigningRequest::Builder::keyId so the signing
    /// engine selects THIS exact key — the label is not unique on multi-cert
    /// cards. **Distinct from @ref keyFID**, which is the matching key's *file*
    /// identifier (a different value): @ref keyFID is the on-card file selector,
    /// @ref ckaId is the PKCS#11 object selector used on the in-process signing
    /// path. Empty when the plugin cannot determine the object id (the caller
    /// then falls back to label / auto-select).
    ///
    /// @since 4.3
    std::vector<std::uint8_t> ckaId;

    /// @brief Defaulted member-wise equality.
    [[nodiscard]] bool operator==(const CertificateData&) const noexcept = default;
};

/// @brief Discovered on-card key reference paired with a plugin-defined label.
///
/// Returned from @ref CardPlugin::discoverKeyReferences.
///
/// @since 4.0
struct KeyReference
{
    /// @brief Plugin-defined label (typically a PKCS#15 CDF label or a
    ///        card-specific alias).
    std::string label;
    /// @brief Raw key reference value understood by the plugin's on-card
    ///        signing path.
    std::uint16_t reference = 0;

    /// @brief Defaulted member-wise equality.
    [[nodiscard]] bool operator==(const KeyReference&) const noexcept = default;
};

/// @brief Cryptographic mechanism for on-card signing.
///
/// @note ECDSA alternatives (`ECDSA_SHA256`, `ECDSA_SHA384`, `ECDSA_SHA512`)
///       are reserved in ABI v6 (4.0). Plugins that do not implement ECDSA MUST
///       return `SignResultOutcome::NotImplemented` when called with one of
///       these mechanisms rather than producing an RSA-signed blob.
enum class SignMechanism : std::uint8_t {
    RSA_PKCS,
    /// @brief ECDSA over SHA-256 (NIST P-256 / secp256r1 typical).
    ECDSA_SHA256,
    /// @brief ECDSA over SHA-384 (NIST P-384 / secp384r1 typical).
    ECDSA_SHA384,
    /// @brief ECDSA over SHA-512 (NIST P-521 / secp521r1 typical).
    ECDSA_SHA512,
};

/// @brief Structured outcome for on-card signing.
///
/// Distinguishes "plugin does not implement signing" from a genuine
/// signing failure. A plugin that advertises `CardCapabilities::PKI`
/// but does not override `CardPlugin::sign` returns @ref NotImplemented.
///
/// @since 4.0
enum class SignResultOutcome : std::uint8_t {
    Unspecified,    ///< Default; caller has not classified the outcome.
    Ok,             ///< Signature produced successfully.
    NotImplemented, ///< Plugin base default hit — no `sign()` override.
    PluginError,    ///< Plugin-internal / card-side signing failure.
    /// @brief Cancellation observed via @ref LibreSCRS::CancelToken.
    ///
    /// Returned by the @ref CardPlugin::readCard / @ref CardPlugin::sign
    /// wrapper when the @c token argument reports @c isCancelled() at entry.
    /// PC/SC-backed plugins treat APDU exchange as atomic and do not observe
    /// cancellation mid-operation.
    /// @since 4.0
    Cancelled,
};

/// @brief Result of an on-card signing operation.
///
/// @note Use @ref ok to query the success predicate.
struct SignResult
{
    /// @brief Raw signature bytes (format depends on `SignMechanism`).
    std::vector<std::uint8_t> signature;

    /// @brief Structured outcome classification.
    SignResultOutcome outcome = SignResultOutcome::Unspecified;

    /// @brief Success predicate derived from @ref outcome.
    ///
    /// Equivalent to `outcome == SignResultOutcome::Ok`. Uniform shape with
    /// @ref PINResult::ok so downstream call-sites read the same across
    /// both types.
    ///
    /// @since 4.0
    [[nodiscard]] bool ok() const noexcept
    {
        return outcome == SignResultOutcome::Ok;
    }

    /// @brief Named factory for the cancellation outcome.
    ///
    /// Returned by the NVI @ref CardPlugin::sign wrapper when its
    /// @c token argument reports @c isCancelled() at entry. Keeps the
    /// API surface consistent with other named factories
    /// (@ref ReadResult::ok, @ref ReadResult::communicationError,
    /// @ref ReadResult::parseError).
    ///
    /// @since 4.0
    [[nodiscard]] static SignResult cancelled() noexcept
    {
        SignResult r;
        r.outcome = SignResultOutcome::Cancelled;
        return r;
    }
};

} // namespace LibreSCRS::Plugin

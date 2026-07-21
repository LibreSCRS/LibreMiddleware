// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::CardPlugin — abstract base every card
///        driver plugin `.so` / `.dylib` implements, plus the @ref
///        LibreSCRS::Plugin::CertificateData / @ref
///        LibreSCRS::Plugin::KeyReference aggregates returned by its
///        signing-related methods.

#include <LibreSCRS/Auth/AuthRequirement.h>
#include <LibreSCRS/Auth/SecretParameter.h>
#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/Plugin/ActivationProfile.h>
#include <LibreSCRS/Plugin/CardData.h>
#include <LibreSCRS/Plugin/PinStatusEntry.h>
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <LibreSCRS/Plugin/ReadResult.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// Forward decl — TrustStore is fully declared in <LibreSCRS/Trust/TrustStore.h>;
// this public header keeps it as a forward decl since only shared_ptr<const TrustStore>
// appears in the signature of the optional setTrustStore() method.
namespace LibreSCRS::Trust {
class TrustStore;
}

namespace LibreSCRS::Plugin {

/// @brief Abstract base class implemented by each card-family plugin.
///
/// Plugins are instantiated once by @ref CardPluginService and shared across
/// readers. Methods are @c const with respect to plugin identity and
/// configuration, with the documented exception of the session-keyed mutators
/// @ref setCredentials and @ref clearCredentials (see their Doxygen for the
/// per-session storage invariant).
///
/// @par Thread-safety
/// Plugins are required to be **thread-safe** (see API-POLICY §8): a single
/// @ref CardPlugin instance services all reader sessions in the host process,
/// so plugin implementations MUST be safe under concurrent invocation
/// **from different sessions**. The contract is per-session, not per-plugin:
/// simultaneous calls into the same plugin against
/// distinct @ref LibreSCRS::SmartCard::CardSession objects are required
/// to be well-defined; concurrent calls against the *same* session are
/// the caller's responsibility (see
/// @ref LibreSCRS::SmartCard::CardSession's thread-safety contract).
/// Plugin-internal per-session storage (the @ref setCredentials cache, any
/// session-keyed mutables) MUST be keyed by `&session` (or an equivalent
/// per-session identity) and protected by an internal mutex when updated
/// concurrently — a plugin-scoped map keyed only by a credential label
/// would corrupt cross-session state.
///
/// @note ABI version is @c 8 (see `kCardPluginAbiVersion`). Plugin loaders
///       reject any plugin whose `card_plugin_abi_version()` differs from
///       this value. v7 added the @ref activationProfile / @ref
///       seedCredentials activation virtuals consumed by the @ref readCard
///       NVI wrapper; v8 appends the @ref doDecipher vtable slot
///       (ABI-additive — see the note on @ref decipher).
///
/// Method groups:
///  - Identification (@ref pluginId, @ref displayName, @ref probePriority) — set via @ref setIdentity
///  - Capabilities (@ref capabilities)
///  - Card matching (@ref canHandle, @ref canHandleConnection)
///  - Data reading (@ref readCard — unified, with optional streaming callback)
///  - PKI (@ref readCertificates, PIN, signing, @ref discoverKeyReferences)
///  - Auth (@ref preReadAuth, @ref verifyPIN, @ref changePIN, @ref unblockPIN)
///  - Session credentials (@ref setCredentials, @ref clearCredentials) —
///    non-`const`, mutate per-session storage
class LIBRESCRS_PUBLIC_API CardPlugin
{
public:
    /// @brief Virtual destructor.
    ///
    /// Declared out-of-line (defined in `lib/LibreSCRS/Plugin/CardPlugin.cpp`)
    /// to act as the Itanium-ABI key function for this class. A single
    /// out-of-line virtual method anchors the vtable + typeinfo to one
    /// translation unit (`LibreSCRS_Plugin`); without a key function GCC /
    /// Clang emit both as weak symbols in every TU that instantiates a
    /// derived class, which breaks cross-`.so` `dynamic_cast` and typeinfo
    /// identity under macOS two-level namespaces and Windows dllimport-
    /// consumer builds. See Itanium C++ ABI §5.1.
    virtual ~CardPlugin();

    // -- Identification ------------------------------------------------------

    /// @brief Stable identifier for this plugin (used as @ref CardData::cardType).
    ///
    /// Set once by the derived constructor via @ref setIdentity; never changes
    /// thereafter. The returned reference is valid for the plugin's lifetime.
    [[nodiscard]] const std::string& pluginId() const noexcept
    {
        return pluginIdValue;
    }

    /// @brief Human-readable plugin name.
    ///
    /// Set once by the derived constructor via @ref setIdentity.
    [[nodiscard]] const std::string& displayName() const noexcept
    {
        return displayNameValue;
    }

    /// @brief Ordering hint; lower numeric values are probed first.
    ///
    /// The "highest-priority match" phrase used in
    /// @ref CardPluginService::findPluginForCard means "the plugin with the
    /// smallest @ref probePriority integer among those that report
    /// @ref canHandle true". In other words: lower numbers win.
    ///
    /// Set once by the derived constructor via @ref setIdentity.
    [[nodiscard]] int probePriority() const noexcept
    {
        return probePriorityValue;
    }

    // -- Capabilities --------------------------------------------------------

    /// @brief Return the capability flags supported by this plugin.
    ///
    /// Callers use `hasCapability` to test individual flags.
    [[nodiscard]] virtual CardCapabilities capabilities() const = 0;

    // -- Card matching -------------------------------------------------------

    // Two-phase probe: the fast phase uses ATR bytes only (no card I/O); the
    // fallback phase uses AID selection on a live connection.

    /// @brief All ATRs this plugin claims via static registration.
    ///
    /// Returns a span over the plugin's compile-time ATR table (delivered
    /// by the codegen step from @c manifest.json). Plugins MUST NOT
    /// return dynamically allocated arrays — the registry treats the span
    /// as static-lifetime and may cache it.
    ///
    /// @par Why a span and not a vector
    /// Per Stroustrup, *A Tour of C++* 3e §11.3, `std::span` is the right
    /// non-owning view for a contiguous range whose lifetime is managed
    /// elsewhere. Returning a `vector` here would oblige every caller to
    /// pay an allocation on every probe; returning a `span` over an
    /// inline-defined `kAtrs` array is allocation-free and makes the
    /// "static lifetime" contract explicit at the type level.
    ///
    /// @since 4.0
    [[nodiscard]] virtual std::span<const Atr> supportedAtrs() const noexcept = 0;

    /// @brief Default ATR match — derived from @ref supportedAtrs set
    ///        membership. Final at the base; plugins that need richer
    ///        per-card matching should override @ref canHandleConnection
    ///        instead.
    ///
    /// The signature accepts `std::span<const std::uint8_t>` so existing
    /// `std::vector<std::uint8_t>` callers convert implicitly. Per Meyers,
    /// *Effective Modern C++* Item 13 (prefer non-member, non-friend
    /// functions to member functions when reasonable), this is kept as a
    /// member because the lookup over `supportedAtrs()` is part of the
    /// `CardPlugin` contract — but it is non-virtual final to remove the
    /// override burden from every plugin (NVI, Item 39 of *Effective C++*
    /// 3e: provide a public non-virtual interface that calls a private
    /// virtual implementation).
    ///
    /// @since 4.0
    [[nodiscard]] bool canHandle(std::span<const std::uint8_t> atr) const noexcept;

    /// @brief Fallback match using AID selection on a live connection.
    ///
    /// Called only if @ref canHandle returned false for all plugins. The ATR
    /// bytes observed when the session opened are passed in the first
    /// parameter so plugins that want to combine an AID probe with a
    /// secondary ATR check do not have to re-read the ATR. The second
    /// parameter is the live card session for AID SELECT probing. Default
    /// implementation returns false.
    /// @return @c true if this plugin recognises the card via AID probe;
    ///         @c false otherwise.
    /// @since 4.0
    [[nodiscard]] virtual bool canHandleConnection(std::span<const std::uint8_t> /*atr*/,
                                                   LibreSCRS::SmartCard::CardSession& /*session*/) const
    {
        return false;
    }

    // -- Data reading --------------------------------------------------------

    /// @brief Callback delivering groups progressively as they are read.
    ///
    /// First argument is the plugin's @ref pluginId so the GUI can look up
    /// the correct widget plugin before the final cardDataReady fires.
    using GroupCallback = std::function<void(const std::string& cardType, const CardFieldGroup&)>;

    /// @brief Read and return all card data as a structured @ref ReadResult.
    ///
    /// Public non-virtual entry point (NVI, *Effective C++* 3e Item 39):
    /// observes @p token and short-circuits before dispatching to the
    /// virtual @ref doReadCard implementation when
    /// @ref LibreSCRS::CancelToken::isCancelled() returns true. The
    /// default-constructed token preserves the simple call shape for
    /// uncancellable callers; new callers thread a
    /// @ref LibreSCRS::CancelToken through from a `std::jthread` /
    /// `std::async` / Swift `Task` cancellation source.
    ///
    /// @param session   Live card session.
    /// @param onGroup   Optional streaming callback. When empty (default),
    ///                  the plugin returns all groups at once inside
    ///                  @ref ReadResult::data. When non-empty, the plugin
    ///                  calls @p onGroup for each group as it becomes
    ///                  available; the returned @ref ReadResult::data still
    ///                  carries the full set for the final result when
    ///                  @ref ReadResult::status is @ref ReadResult::Status::Ok.
    /// @param token Cancellation token. Default-constructed = no cancellation.
    ///              The wrapper observes @c token.isCancelled() and short-circuits
    ///              before dispatching to @ref doReadCard. PC/SC-backed plugins
    ///              do not observe cancellation between APDU exchanges (atomic
    ///              transport — @c SCardTransmit cannot be aborted on
    ///              Linux/pcsclite).
    /// @return @ref ReadResult with a status classification. MUST NOT throw —
    ///         plugins catch any internal exception and translate it into a
    ///         @ref ReadResult::communicationError or
    ///         @ref ReadResult::parseError outcome. Exceptions crossing the
    ///         plugin ABI boundary (the plugin is loaded via @c dlopen with
    ///         a potentially-mismatched C++ standard library) are undefined
    ///         behaviour.
    /// @since 4.0
    /// @note NVI wrapper. Plugins override @ref doReadCard instead.
    [[nodiscard]] ReadResult readCard(LibreSCRS::SmartCard::CardSession& session, GroupCallback onGroup = {},
                                      CancelToken token = {}) const;

protected:
    /// @brief Plugin-side implementation of @ref readCard. Operation is treated
    ///        as atomic from a cancellation standpoint; the base wrapper handles
    ///        the only honest cancellation point (pre-dispatch short-circuit).
    ///        Plugins targeting non-PC/SC transports MAY add an additive
    ///        @c CancelToken-taking overload in 4.x without ABI break.
    /// @since 4.0
    [[nodiscard]] virtual ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& session,
                                                GroupCallback onGroup) const = 0;

public:
    // -- PKI -----------------------------------------------------------------

    /// @brief Return all certificates accessible on the card. Default: empty.
    [[nodiscard]] virtual std::vector<CertificateData>
    readCertificates(LibreSCRS::SmartCard::CardSession& /*session*/) const
    {
        return {};
    }
    /// @brief Verify @p pin against the default PIN reference.
    ///
    /// PIN material is carried by @ref LibreSCRS::Secure::String so the
    /// storage is cleansed when the caller's string drops out of scope.
    ///
    /// @param session Live card session.
    /// @param pin     PIN value to verify; cleansed on @p pin destruction.
    /// @return @ref PINResult describing the outcome; @ref PINResult::ok
    ///         returns @c true on successful verification.
    /// @note Safe default: reports PIN verification as unsupported
    ///       (`outcome == PINResultOutcome::Unsupported`) so a plugin that
    ///       forgets to override this entry point can be distinguished from
    ///       a genuine card-side rejection. Plugins that advertise
    ///       `CardCapabilities::PinManagement` MUST override.
    [[nodiscard]] virtual PINResult verifyPIN(LibreSCRS::SmartCard::CardSession& session,
                                              const LibreSCRS::Secure::String& pin) const
    {
        // 4.0 hardening: static_assert sits in the function body, not
        // at namespace scope, so a maintainer who relaxes the parameter to
        // `const std::string&` trips the assertion at the relaxed declaration's
        // own body — not at a sentinel that has no syntactic connection to
        // the changed line.
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(pin)>,
                      "verifyPIN credential parameter must be Secure::String const&");
        (void)session;
        (void)pin;
        PINResult r;
        r.outcome = PINResultOutcome::Unsupported;
        return r;
    }
    /// @brief Return per-PIN status for all PINs exposed by the card.
    [[nodiscard]] virtual std::vector<PinStatusEntry> getPINList(LibreSCRS::SmartCard::CardSession& /*session*/) const
    {
        return {};
    }

    /// @brief Change the PIN identified by @p pinLabel.
    ///
    /// In the 4.0 ABI (v6) plugin callers pass the old and new PIN directly as
    /// @ref LibreSCRS::Secure::String. Orchestration of the credential
    /// prompt is the caller's responsibility (see
    /// @ref Auth::AuthRequirement::forChangePin and the host's
    /// CredentialProvider infrastructure).
    ///
    /// @param session   Live card session.
    /// @param pinLabel  PIN selector (plugin-specific — e.g. "UserPIN",
    ///                  "SignaturePIN", "pin_<reference>"). Labels are not
    ///                  secret material.
    /// @param oldPin    Current PIN value; cleansed on @p oldPin destruction.
    /// @param newPin    New PIN value; cleansed on @p newPin destruction.
    /// @return PINResult describing the outcome.
    /// @note Safe default: reports PIN change as unsupported
    ///       (`outcome == PINResultOutcome::Unsupported`), so a caller that
    ///       reaches the default base implementation can distinguish "plugin
    ///       did not implement changePIN" from a real card-side failure.
    [[nodiscard]] virtual PINResult changePIN(LibreSCRS::SmartCard::CardSession& session, std::string_view pinLabel,
                                              const LibreSCRS::Secure::String& oldPin,
                                              const LibreSCRS::Secure::String& newPin) const
    {
        // 4.0 hardening: see verifyPIN above for rationale.
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(oldPin)>,
                      "changePIN oldPin parameter must be Secure::String const&");
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(newPin)>,
                      "changePIN newPin parameter must be Secure::String const&");
        (void)session;
        (void)pinLabel;
        (void)oldPin;
        (void)newPin;
        PINResult r;
        r.outcome = PINResultOutcome::Unsupported;
        return r;
    }
    /// @brief Card-reported retries remaining for the default PIN.
    ///
    /// Returns @c std::nullopt when the plugin cannot determine the count;
    /// callers should render this as "unknown" rather than a sentinel integer.
    [[nodiscard]] virtual std::optional<int> getPINTriesLeft(LibreSCRS::SmartCard::CardSession& /*session*/) const
    {
        return std::nullopt;
    }
    /// @brief Perform on-card signing with the key identified by @p keyReference.
    ///
    /// Public non-virtual entry point (NVI, *Effective C++* 3e Item 39 —
    /// same rationale as @ref readCard: a public non-virtual interface
    /// dispatching to a protected virtual implementation lets the wrapper
    /// observe @p token and short-circuit before dispatching to
    /// @ref doSign when @ref LibreSCRS::CancelToken::isCancelled() returns true).
    ///
    /// @param session      Live card session.
    /// @param keyReference Raw on-card key reference; obtained from
    ///                     @ref discoverKeyReferences or hard-coded by the
    ///                     plugin per its card-family conventions.
    /// @param data         Bytes to sign. Interpretation (raw vs. hash) is
    ///                     defined by @p mechanism. The wrapper does NOT take
    ///                     ownership of @p data and does NOT zero the buffer
    ///                     on early exit; callers are responsible for
    ///                     cleansing the buffer post-call when its contents
    ///                     are sensitive (4.0 hardening).
    /// @param mechanism    Cryptographic mechanism — see @ref SignMechanism.
    /// @param token Cancellation token. Default = no cancellation. Observed at
    ///              the wrapper for pre-dispatch short-circuit.
    /// @return @ref SignResult whose @ref SignResult::ok evaluates to false on
    ///         any failure. The wrapper sets
    ///         @ref SignResultOutcome::Cancelled for the early short-circuit
    ///         case (since 4.0).
    /// @since 4.0
    /// @note NVI wrapper. Plugins override @ref doSign instead.
    [[nodiscard]] SignResult sign(LibreSCRS::SmartCard::CardSession& session, std::uint16_t keyReference,
                                  std::span<const std::uint8_t> data, SignMechanism mechanism,
                                  CancelToken token = {}) const;

    /// @brief Raw RSA decrypt with the on-card key @p keyReference.
    ///
    /// Public NVI (mirrors @ref sign): the wrapper observes @p token and
    /// short-circuits to @ref DecipherResultOutcome::Cancelled before
    /// dispatching to @ref doDecipher. @p ciphertext is the RSA block to
    /// decrypt; the backend strips PKCS#1 v1.5 padding and returns the
    /// recovered plaintext. The wrapper does NOT cleanse @p ciphertext (it is
    /// not secret) but the RECOVERED plaintext is sensitive — the caller owns
    /// cleansing the returned bytes.
    /// @since 4.3
    /// @note NVI wrapper. Plugins override @ref doDecipher instead.
    [[nodiscard]] DecipherResult decipher(LibreSCRS::SmartCard::CardSession& session, std::uint16_t keyReference,
                                          std::span<const std::uint8_t> ciphertext, DecipherMechanism mechanism,
                                          CancelToken token = {}) const;

protected:
    /// @brief Plugin-side implementation of @ref sign. Operation is treated as
    ///        atomic; the base wrapper handles the pre-dispatch short-circuit.
    /// @since 4.0
    [[nodiscard]] virtual SignResult doSign(LibreSCRS::SmartCard::CardSession& session, std::uint16_t keyReference,
                                            std::span<const std::uint8_t> data, SignMechanism mechanism) const
    {
        (void)session;
        (void)keyReference;
        (void)data;
        (void)mechanism;
        SignResult r;
        r.outcome = SignResultOutcome::NotImplemented;
        return r;
    }

public:
    /// @brief Enumerate on-card key references paired with a plugin-defined
    ///        label.
    ///
    /// @since 4.0
    [[nodiscard]] virtual std::vector<KeyReference>
    discoverKeyReferences(LibreSCRS::SmartCard::CardSession& /*session*/) const
    {
        return {};
    }
    /// @brief Optional token-info group (PKCS#15 TokenInfo, or equivalent).
    [[nodiscard]] virtual CardFieldGroup readTokenInfo(LibreSCRS::SmartCard::CardSession& /*session*/) const
    {
        return {};
    }

    // -- Session credentials -------------------------------------------------

    /// @brief Store an opaque credential on the session for two-phase auth.
    ///
    /// Keys are plugin-specific (e.g. "mrz_doc_number", "can", "mrz_dob",
    /// "mrz_expiry") — not secret. Values are @ref LibreSCRS::Secure::String
    /// so the plugin's stored copy is cleansed on replacement / clear /
    /// destruction.
    ///
    /// @param session Live card session — used as the per-session key for the
    ///                plugin's internal credential storage.
    /// @param key     Plugin-defined credential identifier (not secret).
    /// @param value   Credential value; cleansed on @p value destruction.
    ///
    /// @note Plugin implementations MUST key credential storage by
    ///       `&session` (or an equivalent per-session identity — see
    ///       `LibreSCRS::SmartCard::detail::sessionGeneration` in the
    ///       internal header for the same pattern used elsewhere in the
    ///       middleware). A plugin-scoped map keyed only by the credential
    ///       label would corrupt concurrent multi-session use, since the
    ///       same plugin instance services all reader sessions.
    /// @note If the plugin cannot safely scope credentials per session, it
    ///       SHOULD exclude `CardCapabilities::PinManagement` from its
    ///       @ref capabilities bitfield and leave this method at the
    ///       no-op default.
    /// @note Non-`const` since ABI v6 (4.0). The earlier `const`
    ///       qualifier was cosmetic — plugins held their per-session cache
    ///       in `mutable` members guarded by an internal mutex, which hid
    ///       the mutation from callers. Dropping `const` makes the
    ///       mutation intent explicit; plugins no longer need `mutable`
    ///       storage. The plugin is still expected to make the call
    ///       thread-safe under concurrent use of different sessions.
    virtual void setCredentials(LibreSCRS::SmartCard::CardSession& session, std::string_view key,
                                const LibreSCRS::Secure::String& value)
    {
        // 4.0 hardening: see verifyPIN above for rationale.
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(value)>,
                      "setCredentials value parameter must be Secure::String const&");
        (void)session;
        (void)key;
        (void)value;
    }

    /// @brief Clear any cached credentials for @p session so the next read starts fresh.
    ///
    /// Called when a card is removed or a new card inserted on the same
    /// reader. Non-`const` since ABI v6 (4.0) — see the note on
    /// @ref setCredentials for why.
    virtual void clearCredentials(LibreSCRS::SmartCard::CardSession& /*session*/) noexcept {}

protected:
    // -- Channel activation --------------------------------------------------

    /// @brief Declare the secure-messaging (or plain) channel this plugin
    ///        needs before reading @p session.
    ///
    /// The @ref readCard NVI wrapper consults this once per read: a profile
    /// that @ref ActivationProfile::requiresActivation drives the wrapper's
    /// channel-acquisition path (@ref seedCredentials then
    /// @ref acquireChannelForProfile), keeping the acquired channel alive for
    /// the duration of @ref doReadCard. A plain profile (the default) short-
    /// circuits the wrapper straight to @ref doReadCard with no channel.
    ///
    /// The same profile feeds the @ref preReadAuth derivation, so a plugin
    /// declares its activation requirement in exactly one place.
    ///
    /// @param session Live card session (unused by the default).
    /// @return The activation descriptor; @ref ActivationProfile::plain by
    ///         default (no secure messaging).
    [[nodiscard]] virtual ActivationProfile activationProfile(LibreSCRS::SmartCard::CardSession& /*session*/) const
    {
        return ActivationProfile::plain();
    }

    /// @brief Push any plugin-stored secrets into the session's per-session
    ///        credential cache before channel activation.
    ///
    /// Called by the @ref readCard NVI wrapper immediately before
    /// @ref acquireChannelForProfile, and only when @p profile
    /// @ref ActivationProfile::requiresActivation. Plugins that retain a
    /// secret captured during an earlier prompt (e.g. a CAN entered for a
    /// prior read on the same reader) seed it here so the activation walk
    /// finds it in the cache rather than re-prompting. Default is a no-op for
    /// plugins that carry no retained secrets.
    ///
    /// @par Mutation
    /// May mutate the plugin's per-session store (the same store backing
    /// @ref setCredentials). The method is @c const on the plugin's identity
    /// but is permitted to update session-keyed mutable storage under the
    /// plugin's internal mutex, consistent with the per-session-cache
    /// invariant documented on @ref setCredentials.
    ///
    /// @par Ordering
    /// MUST run before activation so the seeded secrets are visible to
    /// @ref acquireChannelForProfile's cache-or-provider resolution.
    ///
    /// @param session Live card session — the per-session key for any seeded
    ///                credential storage.
    /// @param profile The activation profile about to be driven.
    virtual void seedCredentials(LibreSCRS::SmartCard::CardSession& /*session*/,
                                 const ActivationProfile& /*profile*/) const
    {}

public:
    // -- Pre-read auth / unblock --------------------------------------------

    /// @brief Describe the pre-read authentication this card requires.
    ///
    /// The base derives this from the plugin's @ref activationProfile: a plain
    /// profile reports @ref Auth::PreReadAuthMethod::None; a PACE profile keyed
    /// on a CAN reports @ref Auth::PreReadAuthMethod::PaceCan; any other
    /// activating profile reports @ref Auth::PreReadAuthMethod::BacMrz. Most
    /// plugins therefore declare their requirement once via @ref
    /// activationProfile and leave this method alone.
    ///
    /// @note A plugin that decides its channel requirement at RUNTIME (e.g. a
    ///       generic PKCS#15 plugin that probes the card to tell a plain card
    ///       from a PACE-CAN IAS-ECC SSCD) MAY override this method when the
    ///       static @ref activationProfile derivation would under-report — the
    ///       pkcs15 plugin is the canonical in-tree example, returning PaceCan
    ///       once its probe has established the card needs PACE. Overrides must
    ///       remain consistent with the channel the plugin actually activates.
    ///
    /// @return The unlock method required before data reads.
    ///
    /// Defined out-of-line in @c lib/plugin/src/card_plugin.cpp so the
    /// derivation lives next to the activation machinery it mirrors.
    [[nodiscard]] virtual Auth::PreReadAuthMethod preReadAuth(LibreSCRS::SmartCard::CardSession& session) const;

    /// @brief Unblock @p pinLabel using a PUK-based flow.
    ///
    /// @param session   Live card session.
    /// @param pinLabel  PIN selector (plugin-specific label; not secret).
    /// @param puk       Current PUK value; cleansed on destruction.
    /// @param newPin    New PIN value to install; cleansed on destruction.
    /// @note Safe default: reports unblock as unsupported
    ///       (`outcome == PINResultOutcome::Unsupported`), so cards that do
    ///       not implement PUK-based unblock are distinguishable from a
    ///       genuine card-side failure of an attempted unblock.
    [[nodiscard]] virtual PINResult unblockPIN(LibreSCRS::SmartCard::CardSession& session, std::string_view pinLabel,
                                               const LibreSCRS::Secure::String& puk,
                                               const LibreSCRS::Secure::String& newPin) const
    {
        // 4.0 hardening: see verifyPIN above for rationale.
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(puk)>,
                      "unblockPIN puk parameter must be Secure::String const&");
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(newPin)>,
                      "unblockPIN newPin parameter must be Secure::String const&");
        (void)session;
        (void)pinLabel;
        (void)puk;
        (void)newPin;
        PINResult r;
        r.outcome = PINResultOutcome::Unsupported;
        return r;
    }

    // -- Trust anchors (@since 4.0) ------------------------------------------

    /// @brief Inject the unified trust store the plugin should use for any
    ///        operation that needs trust anchors (e.g. card-data signature
    ///        verification on rs-eid).
    ///
    /// Public NVI; plugins implement @ref doSetTrustStore. The first
    /// successful call sets the @c trustStoreInjected single-shot guard;
    /// subsequent calls are silent no-ops. This enforces the
    /// "single-injection, monotonic store" invariant the design relies on
    /// (see "Re-injection" below) without requiring every plugin override
    /// to police it.
    ///
    /// @par Lifecycle
    /// Called once during plugin lifecycle by @ref CardPluginService
    /// immediately after a successful plugin load, before the plugin is
    /// exposed via @ref CardPluginService::plugins or any candidate-lookup
    /// path. The @ref CardPluginService construction is the only injection
    /// point, so plugins can rely on the pointer being either non-null
    /// (registry was given a TrustStore) or never delivered at all (registry
    /// was constructed without one) — never both, and never twice.
    ///
    /// @par Lifetime
    /// The pointer remains valid for the plugin's lifetime; the plugin must
    /// not drop the shared_ptr until destruction.
    ///
    /// @par Re-injection
    /// Hard-disallowed by the @c trustStoreInjected guard. A second call
    /// returns immediately without re-invoking @ref doSetTrustStore — the
    /// original injection wins.
    ///
    /// @par Mutability of the underlying store
    /// @since 4.0. The trust store handed in here is **monotonically growing**. The
    /// host (typically @ref LibreSCRS::Trust::TrustStoreService) may add
    /// trust anchors to the same store *after* injection — eager
    /// Trusted-List fetches complete asynchronously, and lazy fetches can
    /// land at @c sign() time. Plugins MUST NOT cache
    /// @ref LibreSCRS::Trust::TrustStore::enumerableAnchors() at injection
    /// time and assume immutability. Recommended pattern: query the
    /// TrustStore on each verification need (the cost is bounded by the
    /// store's internal shared-mutex). If a future ABI ships a per-store
    /// observer hook, it will be added on the @ref LibreSCRS::Trust::TrustStore
    /// itself (NOT on this method) so plugins can subscribe directly.
    ///
    /// @since 4.0
    /// @note @c noexcept: the wrapper performs only a single atomic flag
    ///       test-and-set plus an unqualified call to @ref doSetTrustStore,
    ///       which is itself contract-bound noexcept. Plugins whose trust-
    ///       store-acquisition logic could legitimately throw must catch
    ///       internally and surface the failure on the next @c readCard /
    ///       @c sign call as a Status::CommunicationError or equivalent.
    /// @see LibreSCRS::Trust::TrustStore::enumerableAnchors
    /// @see LibreSCRS::Trust::TrustStoreService::addObserver
    ///
    /// Body lives in @c lib/plugin/src/card_plugin.cpp so the public
    /// header carries the declaration only and downstream consumers do
    /// not transitively pull <atomic> through the inline definition.
    void setTrustStore(std::shared_ptr<const LibreSCRS::Trust::TrustStore> trustStore) noexcept;

    /// @brief Override point for @ref setTrustStore.
    ///
    /// Plugins that need trust anchors override this to cache the pointer
    /// for use during @ref readCard or other methods. Default is a no-op
    /// for plugins that have no trust-anchor needs.
    ///
    /// Called at most once per plugin instance — the public
    /// @ref setTrustStore wrapper enforces the single-shot contract.
    ///
    /// @note @c noexcept by contract: the wrapper is noexcept and any
    ///       throw across this boundary is a contract violation. Plugins
    ///       whose acquisition logic could throw must catch internally.
    ///
    /// @since 4.0 (NVI seam introduced).
    virtual void doSetTrustStore(std::shared_ptr<const LibreSCRS::Trust::TrustStore> /*trustStore*/) noexcept {}

protected:
    /// @brief Plugin-side implementation of @ref decipher. Treated as atomic;
    ///        the base wrapper handles the pre-dispatch cancel short-circuit.
    ///
    /// @note Appended as a single new vtable slot in 4.3 (ABI-additive,
    ///       ABI v8) rather than shifting the existing slots. Do not
    ///       relocate it above an existing virtual. Later additions
    ///       (@ref activateTransportPin, @ref activateSigningKey) appended
    ///       after it; the append anchor for future virtuals sits on
    ///       @ref activateSigningKey — the true LAST virtual.
    /// @since 4.3
    [[nodiscard]] virtual DecipherResult doDecipher(LibreSCRS::SmartCard::CardSession& session,
                                                    std::uint16_t keyReference,
                                                    std::span<const std::uint8_t> ciphertext,
                                                    DecipherMechanism mechanism) const
    {
        (void)session;
        (void)keyReference;
        (void)ciphertext;
        (void)mechanism;
        DecipherResult r;
        r.outcome = DecipherResultOutcome::NotImplemented;
        return r;
    }

public:
    // -- Credential lifecycle ------------------------------------------------

    /// @brief Activate a transport-mode PIN: set the holder's value using
    ///        the issuance transport value (card op: CHANGE REFERENCE DATA;
    ///        exact command form is family-specific).
    /// @param session         Live card session.
    /// @param pinLabel        PIN selector (plugin-specific; not secret).
    /// @param transportValue  Transport PIN value; cleansed on destruction.
    /// @param newPin          Holder's new PIN value; cleansed on destruction.
    /// @note Safe default: `PINResultOutcome::Unsupported` (base not overridden).
    /// @since 4.x
    [[nodiscard]] virtual PINResult activateTransportPin(LibreSCRS::SmartCard::CardSession& session,
                                                         std::string_view pinLabel,
                                                         const LibreSCRS::Secure::String& transportValue,
                                                         const LibreSCRS::Secure::String& newPin) const
    {
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(transportValue)>,
                      "activateTransportPin transportValue parameter must be Secure::String const&");
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(newPin)>,
                      "activateTransportPin newPin parameter must be Secure::String const&");
        (void)session;
        (void)pinLabel;
        (void)transportValue;
        (void)newPin;
        PINResult r;
        r.outcome = PINResultOutcome::Unsupported;
        return r;
    }

    /// @brief Activate the (deactivated) signing key: VERIFY the operational
    ///        SIGN PIN and perform the key ACTIVATE, self-contained within
    ///        one locked session/transaction (PIN-ALWAYS lock discipline).
    ///        On success the plugin clears any security state it established
    ///        before returning.
    /// @param session  Live card session.
    /// @param signPin  Operational SIGN PIN; cleansed on destruction.
    /// @return `Ok` on success; `InvalidPin`/`Blocked` when the VERIFY step
    ///         fails (retriesLeft refers to the SIGN PIN);
    ///         `KeyActivationFailed` when VERIFY succeeded but ACTIVATE failed.
    /// @note Safe default: `PINResultOutcome::Unsupported`.
    /// @note Declared as the LAST virtual in the class: future virtuals
    ///       must be appended AFTER this one so every existing vtable
    ///       slot keeps its position (ABI-additive evolution).
    /// @since 4.x
    [[nodiscard]] virtual PINResult activateSigningKey(LibreSCRS::SmartCard::CardSession& session,
                                                       const LibreSCRS::Secure::String& signPin) const
    {
        static_assert(LibreSCRS::Auth::SecretParameter<decltype(signPin)>,
                      "activateSigningKey signPin parameter must be Secure::String const&");
        (void)session;
        (void)signPin;
        PINResult r;
        r.outcome = PINResultOutcome::Unsupported;
        return r;
    }

protected:
    /// @brief Derived classes call this in their ctor to publish identity.
    ///
    /// The accessors (@ref pluginId, @ref displayName, @ref probePriority)
    /// read back what was set here. Cannot be overridden; this is the only
    /// way to populate the identity fields.
    void setIdentity(std::string newId, std::string newName, int newPriority) noexcept
    {
        pluginIdValue = std::move(newId);
        displayNameValue = std::move(newName);
        probePriorityValue = newPriority;
    }

private:
    // Project convention: no trailing underscores on member
    // variables. The `*Value` suffix mirrors the convention already
    // established for `purposeValue` / `fieldList` / `retriesValue` in
    // AuthRequirement.h, and addresses the ergonomic concern that a
    // derived plugin author writing `std::string id;` would otherwise
    // get two `id` members with no diagnostic. The public accessors
    // (@ref pluginId, @ref displayName, @ref probePriority) are unchanged.
    std::string pluginIdValue;
    std::string displayNameValue;
    int probePriorityValue = 0;

    /// Single-shot guard for @ref setTrustStore. test_and_set returns true
    /// iff a previous call has already injected; the wrapper short-circuits
    /// in that case. atomic_flag is the lightest-weight C++ primitive that
    /// gives lock-free single-shot semantics (no atomic<bool> CAS loop).
    /// Default-initialised to the clear state per C++20 §31.7
    /// [atomics.flag]/4 — `ATOMIC_FLAG_INIT` removed: deprecated in C++20,
    /// removed in C++26.
    std::atomic_flag trustStoreInjectedFlag;
};

// 4.0 compile-time audit: every credential-bearing parameter on
// @ref CardPlugin's virtuals is @c Secure::String const&.
//
// One namespace-scope assertion pins the concept itself: "the canonical
// `const Secure::String&` reference satisfies the SecretParameter
// concept". The per-virtual assertions live INSIDE each function body
// (4.0 hardening) — that way a maintainer who relaxes a parameter
// to `const std::string&` trips the assertion at the relaxed declaration's
// own body, not at a sentinel that has no syntactic connection to the
// changed line.
//
// Per Stroustrup, *A Tour of C++* 3e §8.2: concepts replace SFINAE for
// template constraints; static_assert in the function body gives the same
// machine-check guarantee for the concrete API.

static_assert(LibreSCRS::Auth::SecretParameter<decltype(std::declval<const Secure::String&>())>,
              "SecretParameter concept must accept const Secure::String& (canonical credential reference)");

// Every plugin .so must export THREE functions with C linkage:
//   extern "C" LibreSCRS::Plugin::CardPlugin* create_card_plugin() noexcept;
//   extern "C" void destroy_card_plugin(LibreSCRS::Plugin::CardPlugin*) noexcept;
//   extern "C" uint32_t card_plugin_abi_version() noexcept;
//
// The create_card_plugin() return value is a raw pointer to heap-allocated
// storage. Ownership transfers to the caller (the plugin registry wraps it
// in std::shared_ptr<CardPlugin> with a deleter that forwards to
// destroy_card_plugin). Returning a raw pointer — not unique_ptr — keeps the
// entry point compatible with extern "C" linkage. Plugins should
// `return new MyPlugin();` inside the factory.
//
// destroy_card_plugin() MUST destroy the instance inside the plugin's own
// translation unit (typically `delete plugin;`). This pairs the allocator
// with the deleter: when the host application and the plugin are built
// against different C++ standard-library copies, crossing the .so boundary
// with raw `delete` would reach the host's allocator for storage produced
// by the plugin's allocator. Letting the plugin own both construction AND
// destruction eliminates that class of crash. The symbol is noexcept — a
// throwing destructor at unload time would abort the host.
//
// 4.0 ABI v6 requirement: Plugin loaders MUST reject a shared object that does
// not export destroy_card_plugin() as well as the create/version pair.
// See LibreSCRS/Plugin/CardPluginService.h (LoadOutcome::Status).
//
// Convenience: LibreSCRS/Plugin/PluginExport.h provides the
// LIBRESCRS_DECLARE_CARD_PLUGIN(Type, Version) macro that emits all three
// exports (with a compile-time ABI check via static_assert) in one line.
//
// ABI constraint: Plugins MUST be built with the same compiler and C++ standard
// library (libstdc++/libc++) as the host application. The ABI version check
// (kCardPluginAbiVersion) catches interface changes but cannot detect
// compiler or standard library mismatches.
//
// Plugin methods are const with respect to plugin identity and configuration.
// Session state (mutable) may be cached across calls for performance.
// Callers should batch related operations when possible.

} // namespace LibreSCRS::Plugin

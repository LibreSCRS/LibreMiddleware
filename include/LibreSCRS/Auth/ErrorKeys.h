// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief Centralised @ref LibreSCRS::LocalizedText builders for the
///        small set of generic i18n keys that every plugin / signing service
///        falls back to when no card-specific user message is appropriate.
///
/// @par Design rationale
/// 4.0 drops the @c std::optional wrapper from
/// @ref LibreSCRS::Plugin::ReadResult::userMessage,
/// @ref LibreSCRS::Signing::SigningResult::userMessage, and
/// @ref LibreSCRS::SmartCard::OpenError::userMessage. To avoid spreading
/// twenty copies of the same i18n key + English fallback across plugin
/// sources, the small generic-key set lives here. Plugins (and the signing
/// service) that have no card-specific message reach for one of these
/// builders; specific keys (e.g. eMRTD-failed-PACE) live next to the call
/// site as before.
///
/// Per Stroustrup, *A Tour of C++* 3e §16 (utilities): a tightly-scoped
/// header for declarative constants is preferable to a per-call
/// `LocalizedText{...}` literal. The `inline` / `[[nodiscard]]` factories
/// give the optimiser room to elide the construction at the call site while
/// keeping the call-site readable.

#include <LibreSCRS/LocalizedText.h>

#include <cstdint>
#include <string>

namespace LibreSCRS::Auth::ErrorKeys {

/// @brief Generic "card communication failed" message.
[[nodiscard]] inline LocalizedText genericComm()
{
    return LocalizedText{"librescrs.error.communication.generic", "Communication with the card failed.", {}};
}

/// @brief Generic "card returned malformed data" message.
[[nodiscard]] inline LocalizedText genericParse()
{
    return LocalizedText{"librescrs.error.parse.generic", "The card returned data in an unexpected format.", {}};
}

/// @brief Generic "card not supported" message.
[[nodiscard]] inline LocalizedText unsupportedCard()
{
    return LocalizedText{"librescrs.error.unsupported.generic", "This card is not supported.", {}};
}

/// @brief Generic "authentication failed" message.
[[nodiscard]] inline LocalizedText authFailed()
{
    return LocalizedText{"librescrs.error.auth.generic", "Authentication failed.", {}};
}

/// @brief PIN-incorrect message without a retries-left count.
///
/// Use when the card reports a wrong PIN but does NOT report an updated
/// counter (or the plugin chose not to translate it). Distinct from
/// @ref authFailed so the GUI can render PIN-specific affordances
/// (the LC SignPage distinguishes "Wrong PIN" from "Authentication
/// failed" in its retry UI).
/// @since 4.0
[[nodiscard]] inline LocalizedText pinIncorrect()
{
    return LocalizedText{"librescrs.error.auth.pinIncorrect", "The PIN you entered is incorrect.", {}};
}

/// @brief PIN-incorrect message carrying the remaining-tries count.
///
/// The placeholder @c {count} is filled in by the i18n layer at render
/// time. Plugins should use this builder when the card returned a
/// retries-left value (typically via SW1=63 SW2=Cx for ISO 7816-aware
/// cards) — the placeholder lets the GUI render "Wrong PIN — 2 tries
/// remaining" without a translation-time concatenation hack.
/// @since 4.0
[[nodiscard]] inline LocalizedText pinIncorrectWithRetries(int retries)
{
    // Use a typed Count{} placeholder so consumers can apply their host
    // language's plural rule (LocalizedText::Placeholder::Type::Count).
    // Stringifying defeats the placeholder variant discriminator.
    return LocalizedText{"librescrs.error.auth.pinIncorrectWithRetries",
                         "The PIN you entered is incorrect. {count} attempt(s) remaining.",
                         {Placeholder{.name = "count", .value = Count{static_cast<std::int64_t>(retries)}}}};
}

/// @brief PIN-blocked message — card reports retries exhausted.
///
/// Distinct from @ref pinIncorrect because the recovery affordance is
/// different (PUK / unblock workflow, not "try again").
/// @since 4.0
[[nodiscard]] inline LocalizedText pinBlocked()
{
    return LocalizedText{
        "librescrs.error.auth.pinBlocked", "The PIN is blocked. Use the unblock (PUK) workflow to reset it.", {}};
}

/// @brief Generic "operation cancelled" message — used by the NVI wrappers
///        (@ref LibreSCRS::Plugin::CardPlugin::readCard,
///        @ref LibreSCRS::Plugin::CardPlugin::sign) when the @c CancelToken
///        passed to the wrapper reports @c isCancelled() at entry.
[[nodiscard]] inline LocalizedText cancelled()
{
    return LocalizedText{"librescrs.error.cancelled", "The operation was cancelled.", {}};
}

/// @brief Generic "reader unavailable" message.
[[nodiscard]] inline LocalizedText readerUnavailable()
{
    return LocalizedText{"librescrs.error.reader.unavailable", "The card reader is unavailable.", {}};
}

/// @brief Generic "no card present" message.
[[nodiscard]] inline LocalizedText noCardPresent()
{
    return LocalizedText{"librescrs.error.reader.nocard", "No card present in the reader.", {}};
}

/// @brief Generic "reader protocol error" message.
[[nodiscard]] inline LocalizedText protocolError()
{
    return LocalizedText{"librescrs.error.reader.protocol", "Reader protocol negotiation failed.", {}};
}

/// @brief Generic "card read completed" message used by the success
///        factory @ref LibreSCRS::Plugin::ReadResult::ok.
[[nodiscard]] inline LocalizedText readOk()
{
    return LocalizedText{"librescrs.read.ok", "Card read completed successfully.", {}};
}

/// @brief Generic "signing completed" message used by the success factory
///        @ref LibreSCRS::Signing::SigningResult::ok.
[[nodiscard]] inline LocalizedText signOk()
{
    return LocalizedText{"librescrs.sign.ok", "Signing completed successfully.", {}};
}

/// @brief Generic "signing engine error" message.
[[nodiscard]] inline LocalizedText signingEngineError()
{
    return LocalizedText{"librescrs.error.sign.engine", "Signing engine reported an error.", {}};
}

/// @brief Signing failed because the configured Timestamp Authority (TSA)
///        endpoint could not be reached or rejected the request.
///
/// Distinct from @ref signingEngineError so the GUI can surface a
/// network/TSA-specific affordance (retry, switch TSA, fall back to a
/// signature level that doesn't require timestamping).
/// @since 4.1
[[nodiscard]] inline LocalizedText tsaUnreachable()
{
    return LocalizedText{"librescrs.error.sign.tsa_unreachable", "The timestamp authority server is unreachable.", {}};
}

/// @brief Signing failed because the engine could not fetch certificate
///        revocation data (CRL / OCSP) required by the signature level.
/// @since 4.1
[[nodiscard]] inline LocalizedText revocationFetchFailed()
{
    return LocalizedText{
        "librescrs.error.sign.revocation_fetch_failed", "Certificate revocation data could not be fetched.", {}};
}

/// @brief A long-term signature was requested but the signing certificate's
///        chain is incomplete: no Trusted List completed it and the card did
///        not provide a verified full chain, so the revocation evidence the
///        level requires cannot be verified at all. Distinct from
///        @ref revocationFetchFailed — fetching is not the problem and a
///        retry will not help; configuring a Trusted List (or a card with
///        its full chain) is. @since 4.3
[[nodiscard]] inline LocalizedText certificateChainIncomplete()
{
    return LocalizedText{"librescrs.error.sign.certificate_chain_incomplete",
                         "The signing certificate's chain is incomplete; configure a Trusted List or use a card "
                         "that provides its full certificate chain.",
                         {}};
}

/// @brief Signing failed due to a low-level communication or APDU error
///        with the smart card. Distinct from @ref pinIncorrect (wrong PIN)
///        and @ref pinBlocked (PUK workflow) — this covers transport
///        faults, card-removed-mid-operation, and unexpected SW1/SW2
///        responses from the card.
/// @since 4.1
[[nodiscard]] inline LocalizedText cardError()
{
    return LocalizedText{"librescrs.error.sign.card_error", "Smart card communication error during signing.", {}};
}

/// @brief Signing failed because the card rejected the supplied PIN.
///
/// Distinct from @ref pinIncorrect (used during pre-sign authentication)
/// because the signing-time PIN-verify path may need to surface a different
/// affordance (e.g. the wizard's retry step rather than the card-open
/// PIN dialog).
/// @since 4.1
[[nodiscard]] inline LocalizedText pinVerificationFailed()
{
    return LocalizedText{
        "librescrs.error.sign.pin_verification_failed", "The PIN entered for signing is incorrect.", {}};
}

/// @brief Signing failed because the request was malformed or rejected
///        by request validation (e.g. invalid output path, missing
///        required fields, unsupported signature level for the input).
/// @since 4.1
[[nodiscard]] inline LocalizedText invalidRequest()
{
    return LocalizedText{"librescrs.error.sign.invalid_request", "The signing request is invalid.", {}};
}

/// @brief Signing failed because the document to be signed is invalid or
///        unreadable (wrong type, corrupt, unparseable, or empty). The user
///        should check or replace the input file. Distinct from
///        @ref invalidRequest (malformed request parameters) and
///        @ref signingEngineError (unclassified engine fault).
/// @since 4.3
[[nodiscard]] inline LocalizedText invalidDocument()
{
    return LocalizedText{
        "librescrs.error.sign.invalid_document", "The document to be signed is invalid or unreadable.", {}};
}

/// @brief Signing failed because the inputs violate the configured
///        signing policy (e.g. expired certificate at a level that
///        requires fresh revocation, profile-disallowed algorithm).
/// @since 4.1
[[nodiscard]] inline LocalizedText policyViolation()
{
    return LocalizedText{
        "librescrs.error.sign.policy_violation", "The signing request does not satisfy the configured policy.", {}};
}

/// @brief Signing failed because more than one private key on the token
///        matched the requested CKA_ID discriminator, so the signing key
///        could not be resolved unambiguously. The engine refuses rather
///        than sign with an arbitrary match.
/// @since 4.3
[[nodiscard]] inline LocalizedText keyAmbiguous()
{
    return LocalizedText{
        "librescrs.error.sign.key_ambiguous", "The signing key could not be uniquely identified on the card.", {}};
}

/// @brief Generic "trust store unavailable" message.
[[nodiscard]] inline LocalizedText trustStoreUnavailable()
{
    return LocalizedText{"librescrs.error.sign.trustStore", "The trust store is unavailable.", {}};
}

/// @brief Generic "user cancelled" message — distinct from
///        @ref cancelled, which is the asynchronous-token cancellation
///        used by the NVI wrappers; this one signals an explicit user
///        action (closed PIN dialog, declined consent prompt).
[[nodiscard]] inline LocalizedText userCancelled()
{
    return LocalizedText{"librescrs.error.user.cancelled", "Operation cancelled by the user.", {}};
}

/// @brief Generic "credentials collected" success message used by the
///        @ref LibreSCRS::Auth::CredentialResult::ok factory's mandatory
///        userMessage slot. Hosts typically dismiss the prompt before
///        rendering this — the value carries no UX surface — but every
///        4.0 result type carries a non-empty LocalizedText.
[[nodiscard]] inline LocalizedText credentialsCollected()
{
    return LocalizedText{"librescrs.credentials.ok", "Credentials collected.", {}};
}

/// @brief Generic "no plugins installed or all plugins failed" message
///        used by AutoReaderService when the registry reports
///        @ref LibreSCRS::Plugin::CardPluginService::isUsable returns
///        false — surfaces an actionable
///        "no plugins installed / all plugins failed to load"
///        diagnostic instead of an ambiguous "no plugin matched".
[[nodiscard]] inline LocalizedText registryEmpty()
{
    return LocalizedText{"librescrs.error.registry.empty",
                         "No card plugins are installed or all plugins failed to load. "
                         "Check the LibreSCRS installation.",
                         {}};
}

/// @brief Generic "card read failed" message: every candidate plugin's
///        @ref LibreSCRS::Plugin::CardPlugin::readCard returned a
///        non-Ok status. Used by AutoReaderService.
[[nodiscard]] inline LocalizedText cardReadFailed()
{
    return LocalizedText{"librescrs.error.read.allFailed", "Could not read the card.", {}};
}

/// @brief Generic "no compatible plugin" message: the registry is healthy
///        but no plugin's canHandle returned true for this card's ATR.
[[nodiscard]] inline LocalizedText noCompatiblePlugin()
{
    return LocalizedText{"librescrs.error.read.noPlugin", "No installed plugin recognises this card.", {}};
}

/// @brief Generic "pre-read authentication failed" message — BAC/PACE/
///        any pre-card-read security handshake declined the supplied
///        credentials.
[[nodiscard]] inline LocalizedText preReadAuthFailed()
{
    return LocalizedText{
        "librescrs.error.preRead.authFailed", "Card authentication failed before reading could begin.", {}};
}

/// @brief Structural: the document exposes no PACE (EF.CardAccess absent or
///        empty). NOT a wrong-credential condition — consumers must not treat
///        it as one (no credential eviction / retry punishment).
[[nodiscard]] inline LocalizedText paceUnsupported()
{
    return LocalizedText{"librescrs.error.preRead.paceUnsupported", "This document does not support PACE", {}};
}

/// @brief Structural / security: BAC established but the SM-verified
///        EF.CardAccess showed PACE, so activation was aborted (a detected
///        downgrade). NOT a wrong-credential condition — carried on a non-auth
///        failure so flows never evict or punish a credential for an attack
///        signal.
[[nodiscard]] inline LocalizedText paceDowngradeDetected()
{
    return LocalizedText{
        "librescrs.error.preRead.paceDowngradeDetected", "Secure-channel downgrade detected; the read was aborted", {}};
}

/// @brief Generic "DER certificate could not be parsed" message used by
///        @ref Certificate::ParsedCertificate::fromDer when the input
///        is structurally invalid (truncated TLV, unsupported sig algo,
///        bad date / name / public-key blob, etc.). Specific cause flows
///        through @ref ParsedCertificate::ParseError::diagnosticDetail.
/// @since 4.0
[[nodiscard]] inline LocalizedText derInvalid()
{
    return LocalizedText{"librescrs.error.cert.derInvalid", "Certificate data could not be parsed.", {}};
}

/// @brief Generic "trust-store configuration rejected" message used by
///        @ref Trust::TrustStoreService::create when @ref TrustConfig
///        fails validation (nonexistent cache directory, malformed
///        source URL, conflicting flags). Specific cause flows through
///        @ref TrustStoreService::CreateError::diagnosticDetail.
/// @since 4.0
[[nodiscard]] inline LocalizedText trustConfigInvalid()
{
    return LocalizedText{"librescrs.error.trust.configInvalid", "Trust store configuration is invalid.", {}};
}

/// @brief Generic "trust-store allocation failed" message used by
///        @ref Trust::TrustStoreService::create when the underlying
///        constructor throws @c std::bad_alloc. Mostly hypothetical on
///        production hardware but the contract is noexcept.
/// @since 4.0
[[nodiscard]] inline LocalizedText trustAllocationFailed()
{
    return LocalizedText{"librescrs.error.trust.allocationFailed", "Trust store could not be allocated.", {}};
}

} // namespace LibreSCRS::Auth::ErrorKeys

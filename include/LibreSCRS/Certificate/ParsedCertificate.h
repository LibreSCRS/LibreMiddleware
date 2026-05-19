// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Certificate::ParsedCertificate — comprehensive
///        X.509 v3 certificate introspection with typed extension accessors
///        and generic enumeration of all extensions (known or unknown).
///
/// String-encoding policy: every string-typed accessor returns UTF-8.
/// ASN.1 strings (PrintableString, UTF8String, BMPString, IA5String,
/// T.61String, etc.) are converted at parse time.
///
/// OID-fallback principle: #LibreSCRS::Certificate::ObjectIdentifier::dottedDecimal
/// is always populated; #LibreSCRS::Certificate::ObjectIdentifier::friendlyName
/// is best-effort against the LibreSCRS OID database. Callers must treat
/// dottedDecimal as the canonical identifier.
///
/// Malformed-extension robustness: the typed extension accessors return
/// `std::nullopt` on malformed data; raw access via
/// #LibreSCRS::Certificate::ParsedCertificate::extensions and
/// #LibreSCRS::Certificate::ParsedCertificate::findExtension is always
/// available as a fallback.
///
/// OpenSSL is a PRIVATE dependency of `LibreSCRS_Certificate` — this
/// header pulls in no OpenSSL types.
///
/// @par Thread-safety
/// Thread-compatible (see API-POLICY §8). @ref
/// LibreSCRS::Certificate::ParsedCertificate and the auxiliary types
/// declared here are immutable value snapshots after construction (the
/// pimpl-backed implementation copies all parsed fields out of the
/// underlying X509 handle, then drops the OpenSSL handle). Distinct
/// instances are independent; concurrent reads of the same instance are
/// race-free. The factory
/// #LibreSCRS::Certificate::ParsedCertificate::fromDer is a pure function
/// over its input span.
///
/// @since 4.0

#include <LibreSCRS/Certificate/DistinguishedName.h>
#include <LibreSCRS/Certificate/ObjectIdentifier.h>
#include <LibreSCRS/Export.h>
#include <LibreSCRS/LocalizedText.h>

#include <chrono>
#include <cstdint>
#include <expected>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace LibreSCRS::Certificate {

/// @brief X.509 KeyUsage extension bits (RFC 5280 §4.2.1.3).
/// @since 4.0
enum class KeyUsageBit {
    DigitalSignature,
    NonRepudiation,
    KeyEncipherment,
    DataEncipherment,
    KeyAgreement,
    KeyCertSign,
    CRLSign,
    EncipherOnly,
    DecipherOnly
};

/// @brief Public-key algorithm family.
/// @since 4.0
enum class PublicKeyAlgorithm { RSA, ECDSA, EdDSA, Other };

/// @brief Parsed SubjectPublicKeyInfo summary.
/// @since 4.0
struct LIBRESCRS_PUBLIC_API PublicKeyInfo
{
    /// @brief Public-key algorithm family.
    PublicKeyAlgorithm algorithm{PublicKeyAlgorithm::Other};
    /// @brief Effective key length in bits (e.g. 2048 for RSA-2048,
    ///        256 for P-256). Zero if unknown.
    int bitLength{0};
    /// @brief Human-readable algorithm description (e.g. "rsaEncryption",
    ///        "ecPublicKey").
    std::string algorithmDescription;
    /// @brief Public-key algorithm OID as parsed from SubjectPublicKeyInfo.
    ObjectIdentifier algorithmOid;
    /// @brief Named-curve OID for ECDSA/EdDSA keys; empty otherwise.
    std::string curveOid;
};

/// @brief X.509 GeneralName CHOICE type tag (RFC 5280 §4.2.1.6).
/// @since 4.0
enum class GeneralNameType {
    OtherName,
    Rfc822Name,
    DnsName,
    X400Address,
    DirectoryName,
    EdiPartyName,
    UniformResourceIdentifier,
    IpAddress,
    RegisteredId
};

/// @brief One element of a GeneralNames sequence (used for SAN, IAN, CRL DPs,
///        AIA URLs, etc.).
///
/// String-form variants (Rfc822Name, DnsName, URI, IpAddress, RegisteredId)
/// populate #value with a UTF-8 representation. Composite variants
/// (OtherName, X400Address, DirectoryName, EdiPartyName) populate
/// #rawValue with the raw DER bytes; #value remains empty.
/// @since 4.0
struct LIBRESCRS_PUBLIC_API GeneralName
{
    /// @brief CHOICE tag identifying which GeneralName variant this is.
    GeneralNameType type{GeneralNameType::OtherName};
    /// @brief UTF-8 textual form for string-form variants; empty otherwise.
    std::string value;
    /// @brief Raw DER bytes for composite variants where #value is empty.
    std::vector<std::uint8_t> rawValue;
};

/// @brief One X.509 v3 extension as a raw OID + critical flag + DER value.
///
/// Returned by #LibreSCRS::Certificate::ParsedCertificate::extensions and
/// #LibreSCRS::Certificate::ParsedCertificate::findExtension as the
/// universal escape hatch for extensions without a typed accessor.
/// @since 4.0
struct LIBRESCRS_PUBLIC_API Extension
{
    /// @brief Extension type OID (e.g. 2.5.29.15 for KeyUsage).
    ObjectIdentifier oid;
    /// @brief RFC 5280 critical flag.
    bool critical{false};
    /// @brief Raw DER value of the extension's `extnValue` OCTET STRING.
    std::vector<std::uint8_t> value;
};

/// @brief Parsed X.509 v3 certificate with typed accessors for the most
///        common RFC 5280 / PKIX extensions.
///
/// Construct via @ref fromDer; instances are move-only and own a parsed
/// representation of the underlying certificate. Every accessor is
/// const-callable and re-entrant.
/// @since 4.0
class LIBRESCRS_PUBLIC_API ParsedCertificate
{
public:
    /// @brief Failure outcome of @ref fromDer. Mirrors the shape of every
    ///        4.0 public Error type — coarse @ref Kind enum, mandatory
    ///        translator-friendly @ref userMessage, and a dev-facing
    ///        @ref diagnosticDetail.
    /// @since 4.0
    struct ParseError
    {
        /// @brief Failure classification. Append-only — coarse in 4.0;
        ///        finer values added additively in 4.x without breaking.
        enum class Kind : std::uint8_t {
            /// DER input is structurally invalid: truncated, bad TLV,
            /// unsupported sig algo, invalid TBS, unparseable date /
            /// name / public-key blob, etc. Specific cause is in
            /// @ref diagnosticDetail.
            Invalid,
            /// std::bad_alloc caught from one of the parser-side
            /// allocations (Impl construction, originalDer copy). The
            /// noexcept contract converts the throw into a structured
            /// failure rather than propagating across the public ABI
            /// boundary. Mostly hypothetical on production hardware.
            /// @since 4.0 — symmetrises the fromDer noexcept contract
            /// with sibling factories (CardSession::open,
            /// TrustStoreService::create).
            AllocationFailed,
        };

        Kind kind;
        /// @brief Translator-friendly user-facing message. Mandatory.
        LocalizedText userMessage;
        /// @brief Optional dev-facing detail (logs / telemetry only).
        ///        Never carries secret material.
        std::optional<std::string> diagnosticDetail;

        ParseError(Kind k, LocalizedText msg, std::optional<std::string> diag = std::nullopt) noexcept
            : kind(k), userMessage(std::move(msg)), diagnosticDetail(std::move(diag))
        {}

        /// @brief Default construction is deleted — a default-constructed
        ///        @ref LocalizedText would render as an empty string,
        ///        defeating the mandatory-userMessage invariant. Construct
        ///        via the field-wise constructor with an explicit message.
        ParseError() = delete;
    };

    /// @brief Parse a DER-encoded X.509 certificate.
    /// @return On success, the parsed certificate. On failure, a
    /// @ref ParseError carrying the structured diagnostic.
    /// @since 4.0
    /// @par C++23 Idiom
    /// @code
    /// auto cert = ParsedCertificate::fromDer(derBytes);
    /// if (!cert) {
    ///     log("DER invalid: {}", cert.error().userMessage.defaultText);
    ///     return;
    /// }
    /// use(*cert);
    /// @endcode
    [[nodiscard]] static std::expected<ParsedCertificate, ParseError>
    fromDer(std::span<const std::uint8_t> der) noexcept;

    ~ParsedCertificate();
    ParsedCertificate(const ParsedCertificate&) = delete;
    ParsedCertificate& operator=(const ParsedCertificate&) = delete;
    /// @brief Move-construct, transferring ownership of the parsed pimpl.
    ParsedCertificate(ParsedCertificate&&) noexcept;
    /// @brief Move-assign, transferring ownership of the parsed pimpl.
    ParsedCertificate& operator=(ParsedCertificate&&) noexcept;
    /// @brief @c true when the instance owns a parsed certificate (i.e. was
    ///        not moved-from).
    explicit operator bool() const noexcept;

    // Identity
    /// @brief Subject Distinguished Name.
    [[nodiscard]] DistinguishedName subject() const;
    /// @brief Issuer Distinguished Name.
    [[nodiscard]] DistinguishedName issuer() const;
    /// @brief Big-endian serial number bytes (sign bit included per ASN.1 INTEGER).
    [[nodiscard]] std::vector<std::uint8_t> serialNumber() const;
    /// @brief X.509 version number (typically 3 for v3, 1 for v1).
    [[nodiscard]] int version() const;

    // Validity
    /// @brief Validity period start (notBefore).
    [[nodiscard]] std::chrono::system_clock::time_point notBefore() const;
    /// @brief Validity period end (notAfter).
    [[nodiscard]] std::chrono::system_clock::time_point notAfter() const;

    // Signature
    /// @brief OID of the signature algorithm used to sign the certificate.
    [[nodiscard]] ObjectIdentifier signatureAlgorithmOid() const;
    /// @brief Human-readable signature algorithm description (e.g. "sha256WithRSAEncryption").
    [[nodiscard]] std::string signatureAlgorithmDescription() const;
    /// @brief Raw signature value bytes from the certificate.
    [[nodiscard]] std::vector<std::uint8_t> signatureValue() const;

    // Public key
    /// @brief Parsed SubjectPublicKeyInfo (algorithm + bit length + curve).
    [[nodiscard]] PublicKeyInfo publicKey() const;

    // Typed extension accessors — return std::nullopt when extension absent
    // or malformed.
    /// @brief KeyUsage bits (RFC 5280 §4.2.1.3); `std::nullopt` if extension
    ///        absent or malformed.
    [[nodiscard]] std::optional<std::vector<KeyUsageBit>> keyUsage() const;
    /// @brief ExtendedKeyUsage OIDs (RFC 5280 §4.2.1.12); `std::nullopt` if
    ///        absent or malformed.
    [[nodiscard]] std::optional<std::vector<ObjectIdentifier>> extendedKeyUsage() const;
    /// @brief SubjectAltName GeneralNames; `std::nullopt` if absent or malformed.
    [[nodiscard]] std::optional<std::vector<GeneralName>> subjectAlternativeNames() const;
    /// @brief IssuerAltName GeneralNames; `std::nullopt` if absent or malformed.
    [[nodiscard]] std::optional<std::vector<GeneralName>> issuerAlternativeNames() const;

    /// @brief BasicConstraints extension (RFC 5280 §4.2.1.9) decoded form.
    struct BasicConstraints
    {
        /// @brief @c true if the certificate is a CA.
        bool isCa{false};
        /// @brief Maximum number of non-self-issued intermediates that may
        ///        follow this certificate; absent means unconstrained.
        std::optional<int> pathLenConstraint;
    };
    /// @brief BasicConstraints; `std::nullopt` if absent or malformed.
    [[nodiscard]] std::optional<BasicConstraints> basicConstraints() const;

    /// @brief AuthorityKeyIdentifier keyIdentifier bytes; `std::nullopt` if absent.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> authorityKeyIdentifier() const;
    /// @brief SubjectKeyIdentifier bytes; `std::nullopt` if absent.
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> subjectKeyIdentifier() const;
    /// @brief CRL DistributionPoint URI strings; `std::nullopt` if absent.
    [[nodiscard]] std::optional<std::vector<std::string>> crlDistributionPoints() const;
    /// @brief AIA OCSP responder URI strings; `std::nullopt` if absent.
    [[nodiscard]] std::optional<std::vector<std::string>> ocspResponderUrls() const;
    /// @brief AIA caIssuers URI strings; `std::nullopt` if absent.
    [[nodiscard]] std::optional<std::vector<std::string>> caIssuersUrls() const;
    /// @brief CertificatePolicy OIDs; `std::nullopt` if absent.
    [[nodiscard]] std::optional<std::vector<ObjectIdentifier>> certificatePolicies() const;

    // Generic extension access (covers all extensions, known or unknown).
    /// @brief All extensions in the order they appear in the certificate.
    [[nodiscard]] std::vector<Extension> extensions() const;
    /// @brief Find a single extension by OID; first match wins.
    [[nodiscard]] std::optional<Extension> findExtension(const ObjectIdentifier& oid) const;

    // Raw access
    /// @brief Original DER-encoded certificate bytes (read-only span into
    ///        the pimpl-owned buffer; valid for the lifetime of `*this`).
    [[nodiscard]] std::span<const std::uint8_t> derBytes() const;

private:
    ParsedCertificate();

    struct Impl;
    std::unique_ptr<Impl> d;
};

} // namespace LibreSCRS::Certificate

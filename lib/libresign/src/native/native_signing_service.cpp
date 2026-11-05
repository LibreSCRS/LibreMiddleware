// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/native_signing_service.h"
#include "native/signing_key.h"
#include "native/fetch_and_verify_tl.h"
#include "native/trusted_list_parser.h"
#include "native/cades_module.h"
#include "native/pades_module.h"
#include "native/xades_module.h"
#include "native/jades_module.h"
#include "native/asic_module.h"
#include "trust/TrustedListProvider.h"
#include "native_utils.h" // parseCert (X509Ptr RAII) — avoids manual d2i_X509 / X509_free

#include <openssl/cms.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <LibreSCRS/Logging.h>

#include <algorithm>
#include <chrono>
#include <climits>
#include <cstring>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <utility>
#include <LibreSCRS_internal/Crypto/OpenSslPtr.h>
#include <LibreSCRS_internal/Crypto/OpenSslPtrCms.h>

using LibreSCRS::Internal::Crypto::CmsPtr;
using LibreSCRS::Internal::Crypto::X509Ptr;

namespace libresign {

namespace {

constexpr int kTlFetchTimeoutSeconds = 30;

// Sniff signature format from a document's magic, so @ref alreadySignedIn can
// tell whether the document already is a signature in the requested format.
// Order matters: PDF and ZIP are
// disjoint multi-byte magics; JSON (`{`) and DER (0x30) and XML (`<`)
// each occupy one disambiguating leading byte; UTF-8 BOM gates an
// alternative XAdES entry.
std::optional<SignatureFormat> inferFormat(std::span<const uint8_t> prior)
{
    if (prior.size() >= 5 && std::memcmp(prior.data(), "%PDF-", 5) == 0)
        return SignatureFormat::Pades;
    if (prior.size() >= 4 && prior[0] == 'P' && prior[1] == 'K' && prior[2] == 0x03 && prior[3] == 0x04)
        return SignatureFormat::AsicE;
    if (!prior.empty() && prior.front() == '{')
        return SignatureFormat::Jades;
    if (!prior.empty() && prior.front() == 0x30) // ASN.1 SEQUENCE — DER CMS
        return SignatureFormat::Cades;
    if (!prior.empty() && prior.front() == '<')
        return SignatureFormat::Xades;
    if (prior.size() >= 3 && prior[0] == 0xEF && prior[1] == 0xBB && prior[2] == 0xBF)
        return SignatureFormat::Xades;
    return std::nullopt;
}

// Is @p doc a CMS SignedData that already carries at least one signer?
//
// A leading 0x30 is the ASN.1 SEQUENCE tag *and* the ASCII character '0', so
// every CSV, log or text file whose first character is that digit reaches
// here. Only a real parse can tell them apart; a byte test cannot. Errors
// left on the OpenSSL queue by a failed d2i are cleared, because the next
// unrelated opensslError() would otherwise report this parse's failure.
bool isSignedCms(std::span<const uint8_t> doc)
{
    if (doc.empty() || doc.size() > static_cast<size_t>(LONG_MAX))
        return false;

    const unsigned char* p = doc.data();
    CmsPtr cms(d2i_CMS_ContentInfo(nullptr, &p, static_cast<long>(doc.size())));
    if (!cms) {
        ERR_clear_error();
        return false;
    }

    // Returns null for any content type other than signedData.
    STACK_OF(CMS_SignerInfo)* signers = CMS_get0_SignerInfos(cms.get());
    return signers != nullptr && sk_CMS_SignerInfo_num(signers) > 0;
}

// Cheap "looks like an already-signed document of `fmt`" probe used by
// @ref NativeSigningService::sign to route an already-signed XAdES, JAdES or
// ASiC-E document to the format module's appendSigner instead of its sign()
// — which means an already-signed document never reaches the fresh-sign code
// path.
//
// The checks are intentionally substring scans, not full parses:
// inferFormat() has already gated on the magic bytes, so a false
// positive (e.g. an XML document that literally contains "<Signature" but
// no signature element) only redirects to the module's appendSigner, which
// then runs its own strict parse and fails with a targeted failure rather
// than producing a malformed signature.
// CAdES is the exception and does parse: its magic is a single byte that
// ordinary text shares, so a substring scan has nothing to stand on.
bool looksSignedAlready(std::span<const uint8_t> doc, SignatureFormat fmt)
{
    using namespace std::string_view_literals;
    auto sv = std::string_view{reinterpret_cast<const char*>(doc.data()), doc.size()};
    switch (fmt) {
    case SignatureFormat::Pades:
        // Adobe-spec /Type /Sig dictionary marker; both spaced and
        // unspaced forms occur because PDF whitespace is optional
        // between name token and value.
        return sv.find("/Type /Sig"sv) != std::string_view::npos || sv.find("/Type/Sig"sv) != std::string_view::npos;
    case SignatureFormat::AsicE:
        // EN 319 162-1 ASiC-E containers carry signatures under
        // META-INF/signature*.{p7s,xml}. The literal prefix appears
        // verbatim in the central directory entries.
        return sv.find("META-INF/signature"sv) != std::string_view::npos;
    case SignatureFormat::Xades:
        // XAdES is an XML-DSig profile — every signed XAdES document
        // contains at least one <ds:Signature> (canonical prefix) or
        // <Signature> (default-namespace) element.
        return sv.find("<ds:Signature"sv) != std::string_view::npos ||
               sv.find("<Signature"sv) != std::string_view::npos;
    case SignatureFormat::Jades:
        // JWS JSON General has a top-level "signatures" array. Plain
        // (non-signed) JSON inputs that happen to embed the literal
        // "signatures" substring fall through to JAdESModule's strict
        // tryParseJwsGeneral check downstream.
        return sv.find("\"signatures\""sv) != std::string_view::npos;
    case SignatureFormat::Cades:
        // The one arm the magic byte cannot settle: 0x30 is both the DER
        // SEQUENCE tag and ASCII '0'. Parse rather than assume.
        return isSignedCms(doc);
    }
    std::unreachable();
}

// The request's own format, when the document already is a signature in it.
// The request's format is authoritative: the auto-detect is a convenience —
// "this is already a signed document of the format you asked for, so add a
// signer to it" — and must never answer a different question than the caller
// asked. Sniffing the format instead of agreeing with it refuses ordinary
// documents outright: a CSV whose first character is '0' shares its leading
// byte with a DER SEQUENCE, and a JSON payload containing the word
// "signatures" reads as a JWS.
std::optional<SignatureFormat> alreadySignedIn(const SigningRequest& request)
{
    auto fmt = inferFormat(request.document);
    if (fmt == request.format && looksSignedAlready(request.document, *fmt))
        return fmt;
    return std::nullopt;
}

SigningResult cadesInputIsDetached()
{
    return makeFailure(SignFailureKind::InvalidInput,
                       "CAdES input is a detached CMS signature (no embedded payload): it does not carry the "
                       "document it signs, so no signature can be added beside its signers. Sign the original "
                       "document instead.");
}
} // namespace

bool NativeSigningService::configure(const TrustConfig& config)
{
    trustConfig = config;
    tlAnchorCerts.clear(); // rebuilt from the TLs loaded below
    tlTimestampAnchors.clear();
    lazyListsLoaded = false; // and from the deferred ones, when a level needs them

    int eagerCount = 0;
    int successCount = 0;

    for (const auto& entry : config.trustedLists) {
        if (!entry.eager)
            continue;
        ++eagerCount;
        // A list that fails leaves the service degraded, not unconfigured.
        if (loadTrustList(entry))
            ++successCount;
    }

    // Success if at least one TL loaded, or if no TLs were configured (empty list is valid)
    return eagerCount == 0 || successCount > 0;
}

bool NativeSigningService::loadTrustList(const TrustedListEntry& entry)
{
    FetchOptions opts;
    opts.cacheDirectory = trustConfig.cacheDirectory;
    opts.requestTimeout = std::chrono::seconds{kTlFetchTimeoutSeconds};

    // Every verified list hands its anchors over: retained for long-term
    // chain completion (used even when no host emitter is bound, e.g.
    // native-only signing) and emitted to the host, which merges them into
    // the public TrustStore. Inverted-callback shape: libresign extracts
    // anchors, the bridge owns the merge.
    const auto onList = [this](const std::string& /*url*/, const TrustedListInfo& info) {
        auto anchors = extractAnchorsFromTrustedList(info);
        for (const auto& a : anchors)
            if (!a.certificateDer.empty())
                tlAnchorCerts.push_back(a.certificateDer);
        for (auto& der : timestampAuthorityCertificates(info))
            tlTimestampAnchors.push_back(std::move(der));
        if (anchorEmitter)
            anchorEmitter(std::move(anchors));
    };
    const auto onFailure = [](const std::string& url, const std::string& error) {
        LibreSCRS::log::warnf("Trusted List {} skipped: {}", url, error);
    };

    try {
        auto result = fetchTrustedListTree(entry, opts, onList, onFailure);
        if (!result) {
            onFailure(entry.url, result.error);
            return false;
        }
        return true;
    } catch (const std::exception& e) {
        onFailure(entry.url, e.what());
        return false;
    }
}

void NativeSigningService::loadLazyTrustLists()
{
    if (lazyListsLoaded)
        return;
    lazyListsLoaded = true;

    for (const auto& entry : trustConfig.trustedLists) {
        if (entry.eager)
            continue; // configure() already fetched it
        // Degraded, exactly as configure() treats an eager source that
        // fails: the anchor set stays short and the chain gate below
        // refuses with the cause the user can act on.
        (void)loadTrustList(entry);
    }
}

std::optional<SigningResult> NativeSigningService::completeLongTermChain(SigningKey& key, SignatureLevel level)
{
    // Long-term levels (B-LT/B-LTA) embed the full certificate chain. Cards
    // typically carry only the signer cert, so complete the chain from the
    // Trusted-List anchors before any format module reads
    // key.certificateChain(). Fail closed if the issuing CA is not in the
    // configured TL(s): a long-term signature with an unverifiable chain
    // cannot reach the LT validation level. Skipped when no TL is configured
    // (tlAnchorCerts empty) — the chain then stays as the card provided it,
    // and the revocation gate fails closed on any tail the chain cannot prove
    // (an unproven terminal is the chain-incomplete failure, not a silent
    // pass). A signature added to an already-signed document reaches that
    // gate too: XAdES and ASiC-E by delegation — their appendSigner re-enters
    // the same per-format sign path a fresh signature uses (XAdES enveloped
    // calls sign() directly, ASiC-E calls signWithCAdES which calls
    // CAdESModule::sign) — and JAdES directly: its appendSigner runs the same
    // per-signer level ladder its sign() runs, which reaches the gate at
    // B-LT. PAdES adds a signature through its sign() itself. No format
    // bypasses it.
    if (level < SignatureLevel::B_LT)
        return std::nullopt;

    // Past this line the level DOES require an anchor, which is the condition
    // TrustedListSource::eager names for the deferred fetch. Nothing else in
    // the engine is in a position to know it.
    loadLazyTrustLists();

    if (tlAnchorCerts.empty())
        return std::nullopt;

    auto ordered = native_utils::buildOrderedChain(key.certificateChain(), tlAnchorCerts);
    if (ordered.empty())
        return makeFailure(SignFailureKind::EngineError,
                           "long-term signing requires a complete certificate chain, but the signer's "
                           "issuing CA was not found in the configured Trusted List(s)");
    // The ONE place that can assert the anchor termination: buildOrderedChain's
    // only non-empty return ends at a Trusted-List candidate by construction.
    key.setResolvedChain(std::move(ordered), ChainTermination::AnchorTerminated);
    return std::nullopt;
}

std::optional<SigningResult> NativeSigningService::enforceSignerCertPolicy(SigningKey& key,
                                                                           const SigningRequest& request)
{
    // The native backend's CMS path does not intrinsically reject expired
    // signers — check explicitly so `allowExpiredCertificate=false` (the
    // default) behaves consistently with the DSS backend. The flag is the
    // production user-consent opt-in: the host GUI sets it to true only
    // after the user has acknowledged the expired-certificate warning on
    // the signing page. Adding a signer to an already-signed document is
    // signing, and its request carries the same opt-in the user answered for.
    auto certDer = key.certificate();
    if (certDer.empty())
        return std::nullopt;
    auto x509 = native_utils::parseCert(certDer);
    if (!x509)
        return std::nullopt;

    // A certificate not valid yet is never signed with: no consent covers a
    // signature the certificate's own validity puts before its issuance.
    const int fromCmp = X509_cmp_current_time(X509_get0_notBefore(x509.get()));
    if (fromCmp >= 0) // 1 future, 0 malformed
        return makeFailure(SignFailureKind::PolicyViolation, "Signing certificate is not valid yet");

    const int cmp = X509_cmp_current_time(X509_get0_notAfter(x509.get()));
    const bool expired = (cmp <= 0); // -1 past, 0 malformed — treat both as expired
    if (expired && !request.allowExpiredCertificate)
        return makeFailure(SignFailureKind::PolicyViolation, "Signing certificate has expired");
    return std::nullopt;
}

TSAConfig NativeSigningService::timestampConfig(const SigningRequest& request)
{
    auto tsa = request.tsa;
    tsa.crlEnabled = trustConfig.crlEnabled;
    tsa.ocspEnabled = trustConfig.ocspEnabled;
    tsa.trust.anchors.insert(tsa.trust.anchors.end(), tlTimestampAnchors.begin(), tlTimestampAnchors.end());
    tsa.trust.includeSystemTrustStore = trustConfig.includeSystemTrustStore;
    // Called from inside a format module, during this sign: the service
    // outlives it.
    tsa.trust.deferredAnchors = [this] {
        const auto known = tlTimestampAnchors.size();
        loadLazyTrustLists();
        return std::vector<std::vector<uint8_t>>(tlTimestampAnchors.begin() + static_cast<std::ptrdiff_t>(known),
                                                 tlTimestampAnchors.end());
    };
    return tsa;
}

SigningResult NativeSigningService::sign(const SigningRequest& request, SigningKey& key)
{
    try {
        // A document that already carries a signature in the requested
        // format gains one more. PAdES adds it through a PDF incremental
        // update inside PAdESModule::sign; XAdES, JAdES and ASiC-E add the
        // new signer to the signatures the document carries, over the
        // document they recover from it. A CMS SignedData does not carry the
        // document it signs, so there is nothing to sign beside its signers:
        // refuse it before any certificate is judged or Trusted List fetched.
        const bool alreadySigned = alreadySignedIn(request).has_value();
        if (alreadySigned && request.format == SignatureFormat::Cades)
            return cadesInputIsDetached();

        if (auto failure = enforceSignerCertPolicy(key, request))
            return *failure;

        auto tsa = timestampConfig(request);

        if (auto failure = completeLongTermChain(key, request.level))
            return *failure;

        // API-POLICY §9 forward-compat: exhaustive switch, no `default:`,
        // std::unreachable() after — adding a new SignatureFormat value
        // triggers a -Werror=switch-enum compile error here rather than
        // silently returning "Unsupported signature format" at runtime.
        switch (request.format) {
        case SignatureFormat::Cades: {
            CAdESModule cades;
            return cades.sign(request.document, key, request.level, tsa);
        }
        case SignatureFormat::Pades: {
            PAdESModule pades;
            return pades.sign(request.document, key, request.level, tsa, request.visual);
        }
        case SignatureFormat::Xades: {
            XAdESModule xades;
            if (alreadySigned)
                return xades.appendSigner(request.document, {}, request.fileName, key, request.level, tsa);
            return xades.sign(request.document, request.fileName, key, request.level, request.packaging, tsa);
        }
        case SignatureFormat::Jades: {
            JAdESModule jades;
            if (alreadySigned)
                return jades.appendSigner(request.document, {}, request.fileName, key, request.level, tsa);
            return jades.sign(request.document, request.fileName, key, request.level, request.packaging, tsa);
        }
        case SignatureFormat::AsicE: {
            ASiCModule asic;
            if (alreadySigned)
                return asic.appendSigner(request.document, {}, key, request.level, tsa);
            return asic.signWithCAdES(request.document, request.fileName, key, request.level, tsa);
        }
        }
        std::unreachable();
    } catch (const SignFailureException& e) {
        return makeFailure(e.kind, e.what());
    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("Native signing error: ") + e.what());
    }
}

} // namespace libresign

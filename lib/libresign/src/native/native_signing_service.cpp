// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/native_signing_service.h"
#include "native/pkcs11_token.h"
#include "native/trusted_list_parser.h"
#include "native/cades_module.h"
#include "native/pades_module.h"
#include "native/xades_module.h"
#include "native/jades_module.h"
#include "native/asic_module.h"
#include "trust/TrustedListProvider.h"
#include "native_utils.h" // parseCert (X509Ptr RAII) — avoids manual d2i_X509 / X509_free
#include "pinned_tl_certs.h"
#include "tl_cache.h"
#include "tl_signature_verifier.h"

#include <openssl/pem.h>
#include <openssl/x509.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <optional>
#include <stdexcept>
#include <utility>

namespace libresign {

namespace {

constexpr int kMaxTlRecursionDepth = 3;
constexpr int kTlFetchTimeoutSeconds = 30;

// Load a certificate from a file (DER or PEM). Returns DER bytes.
std::vector<uint8_t> loadCertFromFile(const std::string& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file)
        return {};

    std::vector<uint8_t> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    if (data.empty())
        return {};

    // Try DER first: attempt to parse as DER-encoded X.509
    {
        const unsigned char* p = data.data();
        X509Ptr cert(d2i_X509(nullptr, &p, static_cast<long>(data.size())));
        if (cert)
            return data; // Already DER
    }

    // Try PEM: read PEM and convert to DER
    BioPtr bio(BIO_new_mem_buf(data.data(), static_cast<int>(data.size())));
    if (!bio)
        return {};

    X509Ptr cert(PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr));
    if (!cert)
        return {};

    return native_utils::derEncode(static_cast<int (*)(const X509*, unsigned char**)>(i2d_X509), cert.get());
}

// Sniff signature format from prior bytes' magic. Used by @ref
// NativeSigningService::appendSigner — the public API does not carry a
// SignatureFormat for the append path, so the dispatcher infers it from
// the wire shape of the prior signature. Order matters: PDF and ZIP are
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

// Cheap "looks like an already-signed document of `fmt`" probe used by
// @ref NativeSigningService::sign to lift the per-module multi-sign
// auto-detect (previously inside xades_module / jades_module sign()
// paths) up to the service-level dispatcher. When this returns true,
// sign() routes the request to appendSigner instead of the per-format
// sign() — which means an already-signed document never reaches the
// fresh-sign code path through the public API.
//
// The checks are intentionally substring scans, not full parses:
// inferFormat() has already gated on the magic bytes, so a false
// positive (e.g. a PDF whose content stream literally contains the
// "/Type /Sig" octets but has no signature dict) only redirects to
// appendSigner, which then runs its own strict parse and fails with a
// targeted InvalidInput rather than producing a malformed signature.
// CAdES is special-cased: a DER SEQUENCE matched by inferFormat IS by
// definition a signed CMS blob (no "unsigned CAdES" concept), so the
// probe is unconditionally true.
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
        // Any input that inferFormat tagged as CAdES (DER SEQUENCE
        // leading byte) is a signed CMS blob — there is no unsigned
        // CAdES wire shape.
        return true;
    }
    std::unreachable();
}

} // namespace

bool NativeSigningService::configure(const TrustConfig& config)
{
    trustConfig = config;

    TlCache cache(config.cacheDirectory);
    TlSignatureVerifier verifier;

    int eagerCount = 0;
    int successCount = 0;

    for (const auto& entry : config.trustedLists) {
        if (!entry.eager)
            continue;
        ++eagerCount;
        try {
            loadTrustList(entry.url, entry.isLotl, cache, verifier, 0);
            ++successCount;
        } catch (const std::exception&) {
            // Log warning but continue -- degraded mode
        }
    }

    configured = true;
    fullyConfigured = (successCount == eagerCount);

    // Success if at least one TL loaded, or if no TLs were configured (empty list is valid)
    return eagerCount == 0 || successCount > 0;
}

void NativeSigningService::loadTrustList(const std::string& url, bool isLotl, TlCache& cache,
                                         TlSignatureVerifier& verifier, int depth)
{
    if (depth > kMaxTlRecursionDepth)
        return;

    // Locate the TrustConfig entry for this URL up-front: the file:// gating
    // flag (set only when the public TrustConfig::trustedListFile bridge
    // synthesised this entry) lives on the entry, not on the URL alone. The
    // same entry pointer is reused below for the per-entry signing-cert
    // override (see step 3); hoisting the lookup keeps both paths
    // single-source.
    auto entryIt = std::find_if(trustConfig.trustedLists.begin(), trustConfig.trustedLists.end(),
                                [&url](const TrustedListEntry& e) { return e.url == url; });

    // 1. Check cache (HTTP path) or read from disk (file:// path)
    std::vector<uint8_t> xmlData;
    bool freshlyFetched = false;
    std::string responseEtag;
    std::string responseLastModified;

    constexpr std::string_view kFileScheme = "file://";
    const bool localFileBranch = entryIt != trustConfig.trustedLists.end() && entryIt->localFileOnly &&
                                 url.compare(0, kFileScheme.size(), kFileScheme) == 0;

    if (localFileBranch) {
        // When @ref TrustConfig::trustedListFile is populated,
        // the public bridge in @c LibreSCRS::Signing::SigningService::sign
        // synthesises a @ref TrustedListEntry with @c localFileOnly=true and
        // @c url="file://"+path. Read that path directly via std::ifstream,
        // bypassing @ref HttpClient entirely. HttpClient still rejects
        // @c file:// via @c CURLOPT_PROTOCOLS_STR="http,https" — defense in
        // depth ensures @c file:// can never reach the network layer even
        // if a future caller forgets to set @c localFileOnly. Public
        // @c TrustedListSource entries (URL-fetched) leave the flag at the
        // default @c false and stay on the HTTP path.
        const std::string path(url.substr(kFileScheme.size()));
        std::ifstream is(path, std::ios::binary);
        if (!is)
            throw std::runtime_error("Failed to read local TL file: " + path);
        std::vector<uint8_t> buffer((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
        if (buffer.empty())
            throw std::runtime_error("Local TL file is empty: " + path);
        xmlData = std::move(buffer);
        // Local files don't participate in the on-disk cache: the source of
        // truth is the caller-provided file itself. Skip cache.store() below.
    } else {
        auto cached = cache.load(url);
        if (cached) {
            xmlData = std::move(cached->data);
        } else {
            // 2. Cache miss (expired or absent). Try conditional request with stale metadata.
            auto staleMeta = cache.loadMeta(url);
            auto fetchResult = TrustedListParser::fetchRawConditional(
                url, staleMeta ? staleMeta->etag : std::string{}, staleMeta ? staleMeta->lastModified : std::string{},
                kTlFetchTimeoutSeconds);

            if (fetchResult.notModified) {
                // Server confirmed the cached data is still valid — refresh timestamp
                cache.refreshTimestamp(url);
                auto refreshed = cache.load(url);
                if (refreshed) {
                    xmlData = std::move(refreshed->data);
                } else {
                    throw std::runtime_error("Cache refresh failed for TL: " + url);
                }
            } else if (!fetchResult.data.empty()) {
                xmlData = std::move(fetchResult.data);
                responseEtag = std::move(fetchResult.etag);
                responseLastModified = std::move(fetchResult.lastModified);
                freshlyFetched = true;
            } else {
                throw std::runtime_error("Failed to fetch TL from " + url);
            }
        }
    }

    // 3. Find verification cert: user override > pinned > lotlDerived > reject
    std::vector<uint8_t> verificationCertOwned;
    std::span<const uint8_t> signingCert;

    // Check user override from TrustConfig (entryIt resolved at top of fn)
    if (entryIt != trustConfig.trustedLists.end() && !entryIt->signingCertPath.empty()) {
        verificationCertOwned = loadCertFromFile(entryIt->signingCertPath);
        if (!verificationCertOwned.empty()) {
            signingCert = verificationCertOwned;
        }
    }

    if (signingCert.empty()) {
        auto pinnedCert = pinned_certs::pinnedCertForUrl(url);
        if (!pinnedCert.empty()) {
            signingCert = pinnedCert;
        } else {
            auto it = lotlDerivedCerts.find(url);
            if (it != lotlDerivedCerts.end()) {
                signingCert = std::span<const uint8_t>(it->second);
            } else {
                throw std::runtime_error("No verification cert available for TL: " + url);
            }
        }
    }

    // 4. Verify XML-DSig
    if (!verifier.verify(xmlData, signingCert))
        throw std::runtime_error("TL signature verification failed for " + url + ": " + verifier.lastError());

    // 5. Parse authenticated TL
    auto tlInfo = TrustedListParser::parse(xmlData);

    // 6. Emit TL-derived anchors to the host (LibreSCRS::Signing bridge)
    //    which merges them into the public TrustStore eagerly owned by
    //    Trust::TrustStoreService. Inverted-callback shape: libresign
    //    extracts anchors, the bridge owns the merge. No-op when the host
    //    did not bind an emitter via setAnchorEmitter.
    if (anchorEmitter) {
        auto anchors = extractAnchorsFromTrustedList(tlInfo, "tl:" + url);
        anchorEmitter(std::move(anchors), "tl:" + url);
    }

    // 7. Store in cache (only if freshly fetched, not from cache)
    if (freshlyFetched) {
        cache.store(url, xmlData, responseEtag, responseLastModified);
    }

    // 8. For LoTL: follow OtherTSLPointer entries recursively
    if (isLotl) {
        // Store pointer signing certs for child TL verification
        for (const auto& pointer : tlInfo.pointersToOtherTSL) {
            if (!pointer.signingCertDer.empty()) {
                lotlDerivedCerts[pointer.url] = pointer.signingCertDer;
            }
        }

        for (const auto& pointer : tlInfo.pointersToOtherTSL) {
            if (!TrustedListParser::isSafeTslUrl(pointer.url))
                continue; // SSRF protection
            try {
                loadTrustList(pointer.url, false, cache, verifier, depth + 1);
            } catch (const std::exception&) {
                // Continue on failure -- partial TL loading is acceptable
            }
        }
    }
}

bool NativeSigningService::isAvailable() const
{
    return true;
}

SigningResult NativeSigningService::sign(const SigningRequest& request, const std::string& pkcs11ModulePath,
                                         const LibreSCRS::Secure::Buffer& pin, const std::string& keyAlias,
                                         const std::string& readerName,
                                         std::shared_ptr<LibreSCRS::SmartCard::CardSession> sharedSession)
{
    try {
        // Multi-sign auto-detect, lifted from per-module sign() branches.
        //
        // If the input bytes already shape as a signed document in some
        // format, route to appendSigner instead of the per-format sign().
        // Done BEFORE Pkcs11Token construction so a DETACHED-CAdES (which
        // we reject) never opens the card — saves a card session and a
        // potential PIN attempt on inputs that cannot legally multi-sign
        // without an originalDocument.
        //
        // ENVELOPED-capable formats (PAdES, XAdES, JAdES, ASiC-E): the
        // per-format appendSigner extracts the original payload from the
        // prior signature itself, so an empty originalDocument is fine.
        //
        // CAdES is by definition detached — the originalDocument cannot
        // be recovered from a CMS SignedData, so the only path forward
        // is the explicit appendSigner public API. Fail fast with a
        // pointer at that API.
        if (auto fmt = inferFormat(request.document); fmt && looksSignedAlready(request.document, *fmt)) {
            switch (*fmt) {
            case SignatureFormat::Pades:
                // PAdES handles already-signed PDFs natively through the
                // PDF incremental-update mechanism inside PAdESModule::sign.
                // Falling through to the standard sign() path keeps the
                // single Pkcs11Token construction the per-card PKCS#15
                // session-attach flow expects; redirecting to appendSigner
                // would trigger a second bindFromInjectedSession on PACE-
                // gated contactless cards whose AODF read would then
                // return an empty profile and surface as CKR_PIN_INCORRECT.
                break;
            case SignatureFormat::Xades:
            case SignatureFormat::Jades:
            case SignatureFormat::AsicE:
                // Forward sharedSession to the append-signer dispatcher
                // so PACE-protected cards keep their SM channel across
                // the redirected path.
                return appendSigner(request, request.document, {}, pin, pkcs11ModulePath, keyAlias, readerName,
                                    std::move(sharedSession));
            case SignatureFormat::Cades:
                return makeFailure(SignFailureKind::InvalidInput,
                                   "CAdES input is a detached CMS signature (no embedded payload). "
                                   "Use SigningService::appendSigner with the originalDocument argument "
                                   "to add a new signer to a prior CAdES signature.");
            }
        }

        // Single mandatory ctor — legacy slotIndex=-1 / tokenLabel=""
        // auto-pick paths were removed in 4.0 because they silently
        // selected slots[0] under multi-card setups, routing PIN to
        // the wrong card.
        // sharedSession (optional) is forwarded into the loaded
        // librescrs-pkcs11 module via SessionAttachment; null falls
        // through to standalone bind.
        auto token = Pkcs11Token(pkcs11ModulePath, pin, keyAlias, readerName, std::move(sharedSession));

        // Certificate expiry enforcement. The native backend's CMS path
        // does not intrinsically reject expired signers — add an explicit
        // check so `allowExpiredCertificate=false` (the default) behaves
        // consistently with the DSS backend. The flag is the production
        // user-consent opt-in: the host GUI sets it to true only after
        // the user has acknowledged the expired-certificate warning on
        // the signing page.
        {
            auto certDer = token.certificate();
            if (!certDer.empty()) {
                auto x509 = native_utils::parseCert(certDer);
                if (x509) {
                    const int cmp = X509_cmp_current_time(X509_get0_notAfter(x509.get()));
                    const bool expired = (cmp <= 0); // -1 past, 0 malformed — treat both as expired
                    if (expired && !request.allowExpiredCertificate)
                        return makeFailure(SignFailureKind::PolicyViolation, "Signing certificate has expired");
                }
            }
        }

        // Wire trust config to TSA/revocation parameters
        auto tsa = request.tsa;
        tsa.crlEnabled = trustConfig.crlEnabled;
        tsa.ocspEnabled = trustConfig.ocspEnabled;

        // API-POLICY §9 forward-compat: exhaustive switch, no `default:`,
        // std::unreachable() after — adding a new SignatureFormat value
        // triggers a -Werror=switch-enum compile error here rather than
        // silently returning "Unsupported signature format" at runtime.
        switch (request.format) {
        case SignatureFormat::Cades: {
            CAdESModule cades;
            return cades.sign(request.document, token, request.level, tsa);
        }
        case SignatureFormat::Pades: {
            PAdESModule pades;
            return pades.sign(request.document, token, request.level, tsa, request.visual);
        }
        case SignatureFormat::Xades: {
            XAdESModule xades;
            return xades.sign(request.document, request.fileName, token, request.level, request.packaging, tsa);
        }
        case SignatureFormat::Jades: {
            JAdESModule jades;
            return jades.sign(request.document, request.fileName, token, request.level, request.packaging, tsa);
        }
        case SignatureFormat::AsicE: {
            ASiCModule asic;
            return asic.signWithCAdES(request.document, request.fileName, token, request.level, tsa);
        }
        }
        std::unreachable();
    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("Native signing error: ") + e.what());
    }
}

SigningResult NativeSigningService::appendSigner(const SigningRequest& request, std::span<const uint8_t> priorSignature,
                                                 std::span<const uint8_t> originalDocument,
                                                 const LibreSCRS::Secure::Buffer& pin, const std::string& pkcs11Module,
                                                 const std::string& keyAlias, const std::string& readerName,
                                                 std::shared_ptr<LibreSCRS::SmartCard::CardSession> sharedSession)
{
    try {
        auto fmt = inferFormat(priorSignature);
        if (!fmt)
            return makeFailure(SignFailureKind::InvalidInput,
                               "appendSigner: cannot infer signature format from prior bytes");

        // Mirror sign()'s Pkcs11Token construction. sharedSession (when
        // forwarded by the bridge or by the sign() auto-detect redirect)
        // is critical for PACE-protected cards: without it the loaded
        // PKCS#11 module would open a second standalone PC/SC session
        // against the same reader and tear down the active SM channel
        // before C_Login runs.
        auto token = Pkcs11Token(pkcs11Module, pin, keyAlias, readerName, std::move(sharedSession));

        // Wire trust config to TSA/revocation parameters — the new signer
        // inherits the host's CRL/OCSP posture, identical to sign().
        auto tsa = request.tsa;
        tsa.crlEnabled = trustConfig.crlEnabled;
        tsa.ocspEnabled = trustConfig.ocspEnabled;

        switch (*fmt) {
        case SignatureFormat::Pades: {
            PAdESModule pades;
            return pades.appendSigner(priorSignature, originalDocument, token, request.level, tsa, request.visual);
        }
        case SignatureFormat::Cades: {
            CAdESModule cades;
            return cades.appendSigner(priorSignature, originalDocument, token, request.level, tsa);
        }
        case SignatureFormat::Xades: {
            XAdESModule xades;
            return xades.appendSigner(priorSignature, originalDocument, request.fileName, token, request.level, tsa);
        }
        case SignatureFormat::Jades: {
            JAdESModule jades;
            return jades.appendSigner(priorSignature, originalDocument, request.fileName, token, request.level, tsa);
        }
        case SignatureFormat::AsicE: {
            ASiCModule asic;
            return asic.appendSigner(priorSignature, originalDocument, token, request.level, tsa);
        }
        }
        std::unreachable();
    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("Native appendSigner error: ") + e.what());
    }
}

} // namespace libresign

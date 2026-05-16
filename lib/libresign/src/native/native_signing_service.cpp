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
#include <fstream>
#include <stdexcept>

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
                                         std::span<const uint8_t> pin, const std::string& keyAlias,
                                         const std::string& readerName,
                                         std::shared_ptr<LibreSCRS::SmartCard::CardSession> sharedSession)
{
    try {
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
                        return {false, {}, "Signing certificate has expired"};
                }
            }
        }

        // Wire trust config to TSA/revocation parameters
        auto tsa = request.tsa;
        tsa.crlEnabled = trustConfig.crlEnabled;
        tsa.ocspEnabled = trustConfig.ocspEnabled;

        switch (request.format) {
        case SignatureFormat::CAdES: {
            CAdESModule cades;
            return cades.sign(request.document, token, request.level, tsa);
        }
        case SignatureFormat::PAdES: {
            PAdESModule pades;
            return pades.sign(request.document, token, request.level, tsa, request.visual);
        }
        case SignatureFormat::XAdES: {
            XAdESModule xades;
            return xades.sign(request.document, request.fileName, token, request.level, request.packaging, tsa);
        }

        case SignatureFormat::JAdES: {
            JAdESModule jades;
            return jades.sign(request.document, request.fileName, token, request.level, request.packaging, tsa);
        }

        case SignatureFormat::ASiC_E: {
            ASiCModule asic;
            return asic.signWithCAdES(request.document, request.fileName, token, request.level, tsa);
        }
        default:
            return {false, {}, "Unsupported signature format"};
        }
    } catch (const std::exception& e) {
        return {false, {}, std::string("Native signing error: ") + e.what()};
    }
}

} // namespace libresign

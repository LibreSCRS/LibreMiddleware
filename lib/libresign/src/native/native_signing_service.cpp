// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "libresign/native/native_signing_service.h"
#include "libresign/native/pkcs11_token.h"
#include "libresign/native/trusted_list_parser.h"
#include "libresign/native/cades_module.h"
#include "libresign/native/pades_module.h"
#include "libresign/native/xades_module.h"
#include "libresign/native/jades_module.h"
#include "libresign/native/asic_module.h"
#include "libresign/trust_store_manager.h"
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

    // 1. Check cache
    std::vector<uint8_t> xmlData;
    auto cached = cache.load(url);
    bool freshlyFetched = false;
    std::string responseEtag;
    std::string responseLastModified;

    if (cached) {
        xmlData = std::move(cached->data);
    } else {
        // 2. Cache miss (expired or absent). Try conditional request with stale metadata.
        auto staleMeta = cache.loadMeta(url);
        auto fetchResult = TrustedListParser::fetchRawConditional(url, staleMeta ? staleMeta->etag : std::string{},
                                                                  staleMeta ? staleMeta->lastModified : std::string{},
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

    // 3. Find verification cert: user override > pinned > lotlDerived > reject
    std::vector<uint8_t> verificationCertOwned;
    std::span<const uint8_t> signingCert;

    // Check user override from TrustConfig
    auto entryIt = std::find_if(trustConfig.trustedLists.begin(), trustConfig.trustedLists.end(),
                                [&url](const TrustedListEntry& e) { return e.url == url; });
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

    // 6. Extract certificates -> addTlCertificate to TrustStoreManager
    if (trustStoreMgr) {
        for (const auto& service : tlInfo.services) {
            if (!service.certDer.empty()) {
                trustStoreMgr->addTlCertificate(service.certDer);
            }
        }
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
                                         const std::string& tokenLabel)
{
    try {
        auto makeToken = [&]() -> Pkcs11Token {
            if (tokenLabel.empty())
                return Pkcs11Token(pkcs11ModulePath, pin, keyAlias, -1);
            return Pkcs11Token(pkcs11ModulePath, pin, keyAlias, tokenLabel);
        };
        auto token = makeToken();

        // Certificate expiry enforcement. The native backend's CMS path
        // does not intrinsically reject expired signers — add an explicit
        // check so `allowExpiredCertificate=false` (the default) behaves
        // consistently with the DSS backend. The flag is the test-build
        // opt-in used by LibreCelik when the user accepts the
        // expired-cert warning at the signing page.
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

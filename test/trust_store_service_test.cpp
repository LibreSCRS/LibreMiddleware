// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief 4.0 trust-service GREEN test suite.
///
/// Hermetic + integration coverage for @ref TrustStoreService.
///
/// The default-CI tests are network-free and run in <5 s total:
///   * NonThrowingWhenTlUnreachable — degraded-mode contract
///   * ConstructionDoesNotBlockOnSlowDns — non-blocking ctor invariant
///
/// The network-gated test runs only with @c LIBRESIGN_NETWORK_TESTS=1:
///   * LiveSerbianTlEagerFetch — real PKS Class1 anchor over the wire.

#include <LibreSCRS/CancelToken.h>
#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/TsaProvider.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include "signing_test_support/mock_trusted_list_server.h"
#include "Trust/internal/TrustStoreServiceImpl.h"

#include <gtest/gtest.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <unistd.h>
#include <vector>

namespace {

namespace tt = LibreSCRS::Trust;

std::string sha256Hex(const std::vector<std::uint8_t>& bytes)
{
    unsigned int len = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    EVP_Digest(bytes.data(), bytes.size(), digest, &len, EVP_sha256(), nullptr);
    std::ostringstream os;
    os << std::hex << std::setfill('0');
    for (unsigned int i = 0; i < len; ++i)
        os << std::setw(2) << static_cast<int>(digest[i]);
    return os.str();
}

} // namespace

// =============================================================================
// Default-CI tests (no network)
// =============================================================================

namespace {

struct KeyFree
{
    void operator()(EVP_PKEY* key) const
    {
        EVP_PKEY_free(key);
    }
};
struct CertFree
{
    void operator()(X509* cert) const
    {
        X509_free(cert);
    }
};
using KeyPtr = std::unique_ptr<EVP_PKEY, KeyFree>;
using CertPtr = std::unique_ptr<X509, CertFree>;

void addExtension(X509* cert, int nid, const char* value)
{
    X509V3_CTX ctx;
    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, nullptr, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ext = X509V3_EXT_conf_nid(nullptr, &ctx, nid, value);
    ASSERT_NE(ext, nullptr);
    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
}

// CN=subjectCn issued by CN=issuerCn; a CA certificate carries the basic
// constraints and key usage a chain verifier requires of an issuer.
CertPtr issueCertificate(const char* subjectCn, const char* issuerCn, EVP_PKEY* subjectKey, EVP_PKEY* issuerKey,
                         bool isCa, long serial)
{
    CertPtr cert(X509_new());
    X509_set_version(cert.get(), 2);
    ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);
    X509_gmtime_adj(X509_getm_notBefore(cert.get()), -3600);
    X509_gmtime_adj(X509_getm_notAfter(cert.get()), 60L * 60 * 24 * 365);
    X509_set_pubkey(cert.get(), subjectKey);
    X509_NAME_add_entry_by_txt(X509_get_subject_name(cert.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(subjectCn), -1, -1, 0);
    X509_NAME_add_entry_by_txt(X509_get_issuer_name(cert.get()), "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(issuerCn), -1, -1, 0);
    if (isCa) {
        addExtension(cert.get(), NID_basic_constraints, "critical,CA:TRUE");
        addExtension(cert.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    }
    X509_sign(cert.get(), issuerKey, EVP_sha256());
    return cert;
}

std::vector<std::uint8_t> toDer(X509* cert)
{
    const int len = i2d_X509(cert, nullptr);
    if (len <= 0)
        return {};
    std::vector<std::uint8_t> der(static_cast<std::size_t>(len));
    std::uint8_t* out = der.data();
    i2d_X509(cert, &out);
    return der;
}

} // namespace

// A Trusted List names a subordinate CA as often as a self-signed root. The
// store holds such an anchor as it is: a chain that ends at it is trusted
// without a root the store does not have, and a chain that ends at a sibling
// the store does not hold is still not.
TEST(TrustStoreValidateChain, AChainEndingAtASubordinateAnchorIsTrusted)
{
    KeyPtr rootKey(EVP_EC_gen("P-256"));
    KeyPtr subKey(EVP_EC_gen("P-256"));
    KeyPtr otherSubKey(EVP_EC_gen("P-256"));
    KeyPtr leafKey(EVP_EC_gen("P-256"));
    ASSERT_TRUE(rootKey && subKey && otherSubKey && leafKey);

    auto sub = issueCertificate("Synthetic Subordinate CA", "Synthetic Root CA", subKey.get(), rootKey.get(), true, 2);
    auto otherSub =
        issueCertificate("Synthetic Sibling CA", "Synthetic Root CA", otherSubKey.get(), rootKey.get(), true, 3);
    auto leaf = issueCertificate("Synthetic Signer", "Synthetic Subordinate CA", leafKey.get(), subKey.get(), false, 4);
    auto strayLeaf =
        issueCertificate("Synthetic Stray Signer", "Synthetic Sibling CA", leafKey.get(), otherSubKey.get(), false, 5);
    ASSERT_TRUE(sub && otherSub && leaf && strayLeaf);
    const auto subDer = toDer(sub.get());
    const auto otherSubDer = toDer(otherSub.get());
    const auto leafDer = toDer(leaf.get());
    const auto strayLeafDer = toDer(strayLeaf.get());

    // The store's only anchor: the subordinate CA, whose issuer it never sees.
    const auto certsDir =
        std::filesystem::temp_directory_path() / ("lm-subordinate-anchor-" + std::to_string(::getpid()));
    std::filesystem::remove_all(certsDir);
    std::filesystem::create_directories(certsDir);
    std::ofstream(certsDir / "subordinate-ca.cer", std::ios::binary)
        .write(reinterpret_cast<const char*>(subDer.data()), static_cast<std::streamsize>(subDer.size()));
    ::setenv("LIBRESCRS_CERTIFICATES_DIR", certsDir.c_str(), 1);

    auto service = tt::TrustStoreService::create(tt::TrustConfig{});
    ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
    std::filesystem::remove_all(certsDir);
    ASSERT_TRUE(service.has_value());
    auto store = (*service)->trustStore();
    ASSERT_NE(store, nullptr);

    const auto anchors = store->enumerableAnchors();
    ASSERT_EQ(anchors.size(), 1U);
    ASSERT_EQ(anchors.front().certificateDer, subDer);

    using Status = tt::TrustStore::ChainStatus;
    const std::vector<tt::CertificateView> withAnchor{leafDer, subDer};
    EXPECT_EQ(store->validateChain(withAnchor), Status::Trusted);
    const std::vector<tt::CertificateView> leafOnly{leafDer};
    EXPECT_EQ(store->validateChain(leafOnly), Status::Trusted);

    const std::vector<tt::CertificateView> throughSibling{strayLeafDer, otherSubDer};
    EXPECT_EQ(store->validateChain(throughSibling), Status::UntrustedRoot);
}

namespace {

// A root this host's CA bundle carries and that is valid now, read
// independently of the library: the test names the bundles it knows itself.
std::vector<std::uint8_t> currentRootFromTheHostBundle()
{
    for (const char* bundle : {"/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt",
                               "/etc/ssl/ca-bundle.pem", "/etc/ssl/cert.pem"}) {
        std::FILE* f = std::fopen(bundle, "r");
        if (f == nullptr)
            continue;
        std::vector<std::uint8_t> der;
        while (X509* cert = PEM_read_X509(f, nullptr, nullptr, nullptr)) {
            CertPtr owned(cert);
            if (X509_cmp_current_time(X509_get0_notAfter(cert)) > 0 &&
                X509_cmp_current_time(X509_get0_notBefore(cert)) < 0 && X509_check_issued(cert, cert) == X509_V_OK) {
                der = toDer(cert);
                break;
            }
        }
        std::fclose(f);
        if (!der.empty())
            return der;
    }
    return {};
}

} // namespace

// "Include the system trust store" means the CAs this host trusts, without
// SSL_CERT_FILE / SSL_CERT_DIR naming them: the bundled OpenSSL's own default
// directory holds none.
TEST(TrustStoreValidateChain, ARootTheHostTrustsIsTrustedWithoutAnEnvironmentOverride)
{
    const auto rootDer = currentRootFromTheHostBundle();
    if (rootDer.empty())
        GTEST_SKIP() << "no CA bundle at a well-known path on this host";

    struct RestoreEnv
    {
        std::string name;
        std::optional<std::string> value;
        ~RestoreEnv()
        {
            if (value)
                ::setenv(name.c_str(), value->c_str(), 1);
            else
                ::unsetenv(name.c_str());
        }
    };
    auto saved = [](const char* name) {
        const char* v = std::getenv(name);
        return RestoreEnv{name, v != nullptr ? std::optional<std::string>(v) : std::nullopt};
    };
    const RestoreEnv keepFile = saved("SSL_CERT_FILE");
    const RestoreEnv keepDir = saved("SSL_CERT_DIR");
    ::unsetenv("SSL_CERT_FILE");
    ::unsetenv("SSL_CERT_DIR");

    // No bundled anchors: whatever trusts the root comes from the system store.
    const auto certsDir = std::filesystem::temp_directory_path() / ("lm-system-store-" + std::to_string(::getpid()));
    std::filesystem::remove_all(certsDir);
    std::filesystem::create_directories(certsDir);
    ::setenv("LIBRESCRS_CERTIFICATES_DIR", certsDir.c_str(), 1);
    auto service = tt::TrustStoreService::create(tt::TrustConfig{});
    ::unsetenv("LIBRESCRS_CERTIFICATES_DIR");
    std::filesystem::remove_all(certsDir);
    ASSERT_TRUE(service.has_value());
    auto store = (*service)->trustStore();
    ASSERT_NE(store, nullptr);

    using Status = tt::TrustStore::ChainStatus;
    const std::vector<tt::CertificateView> chain{rootDer};
    EXPECT_EQ(store->validateChain(chain), Status::Trusted);
}

TEST(TrustStoreServiceTest, NonThrowingWhenTlUnreachable)
{
    tt::TrustConfig cfg;
    tt::TrustedListSource src;
    src.url = "https://invalid.example.invalid/tl.xml";
    src.lotl = false;
    src.eager = true;
    cfg.trustedListSources.push_back(src);

    auto result = tt::TrustStoreService::create(std::move(cfg));
    ASSERT_TRUE(result.has_value());
    auto svc = *result;

    // Bundled + system anchors populate the store while the fetch fails;
    // the service is usable rather than asserting an exact anchor count
    // (system store size varies across distros). Releasing it joins the
    // worker whether or not its fetch has failed yet.
    EXPECT_NE(svc->trustStore(), nullptr);
    svc.reset();
}

TEST(TrustStoreServiceTest, ConstructionDoesNotBlockOnSlowDns)
{
    tt::TrustConfig cfg;
    tt::TrustedListSource src;
    src.url = "https://slow.example.invalid/tl.xml";
    src.eager = true;
    cfg.trustedListSources.push_back(src);

    const auto t0 = std::chrono::steady_clock::now();
    auto result = tt::TrustStoreService::create(std::move(cfg));
    const auto elapsed = std::chrono::steady_clock::now() - t0;
    ASSERT_TRUE(result.has_value());
    auto svc = *result;

    EXPECT_LT(elapsed, std::chrono::milliseconds(500))
        << "TrustStoreService::create() must not block on network IO; elapsed="
        << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms";
}

// =============================================================================
// loadTrustedLists: the configured sources reach the store through the
// service, a source that failed in any part is tried again, and a list the
// cache already holds is not downloaded again. A loopback server serves the
// signed synthetic list and counts the downloads; the service is told the
// list's test signing certificate through its test hook (the public
// configuration names none for a loopback URL, and no pinned certificate
// covers it).
// =============================================================================

namespace {

std::filesystem::path freshDir(const std::string& tag)
{
    static int counter = 0;
    auto dir = std::filesystem::temp_directory_path() /
               ("librescrs-" + tag + "-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    return dir;
}

struct TrustedListRig
{
    TrustedListRig() : server(std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/synthetic-tl.xml") {}
    ~TrustedListRig()
    {
        std::error_code ec;
        for (const auto& dir : dirs)
            std::filesystem::remove_all(dir, ec);
    }

    std::shared_ptr<tt::TrustStoreService> service(bool eager, std::optional<std::filesystem::path> cacheDir,
                                                   bool knowsTheSigner = true)
    {
        tt::TrustConfig cfg;
        tt::TrustedListSource src;
        src.url = server.url();
        src.eager = eager;
        cfg.trustedListSources.push_back(src);
        cfg.cacheDirectory = std::move(cacheDir);
        auto result = tt::TrustStoreService::create(std::move(cfg));
        EXPECT_TRUE(result.has_value());
        if (!result)
            return nullptr;
        if (knowsTheSigner)
            teachTheSigner(**result);
        return *result;
    }

    static void teachTheSigner(tt::TrustStoreService& svc)
    {
        tt::detail::TrustStoreServiceAccess::impl(svc).entryHook = [](libresign::TrustedListEntry& entry) {
            entry.signingCertPath = std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/test-tl-signing-cert.pem";
        };
    }

    std::filesystem::path cache(const std::string& tag)
    {
        dirs.push_back(freshDir(tag));
        return dirs.back();
    }

    libresign::test::MockTrustedListServer server;
    std::vector<std::filesystem::path> dirs;
};

std::size_t anchorCount(tt::TrustStoreService& svc)
{
    return svc.trustStore()->enumerableAnchors().size();
}

} // namespace

TEST(TrustStoreServiceTest, ADeferredListsAnchorsReachTheStore)
{
    TrustedListRig rig;
    auto svc = rig.service(/*eager=*/false, rig.cache("deferred"));
    ASSERT_NE(svc, nullptr);
    const auto before = anchorCount(*svc);
    EXPECT_EQ(rig.server.servedCount(), 0) << "a deferred source is left alone at construction";

    svc->loadTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(rig.server.servedCount(), 1);
    EXPECT_GT(anchorCount(*svc), before) << "the verified list's anchors are in the store";

    const auto after = anchorCount(*svc);
    svc->loadTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(rig.server.servedCount(), 1) << "a loaded source is not fetched again";
    EXPECT_EQ(anchorCount(*svc), after);
}

TEST(TrustStoreServiceTest, AFailedLoadIsTriedAgain)
{
    TrustedListRig rig;
    // The list does not verify (the service has no certificate for it yet):
    // nothing reaches the store, and the source stays pending.
    auto svc = rig.service(/*eager=*/false, rig.cache("retry"), /*knowsTheSigner=*/false);
    ASSERT_NE(svc, nullptr);
    const auto before = anchorCount(*svc);
    svc->loadTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(anchorCount(*svc), before);

    TrustedListRig::teachTheSigner(*svc);
    svc->loadTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_GT(anchorCount(*svc), before) << "the failed source was tried again and loaded";
}

TEST(TrustStoreServiceTest, ACancelledLoadFetchesNothingAndIsTriedAgain)
{
    TrustedListRig rig;
    auto svc = rig.service(/*eager=*/false, rig.cache("cancel"));
    ASSERT_NE(svc, nullptr);
    const auto before = anchorCount(*svc);
    LibreSCRS::CancelSource cancel;
    cancel.requestCancel();

    svc->loadTrustedLists(tt::TrustStoreService::Sources::All, cancel.token());
    EXPECT_EQ(rig.server.servedCount(), 0);

    svc->loadTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(rig.server.servedCount(), 1);
    EXPECT_GT(anchorCount(*svc), before);
}

TEST(TrustStoreServiceTest, AnEagerSourceWhoseBackgroundFetchFailedIsLoadedLater)
{
    TrustedListRig rig;
    // Built without the certificate: the background fetch cannot verify.
    auto svc = rig.service(/*eager=*/true, rig.cache("eager"), /*knowsTheSigner=*/false);
    ASSERT_NE(svc, nullptr);
    const auto before = anchorCount(*svc);
    TrustedListRig::teachTheSigner(*svc);

    svc->loadTrustedLists(tt::TrustStoreService::Sources::Eager);
    EXPECT_GT(anchorCount(*svc), before) << "the eager source the background fetch missed is in the store";
}

TEST(TrustStoreServiceTest, AListTheCacheHoldsIsNotDownloadedAgain)
{
    // What the signing engine downloads goes to the cache the two share; the
    // service adopts it from there.
    TrustedListRig rig;
    const auto shared = rig.cache("shared");
    auto first = rig.service(/*eager=*/false, shared);
    ASSERT_NE(first, nullptr);
    first->loadTrustedLists(tt::TrustStoreService::Sources::All);
    ASSERT_EQ(rig.server.servedCount(), 1);

    auto second = rig.service(/*eager=*/false, shared);
    ASSERT_NE(second, nullptr);
    const auto before = anchorCount(*second);
    second->loadTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(rig.server.servedCount(), 1) << "read from the cache, not downloaded";
    EXPECT_GT(anchorCount(*second), before);
}

TEST(TrustStoreServiceTest, WithoutACacheDirectoryTheServiceKeepsItsOwn)
{
    TrustedListRig rig;
    std::filesystem::path privateDir;
    {
        auto svc = rig.service(/*eager=*/false, std::nullopt);
        ASSERT_NE(svc, nullptr);
        ASSERT_TRUE(svc->config().cacheDirectory.has_value())
            << "the engine needs a directory to share with the service";
        privateDir = *svc->config().cacheDirectory;
        EXPECT_TRUE(std::filesystem::is_directory(privateDir));
        svc->loadTrustedLists(tt::TrustStoreService::Sources::All);
        EXPECT_EQ(rig.server.servedCount(), 1);
    }
    EXPECT_FALSE(std::filesystem::exists(privateDir)) << "the private cache goes with the service";
}

// =============================================================================
// Compile-time check: SigningService::trustStore() must not exist anymore.
// =============================================================================

TEST(SigningServiceCompileTime, NoTrustStoreGetter)
{
    // The static_assert here is templated to keep the test SFINAE-friendly:
    // requires-expressions evaluated unconditionally inside a TEST body would
    // attempt to instantiate the member access regardless of substitution.
    auto noGetter = [](auto* svc) { return !requires { svc->trustStore(); }; };
    LibreSCRS::Signing::SigningService* nullSvc = nullptr;
    static_assert(std::is_invocable_v<decltype(noGetter), decltype(nullSvc)>,
                  "noGetter helper must be invocable on SigningService*");
    EXPECT_TRUE(noGetter(nullSvc)) << "SigningService::trustStore() must remain removed";
}

// =============================================================================
// Network-gated integration test.
// =============================================================================

TEST(TrustStoreServiceTest, LiveSerbianTlEagerFetch)
{
    const char* netTests = std::getenv("LIBRESIGN_NETWORK_TESTS");
    if (!netTests || std::string(netTests) != "1")
        GTEST_SKIP() << "Set LIBRESIGN_NETWORK_TESTS=1 to run network integration tests";

    auto cacheDir = std::filesystem::temp_directory_path() / "libresign_trust_store_service_test";
    std::filesystem::remove_all(cacheDir);
    // Recreate the directory: 4.0 TrustStoreService::create rejects a
    // cacheDirectory that does not exist via InvalidConfig.
    std::filesystem::create_directories(cacheDir);

    tt::TrustConfig cfg;
    tt::TrustedListSource src;
    src.url = "https://www.mit.gov.rs/TrustedList/TSL-RS.xml";
    src.lotl = false;
    src.eager = true;
    cfg.trustedListSources.push_back(src);
    cfg.cacheDirectory = cacheDir;

    auto result = tt::TrustStoreService::create(std::move(cfg));
    ASSERT_TRUE(result.has_value());
    auto svc = *result;

    // The anchor joins the store when the eager fetch verifies the list.
    bool found = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (!found && std::chrono::steady_clock::now() < deadline) {
        for (const auto& a : svc->trustStore()->enumerableAnchors()) {
            if (sha256Hex(a.certificateDer).rfind("78fb87f5", 0) == 0) {
                found = true;
                break;
            }
        }
        if (!found)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    EXPECT_TRUE(found) << "PKS CA Class1 (SHA-256 78fb87f5...) must appear in the public store";

    std::error_code ec;
    std::filesystem::remove_all(cacheDir, ec);
}

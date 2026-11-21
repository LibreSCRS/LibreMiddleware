// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief The trust store service's Trusted List loading, against signed
///        lists served on loopback.
///
/// Runs on the service's test copy (LibreSCRS_TrustService_ForTests), the only
/// build that can verify a list under the test signing certificate.

#include <LibreSCRS/Auth/CredentialResult.h>
#include <LibreSCRS/Signing/SigningRequest.h>
#include <LibreSCRS/Signing/SigningService.h>
#include <LibreSCRS/Signing/TsaProvider.h>
#include <LibreSCRS/SmartCard/testing/CardSessionTesting.h>
#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include "signing_test_support/mock_trusted_list_server.h"
#include "soft_key_plugin.h"
#include "trust_service_test_seam.h"
#include "Trust/internal/TrustStoreServiceImpl.h"
#include <native/tl_cache.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <unistd.h>
#include <vector>

namespace tt = LibreSCRS::Trust;

// =============================================================================
// Loading: the eager worker downloads a configured source into the cache and
// merges its anchors; adoptCachedTrustedLists() brings in what the cache holds
// without a download, and a source that failed stays pending. A loopback
// server serves the signed synthetic list and counts the downloads; the
// service's test copy is told the list's test signing certificate (the public
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
    TrustedListRig() : server(std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/synthetic-tl.xml")
    {
        tt::Testing::setTrustedListSigningCertificate({});
    }
    ~TrustedListRig()
    {
        tt::Testing::setTrustedListSigningCertificate({});
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
        // Named before create(): the eager worker starts there.
        if (knowsTheSigner)
            teachTheSigner();
        auto result = tt::TrustStoreService::create(std::move(cfg));
        EXPECT_TRUE(result.has_value());
        if (!result)
            return nullptr;
        return *result;
    }

    static void teachTheSigner()
    {
        tt::Testing::setTrustedListSigningCertificate(std::string(CMAKE_SOURCE_DIR) +
                                                      "/test/fixtures/trust/test-tl-signing-cert.pem");
    }

    std::filesystem::path cache(const std::string& tag)
    {
        dirs.push_back(freshDir(tag));
        return dirs.back();
    }

    libresign::test::MockTrustedListServer server;
    std::vector<std::filesystem::path> dirs;
};

// Waits for the eager workers started at construction to finish.
void awaitWorkers(tt::TrustStoreService& svc)
{
    for (auto& worker : tt::detail::TrustStoreServiceAccess::impl(svc).workers)
        if (worker.joinable())
            worker.join();
}

std::vector<std::uint8_t> fixtureBytes(const std::string& name)
{
    std::ifstream in(std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/" + name, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// What the signing engine leaves in the cache after a download.
void putInCache(const std::filesystem::path& dir, const std::string& url, const std::vector<std::uint8_t>& bytes)
{
    libresign::TlCache(dir.string()).store(url, bytes, "", "");
}

std::size_t anchorCount(tt::TrustStoreService& svc)
{
    return svc.trustStore()->enumerableAnchors().size();
}

// The anchors a service holds before any Trusted List source joins.
std::size_t bundledAnchorCount()
{
    auto bare = tt::TrustStoreService::create(tt::TrustConfig{});
    return bare ? anchorCount(**bare) : 0;
}

} // namespace

TEST(TrustStoreServiceTest, AnEagerSourceIsDownloadedAndMergedInTheBackground)
{
    TrustedListRig rig;
    const auto cache = rig.cache("eager");
    auto svc = rig.service(/*eager=*/true, cache);
    ASSERT_NE(svc, nullptr);
    awaitWorkers(*svc);
    EXPECT_EQ(rig.server.servedCount(), 1);
    EXPECT_GT(anchorCount(*svc), bundledAnchorCount()) << "the verified list's anchors are in the store";

    // The source is recorded as loaded: a different list under the same URL
    // is not taken from the cache by a later adoption.
    const auto after = anchorCount(*svc);
    putInCache(cache, rig.server.url(), fixtureBytes("second-ca-tl.xml"));
    svc->adoptCachedTrustedLists(tt::TrustStoreService::Sources::Eager);
    EXPECT_EQ(anchorCount(*svc), after) << "a loaded source is not taken again";
}

TEST(TrustStoreServiceTest, AnEagerSourceThatDoesNotVerifyAddsNothing)
{
    TrustedListRig rig;
    // The service has no certificate for the list: the worker's fetch fails.
    auto svc = rig.service(/*eager=*/true, rig.cache("eager-unverified"), /*knowsTheSigner=*/false);
    ASSERT_NE(svc, nullptr);
    awaitWorkers(*svc);
    EXPECT_EQ(rig.server.servedCount(), 1);
    EXPECT_EQ(anchorCount(*svc), bundledAnchorCount());
}

TEST(TrustStoreServiceTest, ADeferredListsAnchorsReachTheStoreFromTheCache)
{
    TrustedListRig rig;
    const auto cache = rig.cache("deferred");
    auto svc = rig.service(/*eager=*/false, cache);
    ASSERT_NE(svc, nullptr);
    const auto before = anchorCount(*svc);
    EXPECT_EQ(rig.server.servedCount(), 0) << "a deferred source is left alone at construction";

    putInCache(cache, rig.server.url(), fixtureBytes("synthetic-tl.xml"));
    svc->adoptCachedTrustedLists(tt::TrustStoreService::Sources::Eager);
    EXPECT_EQ(anchorCount(*svc), before) << "a deferred source is outside Sources::Eager";

    svc->adoptCachedTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_GT(anchorCount(*svc), before) << "the verified list's anchors are in the store";
    EXPECT_EQ(rig.server.servedCount(), 0) << "nothing is downloaded";

    const auto after = anchorCount(*svc);
    svc->adoptCachedTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(anchorCount(*svc), after);
}

TEST(TrustStoreServiceTest, AFailedAdoptionIsTriedAgain)
{
    TrustedListRig rig;
    const auto cache = rig.cache("retry");
    // The list does not verify (the service has no certificate for it yet):
    // nothing reaches the store, and the source stays pending.
    auto svc = rig.service(/*eager=*/false, cache, /*knowsTheSigner=*/false);
    ASSERT_NE(svc, nullptr);
    const auto before = anchorCount(*svc);
    putInCache(cache, rig.server.url(), fixtureBytes("synthetic-tl.xml"));
    svc->adoptCachedTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(anchorCount(*svc), before);

    TrustedListRig::teachTheSigner();
    svc->adoptCachedTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_GT(anchorCount(*svc), before) << "the failed source was tried again and loaded";
}

TEST(TrustStoreServiceTest, AListTheCacheHoldsIsNotDownloadedAgain)
{
    // The eager worker downloads into the cache the engine shares with the
    // service; a second service over that cache adopts the list from it.
    TrustedListRig rig;
    const auto shared = rig.cache("shared");
    auto first = rig.service(/*eager=*/true, shared);
    ASSERT_NE(first, nullptr);
    awaitWorkers(*first);
    ASSERT_EQ(rig.server.servedCount(), 1);

    auto second = rig.service(/*eager=*/false, shared);
    ASSERT_NE(second, nullptr);
    const auto before = anchorCount(*second);
    second->adoptCachedTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_GT(anchorCount(*second), before);
}

TEST(TrustStoreServiceTest, WithoutACacheDirectoryTheServiceKeepsItsOwn)
{
    TrustedListRig rig;
    std::filesystem::path privateDir;
    {
        auto svc = rig.service(/*eager=*/true, std::nullopt);
        ASSERT_NE(svc, nullptr);
        ASSERT_TRUE(svc->config().cacheDirectory.has_value())
            << "the engine needs a directory to share with the service";
        privateDir = *svc->config().cacheDirectory;
        EXPECT_TRUE(std::filesystem::is_directory(privateDir));
        awaitWorkers(*svc);
        EXPECT_EQ(rig.server.servedCount(), 1);
    }
    EXPECT_FALSE(std::filesystem::exists(privateDir)) << "the private cache goes with the service";
}

TEST(TrustStoreServiceTest, AdoptingFromTheCacheDownloadsNothing)
{
    TrustedListRig rig;
    auto svc = rig.service(/*eager=*/false, rig.cache("cache-only"));
    ASSERT_NE(svc, nullptr);
    const auto before = anchorCount(*svc);

    svc->adoptCachedTrustedLists(tt::TrustStoreService::Sources::All);
    EXPECT_EQ(rig.server.servedCount(), 0) << "a list the cache does not hold is not downloaded";
    EXPECT_EQ(anchorCount(*svc), before);
}

namespace {

// An address nothing listens on: a fetch from it fails at once.
std::string deadUrl()
{
    libresign::test::MockTrustedListServer gone(std::string(CMAKE_SOURCE_DIR) + "/test/fixtures/trust/lotl-tl.xml");
    return gone.url();
}

LibreSCRS::Signing::SigningResult signABuffer(LibreSCRS::Signing::SigningService& svc)
{
    LibreSCRS::Signing::SigningRequest::Builder b;
    b.format(LibreSCRS::Signing::SignatureFormat::Cades)
        .level(LibreSCRS::Signing::SignatureLevel::B_B)
        .packaging(LibreSCRS::Signing::PackagingMode::Detached);
    const auto request = std::move(b).buildForBufferSign();
    auto provider = [](const LibreSCRS::Auth::AuthRequirement&) {
        std::vector<LibreSCRS::Auth::CredentialEntry> values;
        values.emplace_back("pin", LibreSCRS::Secure::String{"0000"});
        return LibreSCRS::Auth::CredentialResult::ok(std::move(values));
    };
    auto session = LibreSCRS::SmartCard::Testing::makeDetachedCardSession("trust-reader");
    auto plugin = std::make_shared<LibreSCRS::TestSupport::SoftKeyPlugin>();
    const auto certs = plugin->readCertificates(*session);
    static const std::vector<std::uint8_t> document{'d', 'o', 'c'};
    return svc.sign(request, std::span<const std::uint8_t>{document}, provider, plugin, session, certs.front(),
                    std::span<const LibreSCRS::Plugin::CertificateData>{certs});
}

} // namespace

// Through the signing service: a List of Trusted Lists one of whose lists
// does not verify. The lists that verify reach the public store from the
// cache after the signature's Trusted List phase, whatever that phase's
// outcome, with nothing downloaded; the one that failed stays pending and is
// taken once a later signature finds it good.
TEST(TrustStoreServiceTest, ASignatureBringsInTheListsThatVerifiedAndKeepsTheFailedOnePending)
{
    TrustedListRig rig;
    const auto cache = rig.cache("lotl");
    const std::string root = deadUrl();
    const std::string goodChild = "https://tl-a.invalid/tl.xml";
    const std::string badChild = "https://tl-b.invalid/tl.xml";

    tt::TrustConfig cfg;
    cfg.trustedListSources.push_back({root, /*eager=*/true, /*lotl=*/true});
    cfg.cacheDirectory = cache;
    auto created = tt::TrustStoreService::create(std::move(cfg));
    ASSERT_TRUE(created.has_value());
    auto service = *created;
    TrustedListRig::teachTheSigner();
    // The background fetch at construction finds nothing (the cache is empty,
    // the address dead); let it finish so the anchors below can only come
    // from the signature.
    awaitWorkers(*service);
    const auto before = anchorCount(*service);

    auto tampered = fixtureBytes("second-ca-tl.xml");
    const std::string from = "LibreSCRS Test Second TSP";
    const auto at = std::search(tampered.begin(), tampered.end(), from.begin(), from.end());
    ASSERT_NE(at, tampered.end());
    *at = 'X'; // the signature no longer covers the content
    putInCache(cache, root, fixtureBytes("lotl-tl.xml"));
    putInCache(cache, goodChild, fixtureBytes("synthetic-tl.xml"));
    putInCache(cache, badChild, tampered);

    LibreSCRS::Signing::SigningService signing(service, LibreSCRS::Signing::TsaProvider{});
    (void)signABuffer(signing); // the engine cannot verify a loopback list; its phase still ends
    EXPECT_EQ(anchorCount(*service), before + 1) << "the list that verified is in the public store";

    putInCache(cache, badChild, fixtureBytes("second-ca-tl.xml"));
    (void)signABuffer(signing);
    EXPECT_EQ(anchorCount(*service), before + 2) << "the list that failed was taken again and now counts";
}

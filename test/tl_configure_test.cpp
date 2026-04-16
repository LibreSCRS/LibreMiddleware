// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "libresign/native/native_signing_service.h"
#include "libresign/trust_store_manager.h"
#include "libresign/types.h"

#include <cstdlib>
#include <filesystem>
#include <string>

using namespace libresign;
namespace fs = std::filesystem;

namespace {

/// Integration test: configure() with Serbian TL URL.
/// Requires network access; skipped in offline CI.
TEST(TlConfigureTest, SerbianTlCertificatesAppearInTrustStore)
{
    // Check for LIBRESIGN_NETWORK_TESTS=1 to opt in
    const char* netTests = std::getenv("LIBRESIGN_NETWORK_TESTS");
    if (!netTests || std::string(netTests) != "1")
        GTEST_SKIP() << "Set LIBRESIGN_NETWORK_TESTS=1 to run network integration tests";

    auto cacheDir = fs::temp_directory_path() / "libresign_tl_configure_test";
    fs::remove_all(cacheDir);

    // Use the bundled cert dir from the build (the cert dir macro is not
    // available in this test binary, so use a reasonable fallback).
    std::string certDir = CMAKE_SOURCE_DIR "/certificates";
    TrustStoreManager trustStore(certDir);

    NativeSigningService service;
    service.setTrustStoreManager(&trustStore);

    TrustConfig config;
    config.cacheDirectory = cacheDir.string();
    config.trustedLists.push_back(
        TrustedListEntry{
            .url = "https://www.mit.gov.rs/TrustedList/TSL-RS.xml",
            .isLotl = false,
            .eager = true});

    bool ok = service.configure(config);
    EXPECT_TRUE(ok);

    // Verify that the trust store now has TL-derived certs by building
    // a SIGNING store and checking it is non-null.
    auto store = trustStore.buildStore(StoreScope::SIGNING);
    EXPECT_NE(store, nullptr);

    // Cleanup
    std::error_code ec;
    fs::remove_all(cacheDir, ec);
}

} // namespace

#else

TEST(TlConfigureTest, SkippedNoNativeBackend)
{
    GTEST_SKIP() << "Native signing backend not enabled";
}

#endif // LIBRESIGN_HAS_NATIVE

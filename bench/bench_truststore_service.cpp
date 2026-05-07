// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Benchmark: TrustStoreService::create() happy path.
// Uses a file:// trustedListFile fixture so the benchmark stays hermetic
// (no network IO). Two scenarios:
//   1. Plain create() with no eager fetches (fast path)
//   2. create() + waitForEagerFetches over the file:// fixture
//
// Numbers vary by machine; CI tracks deltas, not absolute values.

#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include <benchmark/benchmark.h>

#include <chrono>
#include <filesystem>
#include <utility>

namespace {

void BM_TrustStoreService_Create_Empty(benchmark::State& state)
{
    LibreSCRS::Trust::TrustConfig cfg;
    cfg.includeSystemTrustStore = false;
    for (auto _ : state) {
        auto result = LibreSCRS::Trust::TrustStoreService::create(cfg);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_TrustStoreService_Create_Empty);

void BM_TrustStoreService_Create_WithSystemStore(benchmark::State& state)
{
    LibreSCRS::Trust::TrustConfig cfg;
    cfg.includeSystemTrustStore = true;
    for (auto _ : state) {
        auto result = LibreSCRS::Trust::TrustStoreService::create(cfg);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_TrustStoreService_Create_WithSystemStore);

void BM_TrustStoreService_Create_WithTLFile(benchmark::State& state)
{
    const auto tlPath = std::filesystem::path(LIBRESCRS_BENCH_FIXTURES_DIR) / "trust" / "synthetic-tl.xml";
    const auto certPath = std::filesystem::path(LIBRESCRS_BENCH_FIXTURES_DIR) / "trust" / "test-tl-signing-cert.pem";
    if (!std::filesystem::exists(tlPath) || !std::filesystem::exists(certPath)) {
        state.SkipWithError("synthetic-tl.xml or signing cert fixture missing");
        return;
    }

    LibreSCRS::Trust::TrustConfig::Builder b;
    b.setIncludeSystemTrustStore(false).setTrustedListFile(tlPath).setTrustedListFileSigningCert(certPath);
    auto cfg = std::move(b).build();

    for (auto _ : state) {
        auto result = LibreSCRS::Trust::TrustStoreService::create(cfg);
        // The TL file is processed synchronously during create() (it's local
        // disk); waitForEagerFetches is a near-noop but we include it to
        // measure the full happy-path latency.
        if (result) {
            (void)(*result)->waitForEagerFetches(std::chrono::seconds(5));
        }
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_TrustStoreService_Create_WithTLFile);

} // namespace

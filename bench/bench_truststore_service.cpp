// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Benchmark: TrustStoreService::create() happy path with no Trusted List
// source: the bundled anchors and the system certificate store, no network IO.
//
// Numbers vary by machine; CI tracks deltas, not absolute values.

#include <LibreSCRS/Trust/TrustConfig.h>
#include <LibreSCRS/Trust/TrustStore.h>
#include <LibreSCRS/Trust/TrustStoreService.h>

#include <benchmark/benchmark.h>

namespace {

void BM_TrustStoreService_Create_WithSystemStore(benchmark::State& state)
{
    const LibreSCRS::Trust::TrustConfig cfg;
    for (auto _ : state) {
        auto result = LibreSCRS::Trust::TrustStoreService::create(cfg);
        benchmark::DoNotOptimize(result);
    }
}
BENCHMARK(BM_TrustStoreService_Create_WithSystemStore);

} // namespace

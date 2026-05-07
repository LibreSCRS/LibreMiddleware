// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Benchmark: TrustStore::validateChain over synthetic 1/3/5-deep chains.
// Uses the LM-internal access shim to construct a TrustStore directly with
// a fixed anchor set; we benchmark the validateChain path itself, not the
// async TrustStoreService construction (that is bench_truststore_service).

#include <LibreSCRS/Trust/TrustStore.h>

#include "LibreSCRS/Trust/internal/TrustStoreInternalAccess.h"

#include <benchmark/benchmark.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <span>
#include <vector>

namespace {

std::vector<std::uint8_t> loadDer(const std::string& filename)
{
    const std::filesystem::path path = std::filesystem::path(LIBRESCRS_BENCH_TEST_DATA_DIR) / "cert" / filename;
    std::ifstream is(path, std::ios::binary);
    if (!is) {
        return {};
    }
    return std::vector<std::uint8_t>((std::istreambuf_iterator<char>(is)), std::istreambuf_iterator<char>());
}

LibreSCRS::Trust::TrustStore makeStore()
{
    // Empty bundled-cert dir, system store off — we only want a clean store
    // we can populate ourselves below.
    return LibreSCRS::Trust::detail::TrustStoreInternalAccess::makeStore("", false);
}

void BM_ValidateChain_DepthN(benchmark::State& state, std::size_t depth)
{
    auto rsa = loadDer("rsa-cert.der");
    auto ecdsa = loadDer("ecdsa-cert.der");
    auto ca = loadDer("ca-cert.der");
    if (rsa.empty() || ecdsa.empty() || ca.empty()) {
        state.SkipWithError("required test cert(s) not found");
        return;
    }

    auto store = makeStore();
    std::vector<LibreSCRS::Trust::TrustAnchor> anchors;
    anchors.push_back({ca, "bench:ca"});
    LibreSCRS::Trust::detail::TrustStoreInternalAccess::mergeTrustedListAnchors(store, std::move(anchors),
                                                                                "bench:ca-set");

    // Build a synthetic chain of @p depth elements by repeating the rsa/ecdsa
    // certs. validateChain does not actually verify cryptographically here —
    // it walks the chain end-to-end through findIssuerOf for each intermediate
    // hop, which is exactly the loop we want to time. The "expected status"
    // is mostly UntrustedRoot for these synthetic chains; the benchmark
    // measures the search/validation loop, not crypto correctness.
    std::vector<LibreSCRS::Trust::CertificateView> chain;
    chain.reserve(depth);
    for (std::size_t i = 0; i < depth; ++i) {
        chain.push_back((i % 2 == 0) ? std::span<const std::uint8_t>(rsa) : std::span<const std::uint8_t>(ecdsa));
    }

    for (auto _ : state) {
        auto status = store.validateChain(chain);
        benchmark::DoNotOptimize(status);
    }
}

void BM_ValidateChain_Depth1(benchmark::State& state)
{
    BM_ValidateChain_DepthN(state, 1);
}
void BM_ValidateChain_Depth3(benchmark::State& state)
{
    BM_ValidateChain_DepthN(state, 3);
}
void BM_ValidateChain_Depth5(benchmark::State& state)
{
    BM_ValidateChain_DepthN(state, 5);
}

BENCHMARK(BM_ValidateChain_Depth1);
BENCHMARK(BM_ValidateChain_Depth3);
BENCHMARK(BM_ValidateChain_Depth5);

void BM_FindIssuerOf(benchmark::State& state)
{
    auto rsa = loadDer("rsa-cert.der");
    auto ca = loadDer("ca-cert.der");
    if (rsa.empty() || ca.empty()) {
        state.SkipWithError("required test cert(s) not found");
        return;
    }

    auto store = makeStore();
    std::vector<LibreSCRS::Trust::TrustAnchor> anchors;
    anchors.push_back({ca, "bench:ca"});
    LibreSCRS::Trust::detail::TrustStoreInternalAccess::mergeTrustedListAnchors(store, std::move(anchors),
                                                                                "bench:ca-set");

    for (auto _ : state) {
        auto issuer = store.findIssuerOf(rsa);
        benchmark::DoNotOptimize(issuer);
    }
}
BENCHMARK(BM_FindIssuerOf);

} // namespace

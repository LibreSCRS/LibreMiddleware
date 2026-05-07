// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Benchmark: ParsedCertificate::fromDer + every typed accessor.
// Each fixture is loaded once at static-init time and reused across
// benchmark iterations. Numbers vary by machine; CI tracks deltas, not
// absolute values.

#include <LibreSCRS/Certificate/ParsedCertificate.h>

#include <benchmark/benchmark.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
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

void BM_FromDerRsa(benchmark::State& state)
{
    auto der = loadDer("rsa-cert.der");
    if (der.empty()) {
        state.SkipWithError("rsa-cert.der not found");
        return;
    }
    for (auto _ : state) {
        auto cert = LibreSCRS::Certificate::ParsedCertificate::fromDer(der);
        benchmark::DoNotOptimize(cert);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(der.size()));
}
BENCHMARK(BM_FromDerRsa);

void BM_FromDerEcdsa(benchmark::State& state)
{
    auto der = loadDer("ecdsa-cert.der");
    if (der.empty()) {
        state.SkipWithError("ecdsa-cert.der not found");
        return;
    }
    for (auto _ : state) {
        auto cert = LibreSCRS::Certificate::ParsedCertificate::fromDer(der);
        benchmark::DoNotOptimize(cert);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(der.size()));
}
BENCHMARK(BM_FromDerEcdsa);

void BM_FromDerSerbianEid(benchmark::State& state)
{
    auto der = loadDer("serbian-rs-eid-issuer.der");
    if (der.empty()) {
        state.SkipWithError("serbian-rs-eid-issuer.der not found");
        return;
    }
    for (auto _ : state) {
        auto cert = LibreSCRS::Certificate::ParsedCertificate::fromDer(der);
        benchmark::DoNotOptimize(cert);
    }
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) * static_cast<std::int64_t>(der.size()));
}
BENCHMARK(BM_FromDerSerbianEid);

void BM_FromDerWithExtensionsScan(benchmark::State& state)
{
    auto der = loadDer("cert-with-custom-ext.der");
    if (der.empty()) {
        state.SkipWithError("cert-with-custom-ext.der not found");
        return;
    }
    for (auto _ : state) {
        auto cert = LibreSCRS::Certificate::ParsedCertificate::fromDer(der);
        if (cert) {
            // Touch every typed accessor so the benchmark covers the full
            // post-parse extraction cost — this matches the realistic
            // certificate-viewer call site.
            benchmark::DoNotOptimize(cert->subject());
            benchmark::DoNotOptimize(cert->issuer());
            benchmark::DoNotOptimize(cert->serialNumber());
            benchmark::DoNotOptimize(cert->keyUsage());
            benchmark::DoNotOptimize(cert->extendedKeyUsage());
            benchmark::DoNotOptimize(cert->subjectAlternativeNames());
            benchmark::DoNotOptimize(cert->basicConstraints());
            benchmark::DoNotOptimize(cert->authorityKeyIdentifier());
            benchmark::DoNotOptimize(cert->subjectKeyIdentifier());
            benchmark::DoNotOptimize(cert->crlDistributionPoints());
            benchmark::DoNotOptimize(cert->ocspResponderUrls());
            benchmark::DoNotOptimize(cert->extensions());
        }
    }
}
BENCHMARK(BM_FromDerWithExtensionsScan);

} // namespace

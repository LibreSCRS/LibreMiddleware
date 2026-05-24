# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0
#
# Google Benchmark micro-benchmarks for LibreMiddleware public hot paths.
# Gated behind LIBRESCRS_BUILD_BENCH=ON. JSON output via --benchmark_format=json
# is committed under bench/baselines/ as a per-release reference; CI tracks
# regression deltas against the latest committed baseline.

include(FetchContent)

# Pin Google Benchmark to a known-good release so the baseline JSON values
# are reproducible across environments.
FetchContent_Declare(
    googlebenchmark
    GIT_REPOSITORY https://github.com/google/benchmark.git
    GIT_TAG v1.9.4
    GIT_SHALLOW TRUE)

# benchmark depends on Google Test for its self-tests; we don't need them.
set(BENCHMARK_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_INSTALL OFF CACHE BOOL "" FORCE)
set(BENCHMARK_ENABLE_GTEST_TESTS OFF CACHE BOOL "" FORCE)

FetchContent_MakeAvailable(googlebenchmark)

# Common flags for every benchmark target. We compile under Release-with-debug
# so the optimizer behaves like production but stack traces are still useful.
set(LIBRESCRS_BENCH_LIBS benchmark::benchmark benchmark::benchmark_main)

# ---------------------------------------------------------------------------
# bench_parsed_cert: ParsedCertificate::fromDer hot path
# ---------------------------------------------------------------------------
add_executable(bench_parsed_cert bench_parsed_cert.cpp)
target_link_libraries(bench_parsed_cert PRIVATE
    LibreSCRS_Certificate
    ${LIBRESCRS_BENCH_LIBS})
target_compile_definitions(bench_parsed_cert PRIVATE
    LIBRESCRS_BENCH_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/test/test-data")

# ---------------------------------------------------------------------------
# bench_trust_validate: TrustStore::validateChain over 1/3/5-deep chains
# ---------------------------------------------------------------------------
add_executable(bench_trust_validate bench_trust_validate.cpp)
target_compile_definitions(bench_trust_validate PRIVATE LIBRESCRS_INTERNAL_BUILD)
target_include_directories(bench_trust_validate PRIVATE
    ${PROJECT_SOURCE_DIR}/lib)
target_link_libraries(bench_trust_validate PRIVATE
    LibreSCRS_Trust
    LibreSCRS_Certificate
    ${LIBRESCRS_BENCH_LIBS})
target_compile_definitions(bench_trust_validate PRIVATE
    LIBRESCRS_BENCH_TEST_DATA_DIR="${PROJECT_SOURCE_DIR}/test/test-data")

# ---------------------------------------------------------------------------
# bench_truststore_service: TrustStoreService::create() happy path
# ---------------------------------------------------------------------------
add_executable(bench_truststore_service bench_truststore_service.cpp)
target_link_libraries(bench_truststore_service PRIVATE
    LibreSCRS_Trust
    ${LIBRESCRS_BENCH_LIBS})
target_compile_definitions(bench_truststore_service PRIVATE
    LIBRESCRS_BENCH_FIXTURES_DIR="${PROJECT_SOURCE_DIR}/test/fixtures")

# bench_signing: intentionally absent.
#
# SigningService::sign() requires a working PKCS#11 token (SoftHSM in
# CI), and the bench host does not currently bootstrap one. A benchmark
# that always SKIPs offers no signal, so the target is omitted until a
# hermetic SoftHSM bootstrap lands under bench/. When it does, the
# benchmark binary + its baseline JSON come back in lockstep.

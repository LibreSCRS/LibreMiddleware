# LibreMiddleware micro-benchmarks

Google Benchmark targets that measure latency on LibreMiddleware's public hot
paths. Build is gated behind `-DLIBRESCRS_BUILD_BENCH=ON`; the dependency is
pulled in via `FetchContent` and pinned to a specific tag, so reproducing a
baseline only requires checking out the same commit.

| Target                       | Coverage                                                 |
| ---------------------------- | -------------------------------------------------------- |
| `bench_parsed_cert`          | `ParsedCertificate::fromDer` for RSA / ECDSA / Serbian   |
|                              | eID issuer + full typed-accessor sweep                   |
| `bench_trust_validate`       | `TrustStore::validateChain` over 1/3/5-deep chains +     |
|                              | `findIssuerOf`                                           |
| `bench_truststore_service`   | `TrustStoreService::create()` happy path with empty,     |
|                              | system-store, and file:// TL fixture configs             |

## Build

```bash
cmake -B build-bench -S . -DCMAKE_BUILD_TYPE=Release \
    -DSIGNING_BACKEND=both \
    -DLIBRESCRS_BUILD_BENCH=ON \
    -DBUILD_TESTING=OFF
cmake --build build-bench --target bench_parsed_cert bench_trust_validate \
    bench_truststore_service -j4
```

## Run / capture baseline

```bash
for b in bench_parsed_cert bench_trust_validate bench_truststore_service; do
    ./build-bench/bench/$b \
        --benchmark_min_time=1s \
        --benchmark_format=json \
        --benchmark_out=bench/baselines/4.2-$b.json
done
```

The committed `bench/baselines/4.2-*.json` files were captured on the
release-build environment listed in the JSON's `context` block. **Absolute
numbers vary by machine**: a slower CPU produces larger nanosecond timings.
CI tracks the *delta* between a candidate run and the latest committed
baseline, not the absolute value, and gates merges on regressions exceeding a
configurable threshold (default 20%, see `.github/workflows/bench.yml`).

## Workflow when a benchmark regresses

1. Reproduce locally on the same hardware as the baseline if possible.
2. Re-run with `--benchmark_repetitions=10 --benchmark_report_aggregates_only`
   to confirm the regression is stable, not noise.
3. If real: open a fix-commit; rerun; commit the new baseline together with
   the fix.
4. If a deliberate trade-off (e.g. extra defensive copies for thread safety):
   document the rationale in the commit message and update the baseline.

## Signing benchmark — deferred

A `SigningService::sign()` micro-benchmark is intentionally absent: it
needs a working PKCS#11 token (SoftHSM in CI) and the bench host does
not currently bootstrap one. A hermetic SoftHSM bootstrap script is
tracked in the project backlog; once landed, the signing
benchmark binary + its baseline JSON come back together and measure
the full PKCS#11 + B-B / B-T / B-LT / B-LTA latency curve.

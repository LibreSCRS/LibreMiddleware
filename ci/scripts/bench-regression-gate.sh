#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# bench-regression-gate.sh — fail the bench job when a candidate run is
# meaningfully slower than the committed baseline.
#
# Google Benchmark's own tools/compare.py is not a fit here: it needs
# numpy/scipy pinned versions the CI image does not carry, and — more to
# the point — it is a human-readable diff tool with no pass/fail exit
# code tied to a threshold (its only non-zero exits are argument-parsing
# errors). This script is the minimal machine-gate that decision implies:
# stdlib-only, one clear exit code, one clear message per benchmark.
#
# Compares `cpu_time` (not `real_time`): cpu_time excludes scheduler /
# I/O wait noise that shows up on shared CI runners — the committed
# 4.2-bench_truststore_service.json baseline shows this directly
# (BM_TrustStoreService_Create_WithTLFile: real_time ~1.62ms vs cpu_time
# ~1.15ms, the gap being file-read wait, not the code path under test).
#
# Usage:
#   bench-regression-gate.sh <baseline.json> <candidate.json> [threshold_pct]
#
# threshold_pct defaults to 20 (see bench/README.md, which already
# documents "default 20%" for this gate). Exit codes:
#   0 - no benchmark regressed beyond the threshold
#   1 - at least one benchmark regressed, or a baseline entry vanished
#       from the candidate run
#   2 - usage / input error (missing file, unparseable JSON, ...)

set -euo pipefail

if [[ $# -lt 2 || $# -gt 3 ]]; then
    echo "usage: bench-regression-gate.sh <baseline.json> <candidate.json> [threshold_pct]" >&2
    exit 2
fi

BASELINE="$1"
CANDIDATE="$2"
THRESHOLD_PCT="${3:-20}"

if [[ ! -f "$BASELINE" ]]; then
    echo "bench-regression-gate: baseline not found: $BASELINE" >&2
    exit 2
fi
if [[ ! -f "$CANDIDATE" ]]; then
    echo "bench-regression-gate: candidate not found: $CANDIDATE" >&2
    exit 2
fi

python3 - "$BASELINE" "$CANDIDATE" "$THRESHOLD_PCT" <<'PY'
import json
import sys

baseline_path, candidate_path, threshold_pct_str = sys.argv[1:4]
threshold_pct = float(threshold_pct_str)
threshold = threshold_pct / 100.0


def load_iterations(path):
    """name -> (cpu_time, time_unit) for real measurement records.

    Google Benchmark tags statistical summaries (mean/median/stddev over
    --benchmark_repetitions) with run_type "aggregate"; only "iteration"
    records are actual timed runs, so aggregates are skipped even if a
    future change to bench.yml starts requesting repetitions.
    """
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    out = {}
    for entry in data.get("benchmarks", []):
        if entry.get("run_type", "iteration") != "iteration":
            continue
        name = entry["name"]
        out[name] = (entry["cpu_time"], entry.get("time_unit", "ns"))
    return out


try:
    baseline = load_iterations(baseline_path)
    candidate = load_iterations(candidate_path)
except (json.JSONDecodeError, KeyError, OSError) as exc:
    print(f"bench-regression-gate: failed to read benchmark JSON: {exc}", file=sys.stderr)
    sys.exit(2)

if not baseline:
    print(f"bench-regression-gate: no iteration records in baseline {baseline_path}", file=sys.stderr)
    sys.exit(2)

failed = False
label = candidate_path

for name, (base_cpu, base_unit) in sorted(baseline.items()):
    if name not in candidate:
        # A benchmark present in the baseline but absent from the
        # candidate run means the target didn't produce a result at all
        # (crashed, filtered out, renamed) — silence here would be a
        # false green, so treat it as a hard failure, not a skip.
        print(
            f"FAIL  {name}: present in baseline, MISSING from candidate ({label})",
            file=sys.stderr,
        )
        failed = True
        continue

    cand_cpu, cand_unit = candidate[name]
    if cand_unit != base_unit:
        print(
            f"FAIL  {name}: time_unit changed ({base_unit} -> {cand_unit}), "
            "cannot compare magnitudes",
            file=sys.stderr,
        )
        failed = True
        continue

    if base_cpu <= 0:
        # Guard div-by-zero on a degenerate baseline; nothing meaningful
        # to compute, but not a reason to silently pass either.
        print(f"FAIL  {name}: baseline cpu_time is non-positive ({base_cpu})", file=sys.stderr)
        failed = True
        continue

    delta = (cand_cpu - base_cpu) / base_cpu
    marker = "FAIL" if delta > threshold else "ok  "
    print(
        f"{marker}  {name}: {base_cpu:.1f} -> {cand_cpu:.1f} {base_unit} "
        f"({delta:+.1%}, threshold {threshold_pct:.0f}%)"
    )
    if delta > threshold:
        failed = True

new_benchmarks = sorted(set(candidate) - set(baseline))
for name in new_benchmarks:
    print(f"note  {name}: no baseline entry yet, not gated")

if failed:
    print(
        f"bench-regression-gate: regression(s) found vs {baseline_path} "
        f"(threshold {threshold_pct:.0f}%)",
        file=sys.stderr,
    )
    sys.exit(1)

print(f"bench-regression-gate: {candidate_path} within {threshold_pct:.0f}% of {baseline_path}")
sys.exit(0)
PY

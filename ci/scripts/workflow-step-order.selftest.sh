#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# workflow-step-order.selftest.sh — does the check see the defect it exists for,
# and does it stay silent on the shapes that only look like it?
#
# The red proof is the workflow as it actually was when three steps sat in a job
# that does not run on push and named a working directory no checkout had
# created: ci/fixtures/workflow-step-order/ll-coverage-misplaced.yml, committed
# rather than fetched with `git show`, because the commit exists in one
# repository and this check is byte-identical in all of them.
#
# The false-failure half matters as much. Two shapes in the real workflows look
# like the defect and are not: a `git clone` inside a `run:` body that creates
# the directory a later step reads, and a gate step whose `if:` names a matrix
# key that one leg sets. Both are asserted against the TRACKED workflows, so a
# rule that tightened into a false failure fails here.
set -uo pipefail

here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd -- "$here/../.." && pwd)"
SUBJECT="${SUBJECT:-$repo/ci/scripts/workflow-step-order.py}"
FIXTURES="${FIXTURES:-$repo/ci/fixtures/workflow-step-order}"

[ -f "$SUBJECT" ] || { echo "FATAL: no subject at $SUBJECT" >&2; exit 2; }
command -v python3 >/dev/null 2>&1 || { echo "FATAL: python3 is not on PATH" >&2; exit 2; }
python3 -c 'import yaml' 2>/dev/null || { echo "FATAL: python3 cannot import yaml -- cannot judge" >&2; exit 2; }

work="$(mktemp -d "${TMPDIR:-/var/tmp}/workflow-step-order-selftest.XXXXXX")" || exit 2
trap 'rm -rf "$work"' EXIT

cases=0
red=0
failed=0
out="$work/out"

# run <cwd> <args...> — runs the subject and leaves its output in $out.
run() {
    local cwd="$1"
    shift
    (cd "$cwd" && python3 "$SUBJECT" "$@") >"$out" 2>&1
}

judge() {
    local want=$1 name=$2 got=$3
    shift 3
    cases=$((cases + 1))
    if [ "$got" != "$want" ]; then
        printf 'FAIL  %s: wanted exit %s, got %s\n' "$name" "$want" "$got"
        sed -n '1,8p' "$out" | sed 's/^/  | /'
        failed=1
        return
    fi
    local needle
    for needle in "$@"; do
        if ! grep -qF -- "$needle" "$out"; then
            printf 'FAIL  %s: exit %s was right but the output never names %s\n' \
                "$name" "$got" "$needle"
            sed -n '1,10p' "$out" | sed 's/^/  | /'
            failed=1
            return
        fi
    done
    [ "$want" = 0 ] || red=$((red + 1))
    printf 'ok    %s (exit %s)\n' "$name" "$got"
}

# --- a scratch repository the cases can shape ------------------------------
# The fixtures are judged with the subject's cwd here, not in the checkout, so
# the rows that excuse the fixture's own dispatch-only jobs do not have to be
# carried in the repository's real exceptions file (where they would be stale).
mkdir -p "$work/scratch/ci" "$work/scratch/.github/workflows"
git -C "$work/scratch" init -q 2>/dev/null || true
scratch_rows() { printf '%s\n' "$@" >"$work/scratch/ci/gate-job-exceptions.txt"; }
FIXTURE_ROWS_MISPLACED=(
    "ll-coverage-misplaced.yml:coverage    dispatch-only in the recorded workflow"
    "ll-coverage-misplaced.yml:package    never ran in the recorded workflow"
)
FIXTURE_ROWS_FIXED=(
    "ll-coverage-fixed.yml:coverage    dispatch-only in the recorded workflow"
    "ll-coverage-fixed.yml:package    never ran in the recorded workflow"
)

# --- case 1: the defect, as it was ----------------------------------------
scratch_rows "${FIXTURE_ROWS_MISPLACED[@]}"
run "$work/scratch" "$FIXTURES/ll-coverage-misplaced.yml"
judge 1 "the recorded workflow fails, naming all three misplaced steps" $? \
    "Install to the system prefix" "Prove the gate still discriminates" \
    "TSan (agent concurrency)" "before anything provides it"
cp "$out" "$work/misplaced.out"

# --- case 2: the same workflow with the steps where they belong ------------
scratch_rows "${FIXTURE_ROWS_FIXED[@]}"
run "$work/scratch" "$FIXTURES/ll-coverage-fixed.yml"
judge 0 "the same workflow with the steps moved back passes" $?
cp "$out" "$work/fixed.out"

# --- case 3: the perturbation changed something ----------------------------
# A red proof whose output is identical to the green one has proved nothing.
cases=$((cases + 1))
if cmp -s "$work/misplaced.out" "$work/fixed.out"; then
    printf 'FAIL  the two fixtures produce identical output -- the perturbation is inert\n'
    failed=1
else
    red=$((red + 1))
    printf 'ok    the two fixtures produce different output (the perturbation bites)\n'
fi

# --- case 4: the tracked workflows of this repository must pass ------------
# This is the case that defends against a tightened rule: a `git clone` inside a
# `run:` body providing a later step's directory, and gate steps under a matrix
# condition one leg satisfies, are both here in the real files.
run "$repo"
judge 0 "the tracked workflows of this repository pass" $? "gate step(s)"

# --- case 5: working-directory before and after the checkout ---------------
mk_wf() { mkdir -p "$work/scratch/.github/workflows"; cat >"$work/scratch/.github/workflows/$1"; }
: >"$work/scratch/ci/gate-job-exceptions.txt"

mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: early reader
        working-directory: Sub
        run: echo hi
      - uses: actions/checkout@v4
        with:
          path: Sub
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a working-directory before the checkout that creates it fails" $? "reads 'Sub'"

mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          path: Sub
      - name: later reader
        working-directory: Sub
        run: echo hi
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 0 "the same reader after that checkout passes" $?

mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - name: make it
        run: mkdir -p Sub
      - name: later reader
        working-directory: Sub
        run: echo hi
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 0 "a directory a run: step creates counts as provided" $?

# --- case 6: a local action before the checkout ----------------------------
mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/thing
      - uses: actions/checkout@v4
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a local action used before the checkout fails" $? "reads '.'"

# --- case 7: the exceptions file, all four ways ---------------------------
mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    if: vars.FOO == 'true'
    steps:
      - uses: actions/checkout@v4
      - name: gate
        run: ./ci/scripts/thing.sh
YML
: >"$work/scratch/ci/gate-job-exceptions.txt"
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a gate step in a job that needs a variable fails without a row" $? "no reason is recorded"

scratch_rows "t.yml:j    the variable is not set on this repository"
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 0 "the same step passes with a row that carries a reason" $?

scratch_rows "t.yml:j"
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a row with an empty reason fails" $? "empty reason"

scratch_rows "t.yml:gone    a reason for a job that is not there"
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a row naming a job that does not exist fails" $? "does not exist"

# --- case 8: a row that excuses something needing no excuse ---------------
mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: gate
        run: ./ci/scripts/thing.sh
YML
scratch_rows "t.yml:j    a reason that has outlived the condition"
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a row for a step that now runs on push fails as stale" $? "outlived"

# --- case 9: the matrix is modelled --------------------------------------
: >"$work/scratch/ci/gate-job-exceptions.txt"
mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - os: a
          - os: b
            extra_gates: true
    steps:
      - uses: actions/checkout@v4
      - name: gate
        if: matrix.extra_gates
        run: ./ci/scripts/thing.sh
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 0 "a gate step under a matrix key one leg sets passes" $?

mk_wf t.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        include:
          - os: a
          - os: b
    steps:
      - uses: actions/checkout@v4
      - name: gate
        if: matrix.extra_gates
        run: ./ci/scripts/thing.sh
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a gate step under a matrix key no leg sets fails" $? "matrix.extra_gates"

# --- case 10: needs: is transitive ---------------------------------------
mk_wf t.yml <<'YML'
on: [push]
jobs:
  dispatch_only:
    runs-on: ubuntu-latest
    if: github.event_name == 'workflow_dispatch'
    steps:
      - uses: actions/checkout@v4
  downstream:
    runs-on: ubuntu-latest
    needs: dispatch_only
    steps:
      - uses: actions/checkout@v4
      - name: gate
        run: ./ci/scripts/thing.sh
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a job needing a dispatch-only job is not on push either" $? "needs: dispatch_only"

# --- case 11: a gate step in a job that checks nothing out ----------------
# The shape a pages workflow has: a deploy job with one step, no checkout, and
# needs: on a build job that did check out. R2 is satisfied -- it does run on
# push -- and the step would read a tree that does not exist.
mk_wf t.yml <<'YML'
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: gate
        run: ./ci/scripts/thing.sh
  deploy:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - name: gate in the wrong job
        run: ./ci/scripts/thing.sh
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 1 "a gate step in a job that never checks anything out fails" $? \
    "never checks anything out"

mk_wf t.yml <<'YML'
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: gate
        run: ./ci/scripts/thing.sh
      - name: the same gate, in the job that has the tree
        run: ./ci/scripts/thing.sh
  deploy:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/deploy-pages@v4
YML
run "$work/scratch" "$work/scratch/.github/workflows/t.yml"
judge 0 "the same gate step in the job that has the tree passes" $?

# --- case 12: the anti-vacuum ---------------------------------------------
# A floor that cannot be breached is not a floor, so it is breached here.
mkdir -p "$work/vacuum/ci" "$work/vacuum/.github/workflows"
cp "$work/scratch/.github/workflows/t.yml" "$work/vacuum/.github/workflows/"
git -C "$work/vacuum" init -q 2>/dev/null || true
git -C "$work/vacuum" add -A >/dev/null 2>&1 || true
printf 'min_workflows 9\nmin_jobs 99\n' >"$work/vacuum/ci/workflow-shape.txt"
run "$work/vacuum"
judge 2 "a repository with fewer workflows than it declares cannot be judged" $? \
    "ci/workflow-shape.txt declares at least"

printf 'not: [valid\n  yaml: -\n' >"$work/scratch/.github/workflows/broken.yml"
run "$work/scratch" "$work/scratch/.github/workflows/broken.yml"
judge 2 "unloadable YAML is not a clean workflow" $?
rm -f "$work/scratch/.github/workflows/broken.yml"

mk_wf empty.yml <<'YML'
on: [push]
jobs:
  j:
    runs-on: ubuntu-latest
    steps: []
YML
run "$work/scratch" "$work/scratch/.github/workflows/empty.yml"
judge 2 "a job with no steps is not a judgeable job" $?
rm -f "$work/scratch/.github/workflows/empty.yml"

# A host whose python3 cannot import yaml must be exit 2, never a pass. The
# import is shimmed away rather than uninstalled.
mkdir -p "$work/noyaml"
printf 'raise ImportError("no yaml here")\n' >"$work/noyaml/yaml.py"
(cd "$work/scratch" && PYTHONPATH="$work/noyaml" python3 "$SUBJECT" \
    "$work/scratch/.github/workflows/t.yml") >"$out" 2>&1
judge 2 "a python3 that cannot import yaml cannot judge" $? "PyYAML"

printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
[ "$failed" = 0 ] || exit 1
exit 0

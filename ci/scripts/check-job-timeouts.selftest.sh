#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-job-timeouts.sh. Five shapes, each one a way the check
# could be wrong rather than merely absent.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-job-timeouts.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
cases=0
red=0

run() {  # run <name> <expected-rc> <dir>
    local name=$1 want=$2 dir=$3
    cases=$((cases + 1))
    # red-proved: the gate returned non-zero on a perturbed input.
    if [ "$want" != 0 ]; then red=$((red + 1)); fi
    bash "$subject" "$dir" > "$work/out" 2>&1
    local got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-52s rc=%s  %s\n' "$name" "$got" "$(grep -m1 '^jobs=' "$work/out" || true)"
    else
        printf '  FAIL  %-52s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_1 -- a job with no bound at all must fail.
d=$work/case_1; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: true
Y
run "case_1 unbounded job" 1 "$d"

# case_2 -- a bound that lives INSIDE a step must not count for the job. This
# is the one a naive grep gets wrong, and this project's own CI file has both
# levels in the same file.
d=$work/case_2; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: true
        timeout-minutes: 5
Y
run "case_2 step-level bound does not bound the job" 1 "$d"

# case_3 -- a bound indented under `on:` rather than under a job.
d=$work/case_3; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on:
  schedule:
    timeout-minutes: 30
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: true
Y
run "case_3 bound outside the jobs mapping" 1 "$d"

# case_4 -- a file with no jobs: key contributes no jobs and no failure.
d=$work/case_4; mkdir -p "$d"
printf 'name: nothing\non: [push]\n' > "$d/a.yml"
run "case_4 file with no jobs key" 0 "$d"

# case_5 -- a well-formed file passes, and reports the right census.
d=$work/case_5; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    timeout-minutes: 30
    steps:
      - run: true
        timeout-minutes: 5
  test:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - run: true
Y
run "case_5 two bounded jobs" 0 "$d"
grep -q '^jobs=2 bounded=2 unbounded=0$' "$work/out" \
    && printf '  ok    %-52s\n' "case_5 census is 2/2/0" \
    || { printf '  FAIL  %-52s\n' "case_5 census is 2/2/0"; fails=$((fails + 1)); }

# case_6 -- an empty directory is an error, not a pass. A check that reports
# success because it found nothing to check is the vacuous kind.
d=$work/case_6; mkdir -p "$d"
run "case_6 no workflow files is an error, not a pass" 2 "$d"

if [ "$fails" -eq 0 ]; then
    echo "check-job-timeouts selftest: all cases passed"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-job-timeouts selftest: $fails case(s) failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1

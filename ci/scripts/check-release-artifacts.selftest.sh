#!/usr/bin/env bash
# Selftest for check-release-artifacts.sh. Thirteen shapes, each one a way the
# check could be wrong rather than merely absent: seven the check must fail or
# pass on its own terms; two -- case_10 and case_11 -- that a direct-needs
# reading gets wrong in the other direction, by failing a workflow that is
# correct or by not terminating at all; and two -- case_12 and case_13 -- that
# a reading per JOB rather than per ARTEFACT gets wrong, which is how a
# consumer needing one producer went on passing after a second producer was
# dropped from its needs.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-release-artifacts.sh"
[ -f "$subject" ] || { echo "missing subject: $subject" >&2; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
fails=0
cases=0
red=0

run() {  # run <name> <expected-rc> <dir>
    local name=$1 want=$2 dir=$3
    cases=$((cases + 1))
    # red-proved: the case in which the gate returned non-zero on a perturbed input.
    if [ "$want" != 0 ]; then red=$((red + 1)); fi
    bash "$subject" "$dir" > "$work/out" 2>&1
    local got=$?
    if [ "$got" -eq "$want" ]; then
        printf '  ok    %-56s rc=%s  %s\n' "$name" "$got" "$(grep -m1 '^artifact-consumers=' "$work/out" || true)"
    else
        printf '  FAIL  %-56s rc=%s want=%s\n' "$name" "$got" "$want"
        sed 's/^/          /' "$work/out"
        fails=$((fails + 1))
    fi
}

# case_1 -- a consumer with no producer anywhere in the workflow. This is the
# shape that shipped: release.yml downloaded from a run nobody uploaded to.
d=$work/case_1; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: true
  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_1 consumer with no producer" 1 "$d"

# case_2 -- the fixed shape: the job it needs uploads.
d=$work/case_2; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
  release:
    needs: package
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_2 producer named in needs" 0 "$d"

# case_3 -- a producer in the same file that the consumer does NOT need. It may
# still be running when the download happens, so it is not a producer for this
# purpose. A grep for upload-artifact anywhere in the file passes this.
d=$work/case_3; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
  build:
    runs-on: ubuntu-latest
    steps:
      - run: true
  release:
    needs: build
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_3 producer not upstream of the consumer" 1 "$d"

# case_4 -- the word appears, the action does not. A comment or a step name
# must never stand in for a step that runs.
d=$work/case_4; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      # actions/upload-artifact@v4 was here once
      - name: upload-artifact
        run: true
  release:
    needs: package
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_4 the word, not the action" 1 "$d"

# case_5 -- needs as a block list.
d=$work/case_5; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: true
  package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
  release:
    needs:
      - test
      - package
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_5 needs as a block list" 0 "$d"

# case_6 -- needs as a flow list, which is what this repository writes.
d=$work/case_6; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: true
  package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
  release:
    needs: [test, package]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_6 needs as a flow list" 0 "$d"

# case_7 -- a consumer with no needs at all: nothing orders the producer.
d=$work/case_7; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
  release:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_7 consumer with no needs" 1 "$d"

# case_8 -- a workflow that downloads nothing is not this check's business,
# and must not be failed for it.
d=$work/case_8; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
Y
run "case_8 no consumer at all" 0 "$d"
grep -q '^artifact-consumers=0 producer-backed=0 unbacked=0$' "$work/out" \
    && printf '  ok    %-56s\n' "case_8 census is 0/0/0" \
    || { printf '  FAIL  %-56s\n' "case_8 census is 0/0/0"; fails=$((fails + 1)); }

# case_9 -- an empty directory is an error, not a pass. A check that reports
# success because it found nothing to check is the vacuous kind.
d=$work/case_9; mkdir -p "$d"
run "case_9 no workflow files is an error, not a pass" 2 "$d"

# case_10 -- the producer is upstream through a third job. Actions orders the
# whole chain, so the artefact is there when the download runs and this workflow
# is correct. A check that reads only the consumer's own needs: line calls it
# unbacked, which is a false failure pointing the reader at adding a needs edge
# that changes nothing.
d=$work/case_10; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
  fanout:
    needs: [package]
    runs-on: ubuntu-latest
    steps:
      - run: true
  release:
    needs: [fanout]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_10 producer upstream through a third job" 0 "$d"

# case_11 -- a needs cycle. Actions rejects such a workflow, so the verdict
# matters less than the fact that walking the closure has to END. Without a
# visited set this case never returns.
d=$work/case_11; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  first:
    needs: [second]
    runs-on: ubuntu-latest
    steps:
      - run: true
  second:
    needs: [first]
    runs-on: ubuntu-latest
    steps:
      - run: true
  release:
    needs: [first]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
Y
run "case_11 a needs cycle terminates" 1 "$d"

# case_12 -- the consumer needs a producer, and downloads an artefact that
# producer does not upload. Reading the pairing per job passes this: the job
# has A producer. The download fails on the tag with a name nothing in the run
# ever uploaded.
d=$work/case_12; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  package:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: packages-debian
  release:
    needs: [package]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: 'packages-*'
      - uses: actions/download-artifact@v4
        with:
          name: source-tarball
Y
run "case_12 a named artefact with no producer upstream" 1 "$d"
grep -q "downloads 'source-tarball'" "$work/out" \
    && printf '  ok    %-56s\n' "case_12 names the artefact, not the job" \
    || { printf '  FAIL  %-56s\n' "case_12 names the artefact, not the job"; fails=$((fails + 1)); }

# case_13 -- the matrix case, which must NOT be failed: the consumer asks with
# a pattern and the producer's name is an expression the matrix expands. A
# check that compared the two literally would call this missing.
d=$work/case_13; mkdir -p "$d"
cat > "$d/a.yml" <<'Y'
name: a
on: [push]
jobs:
  package:
    strategy:
      matrix:
        slug: [debian, ubuntu]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/upload-artifact@v4
        with:
          name: packages-${{ matrix.slug }}
  fanout:
    needs: [package]
    runs-on: ubuntu-latest
    steps:
      - run: true
  release:
    needs: [fanout]
    runs-on: ubuntu-latest
    steps:
      - uses: actions/download-artifact@v4
        with:
          pattern: 'packages-*'
Y
run "case_13 a pattern served through the matrix and a fan-in" 0 "$d"

if [ "$fails" -eq 0 ]; then
    echo "check-release-artifacts selftest: all cases passed"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-release-artifacts selftest: $fails case(s) failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1

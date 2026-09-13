#!/usr/bin/env bash
# Selftest for check-artifact-names.sh. Eleven fixtures, written here rather
# than copied from the repository, so the file is the same in every repository
# that ships the gate and the cases do not change meaning when a workflow does.
#
# Five of the eleven must PASS. A gate that refuses everything is as useless
# as one that refuses nothing, and the matrix-expression case is exactly where
# an over-strict rule would start failing correct workflows.
#
# The last four exercise the producer arm, which needs a repository around the
# workflow directory rather than a bare directory of yml files: the arm asks
# whether the present make-source-tarball.sh is both run and published by some
# job. The commented case is there because naming a script in a `#` comment is
# the cheapest way to turn a textual check green, and the unpublished case is
# there because a step that only asked whether some step names the maker
# stayed green while a job built the tarball and threw it away.
#
# Fixtures live under /var/tmp -- never /tmp, which is RAM on this machine.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-artifact-names.sh"
root=$(CDPATH= cd -- "$here/../.." && pwd)

work="${TMPDIR_SELFTEST:-/var/tmp/check-artifact-names-selftest.$$}"
rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

fails=0
cases=0

wf() {  # wf <case> <upload-name> <consumer-key> <consumer-value>
    local c=$1 up=$2 key=$3 val=$4 d="$work/$1"
    mkdir -p "$d"
    {
        echo 'name: Fixture'
        echo 'on:'
        echo '  push:'
        echo 'jobs:'
        echo '  produce:'
        echo '    runs-on: ubuntu-latest'
        echo '    steps:'
        echo '      - uses: actions/upload-artifact@v4'
        echo '        with:'
        echo "          name: $up"
        echo '          path: out/*'
        if [ -n "$key" ]; then
            echo '  consume:'
            echo '    needs: produce'
            echo '    runs-on: ubuntu-latest'
            echo '    steps:'
            echo '      - name: Fetch what the other job made'
            echo '        uses: actions/download-artifact@v4'
            echo '        with:'
            echo "          $key: $val"
            echo '          path: artifacts'
        fi
    } > "$d/fixture.yml"
}

# A fixture with a repository around it: the producer arm reads the workflow
# directory's grandparent, which is what .github/workflows makes the root.
wfroot() {  # wfroot <case> <line-naming-the-maker-or-empty>
    local c=$1 line=$2 d="$work/$1/root"
    mkdir -p "$d/ci/scripts" "$d/.github/workflows"
    printf '#!/bin/sh\nexit 0\n' > "$d/ci/scripts/make-source-tarball.sh"
    chmod 755 "$d/ci/scripts/make-source-tarball.sh"
    {
        echo 'name: Fixture'
        echo 'on:'
        echo '  push:'
        echo 'jobs:'
        echo '  produce:'
        echo '    runs-on: ubuntu-latest'
        echo '    steps:'
        [ -n "$line" ] && echo "      $line"
        echo '      - uses: actions/upload-artifact@v4'
        echo '        with:'
        echo '          name: source-tarball'
        echo '          path: out/*'
        echo '  consume:'
        echo '    needs: produce'
        echo '    runs-on: ubuntu-latest'
        echo '    steps:'
        echo '      - uses: actions/download-artifact@v4'
        echo '        with:'
        echo '          name: source-tarball'
    } > "$d/.github/workflows/fixture.yml"
}

# A fixture with a repository around it where the job runs the maker but
# never publishes what it built: no upload-artifact step anywhere in the job.
wfroot_unpublished() {  # wfroot_unpublished <case>
    local c=$1 d="$work/$1/root"
    mkdir -p "$d/ci/scripts" "$d/.github/workflows"
    printf '#!/bin/sh\nexit 0\n' > "$d/ci/scripts/make-source-tarball.sh"
    chmod 755 "$d/ci/scripts/make-source-tarball.sh"
    {
        echo 'name: Fixture'
        echo 'on:'
        echo '  push:'
        echo 'jobs:'
        echo '  produce:'
        echo '    runs-on: ubuntu-latest'
        echo '    steps:'
        echo '      - run: ci/scripts/make-source-tarball.sh out'
    } > "$d/.github/workflows/fixture.yml"
}

expect() {  # expect <case> <want-rc> <substring>
    local c=$1 want=$2 sub=$3 out rc
    cases=$((cases + 1))
    local d="$work/$c"; [ -d "$d/root/.github/workflows" ] && d="$d/root/.github/workflows"
    out=$(bash "$subject" "$d" 2>&1); rc=$?
    if [ "$rc" -ne "$want" ]; then
        echo "CASE $c: expected rc=$want, got $rc"
        printf '%s\n' "$out" | sed 's/^/    /'
        fails=$((fails + 1)); return
    fi
    case "$out" in
        *"$sub"*) : ;;
        *) echo "CASE $c: rc was $rc but no line mentions '$sub'"
           printf '%s\n' "$out" | sed 's/^/    /'
           fails=$((fails + 1)) ;;
    esac
}

# 1 -- the hole this gate exists for: an artefact whose name the consumer's
#      pattern cannot match. Built, kept, silently dropped.
wf unmatched_name source-tarball pattern "'*-artifacts'"
expect unmatched_name 1 "artefact 'source-tarball' is uploaded but no download step"

# 2 -- the same hole with a matrix name.
wf unmatched_matrix 'packages-${{ matrix.slug }}' pattern "'pkg-*'"
expect unmatched_matrix 1 "is uploaded but no download step"

# 3 -- a matrix name the pattern DOES cover must pass. An over-strict rule
#      would fail this, and every packaging workflow with it.
wf matched_matrix 'packages-${{ matrix.slug }}' pattern "'packages-*'"
expect matched_matrix 0 "matched=1 unmatched=0"

# 4 -- a consumer that asks for the exact name must pass too.
wf matched_name source-tarball name source-tarball
expect matched_name 0 "matched=1 unmatched=0"

# 5 -- a workflow with no consumer at all is evidence retention. It must pass,
#      and it must SAY it was skipped: a silent skip is a vacuum.
wf no_consumer abi-snapshot "" ""
expect no_consumer 0 "no consumer -- evidence retention, out of scope"

# 6 -- nothing to measure is not a pass.
mkdir -p "$work/empty"
expect empty 2 "nothing to check"

# 7 -- the maker is present and no workflow names it. Every artefact name still
#      lines up, so arm 1 is green and only the producer arm speaks.
wfroot producer_missing ''
expect producer_missing 1 "is present but no workflow step runs it"

# 8 -- the maker is named, but only inside a comment. A textual check that
#      counted this would be greenest for whoever writes the least CI.
wfroot producer_commented '# ci/scripts/make-source-tarball.sh used to run here'
expect producer_commented 1 "is present but no workflow step runs it"

# 9 -- the maker is named by a step, and that same job publishes what it
#      built. This is the shape every release workflow in the stack has, and
#      it must pass.
wfroot producer_present '- run: ci/scripts/make-source-tarball.sh out'
expect producer_present 0 "source-tarball-producers=1"

# 10 -- the maker runs, but its job has no upload-artifact step at all: the
#       tarball is built and thrown away. The gate this replaced only asked
#       whether some step named the maker, and stayed green on this exact
#       fixture (measured against the previous check-artifact-names.sh).
wfroot_unpublished producer_unpublished
expect producer_unpublished 1 "but has no actions/upload-artifact step"

# 11 -- control: this repository's own workflows must pass, and the census
#       line must say how many uploads were actually judged.
cases=$((cases + 1))
out=$(cd "$root" && bash "$subject" 2>&1); rc=$?
if [ "$rc" -ne 0 ]; then
    echo "CASE control: this repository does not pass its own gate (rc=$rc)"
    printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1))
fi
case "$out" in
    *"uploads-with-a-consumer-in-scope="*) : ;;
    *) echo "CASE control: no census line -- the gate said nothing about what it measured"
       printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1)) ;;
esac

if [ "$fails" -eq 0 ]; then echo "check-artifact-names selftest: all $cases cases passed"; exit 0; fi
echo "check-artifact-names selftest: $fails of $cases case(s) failed"; exit 1

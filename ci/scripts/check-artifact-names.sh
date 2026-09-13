#!/usr/bin/env bash
# check-artifact-names.sh [workflow-dir]
#
# An artefact that is uploaded and never downloaded is built, kept for ninety
# days and silently dropped from the release. Measured on a sibling repository
# while this was being written: a job uploaded `source-tarball` into a workflow
# whose release job collects its inputs with `pattern: '*-artifacts'`. Nothing
# failed. download-artifact is happy with an empty match, every gate stayed
# green, and the release would simply have carried no source tarball -- while
# the packaging recipe pointed at the asset that was never published.
#
# So: in a workflow that downloads artefacts at all, every uploaded artefact
# name must be matched by some consumer's `name:` or `pattern:` in that same
# workflow. `${{ ... }}` inside an uploaded name stands for anything, because
# that is what a matrix expands to.
#
# A workflow with NO consumer is out of scope and is printed as such. Uploads
# there are evidence retention -- an ABI snapshot, a fuzz crash, a package to
# download by hand from the run page -- and demanding a consumer for those
# would be demanding the wrong thing.
#
# Second arm, the other direction, for the one asset with a contract outside
# this repository. The source tarball the packaging recipes fetch by URL is
# built by one workflow step and has to be published by another; if the build
# step is dropped the release publishes no tarball, every gate here stays
# green, and the recipe's `source=` 404s for everyone at the next tag. The
# wiring check does not see it either: reachability there is TRANSITIVE, and
# make-source-tarball.sh is named in code by the recipe check and by the
# determinism check, so it counts as wired even when no workflow names it at
# all (measured -- deleting the whole job left that check green). Dropping
# only the upload step is the quieter half of the same hole: the run step
# that builds the tarball is untouched, so a check that only asked whether
# some step names the maker stayed green while the job built the tarball and
# threw it away (measured on a copy with just that step removed). So: where
# the script is present, the job that runs it must also carry a
# `uses: actions/upload-artifact` step of its own. Where the script is not
# present the arm says so rather than passing quietly.
#
# This checks NAMES only. Whether the consumer is downstream of the producer is
# the `needs` question, and a name can match while the ordering is still wrong,
# and vice versa. That question is answered by ci/scripts/check-release-artifacts.sh
# WHERE A REPOSITORY CARRIES ONE -- not all of them do, and where the file is
# absent nothing measures the ordering at all. Do not read a green run here as
# an answer to it.
#
# Threat model. This reads workflow TEXT, so it guards against the honest
# regression: someone adds an upload, or renames one, in the shapes these
# workflows actually use, and no run says the artefact stopped arriving. It
# does not resist a workflow written to conceal intent, and these doors are
# left open knowingly: an upload or download supplied through a composite
# action or reusable workflow rather than a `uses: actions/upload-artifact`
# line here; a quoted `uses: 'actions/upload-artifact@v4'`, which is not seen
# at all; a name built by an expression whose expansion never matches the
# pattern, since `${{ ... }}` is read as "anything"; and an upload whose
# `if:` condition is false in practice. One more door is worth naming because
# it is the one that fails quietly: a workflow that loses its LAST download
# step falls out of scope as a whole, and its uploads stop being measured here
# at all. The neighbouring check sees a consumer that lost its producer, never
# a producer that lost its consumer. Code review, not this gate, is what
# catches a workflow written to mislead.
#
# Exit: 0 every uploaded artefact has a consumer that can name it and the
#         source tarball's producer job also publishes it - 1 one of those is
#         false - 2 nothing could be measured, which is NOT a pass.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

dir=${1:-.github/workflows}
rc=0
uploads=0
matched=0

shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
shopt -u nullglob

if [ "${#files[@]}" -eq 0 ]; then
    echo "no workflow files under $dir -- nothing to check, and that is not a pass" >&2
    exit 2
fi

extract() {  # extract <file> -> "UP <name>" / "DOWN <glob>" lines
    awk '
        function val(line,   v) {
            v = line
            sub(/^[[:space:]]*[A-Za-z-]+:[[:space:]]*/, "", v)
            sub(/[[:space:]]+#.*$/, "", v)
            gsub(/^["'"'"']|["'"'"']$/, "", v)
            sub(/[[:space:]]+$/, "", v)
            return v
        }
        /uses:[[:space:]]*actions\/upload-artifact/   { mode = "up";   next }
        /uses:[[:space:]]*actions\/download-artifact/ { mode = "down"; next }
        /^[[:space:]]*-[[:space:]]/ { mode = "" }
        /^[^[:space:]#]/            { mode = "" }
        mode == "up"   && /^[[:space:]]*name:[[:space:]]*[^[:space:]]/    { print "UP " val($0); mode = ""; next }
        mode == "down" && /^[[:space:]]*name:[[:space:]]*[^[:space:]]/    { print "DOWN " val($0); next }
        mode == "down" && /^[[:space:]]*pattern:[[:space:]]*[^[:space:]]/ { print "DOWN " val($0); next }
    ' "$1"
}

for f in "${files[@]}"; do
    mapfile -t lines < <(extract "$f")
    ups=(); downs=()
    for l in "${lines[@]}"; do
        case "$l" in
            "UP "*)   ups+=("${l#UP }") ;;
            "DOWN "*) downs+=("${l#DOWN }") ;;
        esac
    done
    [ "${#ups[@]}" -eq 0 ] && continue
    if [ "${#downs[@]}" -eq 0 ]; then
        printf '%s: %d upload(s), no consumer -- evidence retention, out of scope\n' "$f" "${#ups[@]}"
        continue
    fi
    for u in "${ups[@]}"; do
        uploads=$((uploads + 1))
        # A matrix expression stands for anything the matrix can produce.
        subject=$u
        while [ "$subject" != "${subject/\$\{\{*\}\}/*}" ]; do subject=${subject/\$\{\{*\}\}/*}; done
        hit=""
        for d in "${downs[@]}"; do
            # shellcheck disable=SC2254  # the consumer's value IS a glob
            case "$subject" in
                $d) hit=$d; break ;;
            esac
        done
        if [ -n "$hit" ]; then
            matched=$((matched + 1))
            printf "%s: upload '%s' is downloaded by '%s'\n" "$f" "$u" "$hit"
        else
            echo "::error file=$f::artefact '$u' is uploaded but no download step in this workflow can name it -- it would be built, kept and silently dropped"
            rc=1
        fi
    done
done

printf 'uploads-with-a-consumer-in-scope=%d matched=%d unmatched=%d\n' \
    "$uploads" "$matched" "$((uploads - matched))"

# The producer arm. The repository root is the workflow directory's
# grandparent, which is what .github/workflows makes it. A job "runs" the
# maker if some non-comment line names it; that same job must also carry an
# upload-artifact step, or the tarball it builds is never published.
maker=ci/scripts/make-source-tarball.sh
root=$(CDPATH= cd -- "$dir/../.." 2>/dev/null && pwd)
if [ -n "$root" ] && [ -f "$root/$maker" ]; then
    producers=0
    job=""
    has_maker=0
    has_upload=0
    flush_job() {
        [ "$has_maker" -eq 1 ] || return 0
        producers=$((producers + 1))
        if [ "$has_upload" -eq 1 ]; then
            printf '%s: job %s runs %s and publishes it\n' "$f" "$job" "$maker"
        else
            echo "::error file=$f::job '$job' runs $maker but has no actions/upload-artifact step of its own -- the tarball would be built and thrown away, and the packaging recipes fetch that asset by URL"
            rc=1
        fi
    }
    for f in "${files[@]}"; do
        job=""; has_maker=0; has_upload=0
        while IFS=$'\t' read -r tag rest; do
            case "$tag" in
                JOB)    flush_job; job=$rest; has_maker=0; has_upload=0 ;;
                MAKER)  has_maker=1 ;;
                UPLOAD) has_upload=1 ;;
            esac
        done < <(awk '
            /^jobs:[[:space:]]*$/               { seen = 1; next }
            seen && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ {
                j = $0
                sub(/^  /, "", j); sub(/:[[:space:]]*$/, "", j)
                print "JOB\t" j
                next
            }
            /^[[:space:]]*#/ { next }
            /make-source-tarball\.sh/                   { print "MAKER" }
            /uses:[[:space:]]*actions\/upload-artifact/  { print "UPLOAD" }
        ' "$f")
        flush_job
    done
    if [ "$producers" -eq 0 ]; then
        echo "::error::$maker is present but no workflow step runs it -- the release would publish no source tarball, and the packaging recipes fetch that asset by URL"
        rc=1
    fi
    printf 'source-tarball-producers=%d\n' "$producers"
else
    printf 'no %s here -- the producer arm does not apply\n' "$maker"
fi

exit "$rc"

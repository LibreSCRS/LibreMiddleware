#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-release-artifacts.sh
#
# A job that DOWNLOADS artefacts must depend on a job that UPLOADS them, in the
# same workflow.
#
# Measured on this repository before this check existed: release.yml downloaded
# `pattern: '*'` into artifacts/ while no job in that workflow uploaded
# anything. actions/download-artifact neither fails on an empty match nor
# creates its target directory, so the next step ran `find artifacts` against a
# path that does not exist and the release job died there -- five steps before
# `gh release create`, leaving no Release object, no SBOM and no SHA256SUMS.
# Nothing in CI said so, because nothing read this pairing.
#
# `needs` is half the invariant and not a formality: download-artifact without
# a run-id sees only artefacts that jobs of the SAME run have already finished
# uploading, so a producer that is not upstream of the consumer is a race, not
# a producer.
#
# The pairing is read per ARTEFACT, not per job. A release job that downloads
# two named artefacts and needs one producer used to pass on the strength of
# that one: dropping the other producer from `needs` left the census reading
# backed, and the failure waited for the tag, where download-artifact errors
# out with a name nothing in the run uploaded. So every `name:` and `pattern:`
# a consumer asks for must be matched by an artefact name uploaded somewhere in
# its transitive needs closure. A download step with neither key asks for
# everything in the run, and any producer upstream answers it. `${{ ... }}` on
# either side stands for anything, because that is what a matrix expands to.
#
# Upstream means the TRANSITIVE closure of `needs`, not the direct list. A
# workflow that puts a fan-in or summary job between the producer and the
# consumer still orders them, so it is correct and must not be failed here; the
# walk carries a visited set, so a needs cycle terminates instead of recursing
# forever. The message still names the direct `needs`, because that is the line
# the reader has to edit.
#
# Deliberately not a YAML-library parse, for the same reason as
# check-job-timeouts.sh: a job that runs inside a minimal container would need
# an extra package for that, and the indentation is exact enough for the
# distinctions that matter -- a job key is two spaces, its own keys four, its
# steps six.
#
# Threat model. This reads workflow TEXT, so it guards against the honest
# regression: someone adds a consumer job, or drops a producer, writing the
# shapes this repository actually writes, and nothing else notices. It cannot
# and does not resist a workflow written to conceal intent, and these doors are
# left open knowingly: a producer step supplied through a composite action or a
# reusable workflow rather than a `uses: actions/upload-artifact` line here; a
# job key written with other than two spaces of indentation; and a producer
# that uploads ZERO files, which is a valid upload and passes. The
# last one is why the release job additionally asserts at run time that the
# artefacts arrived, and why its upload sets `if-no-files-found: error`. Code
# review, not this gate, is what catches a deliberately misleading workflow.
#
# One more door, named because it is the one that fails SILENTLY: `uses:` and
# `needs:` are matched as bare scalars, so a quoted spelling -- `uses:
# 'actions/download-artifact@v4'`, or `needs: ['a','b']` -- is not seen. A
# quoted consumer disappears from the census, a quoted producer or a quoted
# `needs` list is reported as unbacked. No workflow in these repositories
# writes either shape today. The consequence to keep in mind when reading the
# census: `artifact-consumers=0` means no consumer was PARSED, which is how
# every workflow without a download looks and also how one written this way
# would look.
#
# Scans relative to the current directory, so a repository without its own copy
# can borrow one.
#
# Exit: 0 every artefact a consumer asks for has a producer it needs - 1 one
#       does not - 2 nothing could be measured -- NOT a pass.
#
# SPDX-License-Identifier: LGPL-2.1-or-later
set -u

dir=${1:-.github/workflows}
rc=0
consumers=0
backed=0
requests=0
matched=0

shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
shopt -u nullglob

if [ "${#files[@]}" -eq 0 ]; then
    echo "no workflow files under $dir -- nothing to check, and that is not a pass" >&2
    exit 2
fi

for f in "${files[@]}"; do
    while read -r kind job verdict rest; do
        if [ "$kind" = REQ ]; then
            requests=$((requests + 1))
            case "$verdict" in
                ok)
                    matched=$((matched + 1)) ;;
                missing)
                    echo "::error file=$f::job '$job' downloads '$rest' but no job in its needs closure uploads an artefact by that name -- the download fails on the tag, where it cannot be taken back"
                    rc=1 ;;
            esac
            continue
        fi
        consumers=$((consumers + 1))
        case "$verdict" in
            ok)
                backed=$((backed + 1)) ;;
            partial)
                : ;;
            noneeds)
                echo "::error file=$f::job '$job' downloads artefacts but declares no needs: -- nothing guarantees a producer ran first"
                rc=1 ;;
            unbacked)
                echo "::error file=$f::job '$job' downloads artefacts but none of the jobs it needs ($rest) uploads any"
                rc=1 ;;
        esac
    done < <(awk '
        # A step ends the artefact block it opened: the name that belongs to an
        # upload or download step is the one inside its own with:.
        function flush(   ) {
            if (mode == "up"   && pend) upn[cur]  = upn[cur]  " artifact"
            if (mode == "down" && pend) dreq[cur] = dreq[cur] " *"
            mode = ""; pend = 0
        }
        function val(line,   v) {
            v = line
            sub(/^[[:space:]]*[A-Za-z-]+:[[:space:]]*/, "", v)
            sub(/[[:space:]]+#.*$/, "", v)
            gsub(/^["'"'"']|["'"'"']$/, "", v)
            sub(/[[:space:]]+$/, "", v)
            return v
        }
        # A matrix expression stands for anything the matrix can produce.
        function expand(x) {
            while (match(x, /\$\{\{[^}]*\}\}/))
                x = substr(x, 1, RSTART - 1) "*" substr(x, RSTART + RLENGTH)
            return x
        }
        # The consumer asks with a glob; turn it into a regex so an upload name
        # can be tested against it. Everything else is matched literally.
        function globre(g,   i, c, out) {
            out = "^"
            for (i = 1; i <= length(g); i++) {
                c = substr(g, i, 1)
                if (c == "*") out = out ".*"
                else if (c == "?") out = out "."
                else if (index(".^$+()[]{}|\\", c) > 0) out = out "\\" c
                else out = out c
            }
            return out "$"
        }
        /^jobs:[[:space:]]*$/ { inj = 1; next }
        inj && /^[^[:space:]#]/ { flush(); inj = 0 }
        # A job key: exactly two spaces, a name, a colon, nothing after it.
        inj && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ {
            flush()
            cur = $1; sub(/:$/, "", cur)
            order[++n] = cur; up[cur] = 0; down[cur] = 0; needs[cur] = ""
            upn[cur] = ""; dreq[cur] = ""
            inneeds = 0
            next
        }
        cur == "" { next }
        # Only a uses: line counts. A comment that mentions the action, or a
        # step named after it, must not stand in for one that runs it.
        /^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*actions\/upload-artifact/   { flush(); up[cur] = 1;   mode = "up";   pend = 1; next }
        /^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*actions\/download-artifact/ { flush(); down[cur] = 1; mode = "down"; pend = 1; next }
        # needs at JOB level is four spaces. Three spellings: scalar, flow list,
        # block list.
        /^    needs:/ {
            flush()
            line = $0
            sub(/^[[:space:]]*needs:[[:space:]]*/, "", line)
            gsub(/[][,]/, " ", line)
            needs[cur] = needs[cur] " " line
            inneeds = 1
            next
        }
        # A new four-space key ends the block list.
        /^    [^ ]/ { inneeds = 0 }
        inneeds && /^      -[[:space:]]/ {
            item = $0
            sub(/^[[:space:]]*-[[:space:]]*/, "", item)
            needs[cur] = needs[cur] " " item
            next
        }
        # Any other step boundary closes the block.
        /^[[:space:]]*-[[:space:]]/ { flush() }
        mode == "up"   && /^[[:space:]]*name:[[:space:]]*[^[:space:]]/    { upn[cur]  = upn[cur]  " " val($0); mode = ""; pend = 0; next }
        mode == "down" && /^[[:space:]]*name:[[:space:]]*[^[:space:]]/    { dreq[cur] = dreq[cur] " " val($0); pend = 0; next }
        mode == "down" && /^[[:space:]]*pattern:[[:space:]]*[^[:space:]]/ { dreq[cur] = dreq[cur] " " val($0); pend = 0; next }
        # A producer anywhere in the closure of needs is upstream of the
        # consumer. seen guards against a cycle: an illegal workflow must make
        # this exit, not hang.
        function backed(j, seen,   m, t, k, c) {
            m = split(needs[j], t, /[[:space:]]+/)
            for (k = 1; k <= m; k++) {
                c = t[k]
                if (c == "" || (c in seen)) continue
                seen[c] = 1
                if (up[c]) return 1
                if (backed(c, seen)) return 1
            }
            return 0
        }
        # The same walk, but asking whether the artefact this consumer NAMES is
        # uploaded anywhere upstream.
        function serves(j, re, seen,   m, t, k, c, nn, q, i) {
            m = split(needs[j], t, /[[:space:]]+/)
            for (k = 1; k <= m; k++) {
                c = t[k]
                if (c == "" || (c in seen)) continue
                seen[c] = 1
                nn = split(upn[c], q, /[[:space:]]+/)
                for (i = 1; i <= nn; i++)
                    if (q[i] != "" && expand(q[i]) ~ re) return 1
                if (serves(c, re, seen)) return 1
            }
            return 0
        }
        END {
            flush()
            for (i = 1; i <= n; i++) {
                j = order[i]
                if (!down[j]) continue
                if (needs[j] ~ /^[[:space:]]*$/) { printf "JOB %s noneeds -\n", j; continue }
                delete seen
                if (!backed(j, seen)) {
                    gsub(/^[[:space:]]+|[[:space:]]+$/, "", needs[j])
                    printf "JOB %s unbacked %s\n", j, needs[j]
                    continue
                }
                bad = 0
                m = split(dreq[j], t, /[[:space:]]+/)
                for (k = 1; k <= m; k++) {
                    r = t[k]
                    if (r == "") continue
                    delete seen
                    if (serves(j, globre(expand(r)), seen)) printf "REQ %s ok %s\n", j, r
                    else { printf "REQ %s missing %s\n", j, r; bad = 1 }
                }
                printf "JOB %s %s -\n", j, (bad ? "partial" : "ok")
            }
        }
    ' "$f")
done

printf 'artifact-consumers=%d producer-backed=%d unbacked=%d\n' "$consumers" "$backed" "$((consumers - backed))"
printf 'artefact-requests=%d matched=%d unmatched=%d\n' "$requests" "$matched" "$((requests - matched))"
exit "$rc"

#!/usr/bin/env bash
# check-job-timeouts.sh
#
# Every job in .github/workflows/*.yml must carry a timeout-minutes.
#
# An unbounded job that hangs holds a runner for six hours and refuses to serve
# its log while it does, so the failing test cannot even be named until someone
# cancels the run. That happened here and cost most of a working day.
#
# Deliberately not a YAML-library parse: two sibling repositories build inside
# Arch containers that would need an extra package for that, and the
# indentation is exact enough for the one distinction that matters — a
# job-level timeout-minutes (four spaces) is not a step-level one (eight), and
# this project's own CI file carries both.
#
# Scans relative to the current directory, so a repository without its own copy
# can borrow one.
set -u

dir=${1:-.github/workflows}
rc=0
total=0
bounded=0

shopt -s nullglob
files=("$dir"/*.yml "$dir"/*.yaml)
shopt -u nullglob

if [ "${#files[@]}" -eq 0 ]; then
    echo "no workflow files under $dir — nothing to check, and that is not a pass" >&2
    exit 2
fi

for f in "${files[@]}"; do
    while read -r job bound; do
        total=$((total + 1))
        if [ "$bound" = 1 ]; then
            bounded=$((bounded + 1))
        else
            echo "::error file=$f::job '$job' has no timeout-minutes"
            rc=1
        fi
    done < <(awk '
        # Only inside the top-level jobs: mapping.
        /^jobs:[[:space:]]*$/ { inj = 1; next }
        inj && /^[^[:space:]#]/ { inj = 0 }
        # A job key: exactly two spaces, a name, a colon, nothing after it.
        inj && /^  [A-Za-z0-9_.-]+:[[:space:]]*$/ {
            cur = $1; sub(/:$/, "", cur); b[cur] = 0; order[++n] = cur; next
        }
        # A bound at JOB level is four spaces. Eight spaces is a step bound and
        # must not count: a step that cannot exceed ten minutes says nothing
        # about the job that runs twenty of them.
        inj && /^    timeout-minutes:/ { if (cur != "") b[cur] = 1 }
        END { for (i = 1; i <= n; i++) printf "%s %d\n", order[i], b[order[i]] }
    ' "$f")
done

printf 'jobs=%d bounded=%d unbounded=%d\n' "$total" "$bounded" "$((total - bounded))"
exit "$rc"

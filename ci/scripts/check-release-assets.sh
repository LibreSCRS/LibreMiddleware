#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-release-assets.sh -- what a tag of this repository publishes, held
# true against ci/release-assets.txt.
#
#   --staged [<dir>]            before `gh release create`: the files in <dir>
#                               are exactly the declared set, both directions.
#                               No <dir> means "this release uploads no asset",
#                               and then the declaration must hold no glob.
#   --wired                     on push: the release workflow's job that runs
#                               `gh release create` runs `--staged` before it,
#                               in a step that can fail the job -- not behind
#                               continue-on-error, an if:, or a trailing ||.
#   --published <tag>           after the release exists: its assets are the
#                               declared set. A draft is judged, and says so.
#   --published-strict <tag>    the same, and a draft is NOT judged (exit 2):
#                               the only form that is evidence of a release.
#
# It measures names handed to gh, not a model of the workflow. A static reading
# of release.yml would have to model every flatten step, and a step that later
# removes or adds a file would pass it; the staged directory is the bytes gh is
# about to publish. An entry in it that is a directory is named: gh refuses it.
#
# The declaration is one glob per line (fnmatch, against the asset NAME), two
# spaces, then the one-line description the downloads page renders. A file
# holding only comments is a claim -- "this repository publishes no asset" --
# and a missing file is not a claim at all.
#
# Inputs (for the self-test; CI uses the defaults):
#   RELEASE_ASSETS_FILE  default: ci/release-assets.txt next to this script
#   RELEASE_WORKFLOW     default: .github/workflows/release.yml of this checkout
#   GH_ASSETS_JSON       a file standing in for `gh release view --json`
#   GITHUB_REPOSITORY    the repository `gh release view` asks about
#
# Exit codes -- a consumer writes the condition as `rc = 0`, never "not 1":
#   0  the sets agree (or the job is wired)
#   1  they do not: a name with no glob, a glob with no name, a directory in
#      staging, an empty staging against a non-empty declaration, or the
#      --staged step missing from or after the release step
#   2  nothing could be measured, which is NOT a pass: no declaration, a glob
#      declared twice, a staging directory that was promised and does not
#      exist, no `gh release create` in the workflow, no release to read, or a
#      draft under --published-strict
set -uo pipefail

self="$(basename -- "$0")"
here="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)" \
    || { echo "FATAL: cannot resolve own directory -- cannot judge" >&2; exit 2; }
DECL="${RELEASE_ASSETS_FILE:-$here/../release-assets.txt}"
WORKFLOW="${RELEASE_WORKFLOW:-$here/../../.github/workflows/release.yml}"

usage() {
    echo "FATAL: usage: $self --staged [<dir>] | --wired | --published <tag> | --published-strict <tag>" >&2
    exit 2
}

# ------------------------------------------------------------ declaration --
globs=()
load_declaration() {
    if [ ! -f "$DECL" ]; then
        echo "FATAL: no declaration at $DECL -- a missing release-assets.txt is not a claim that nothing ships; cannot judge" >&2
        exit 2
    fi
    local line glob n=0
    declare -A seen=()
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        case "$line" in '' | '#'*) continue ;; esac
        case "$line" in *[![:space:]]*) ;; *) continue ;; esac
        glob="${line%%[[:space:]]*}"
        if [ -n "${seen[$glob]:-}" ]; then
            echo "FATAL: $DECL:$n declares glob $glob a second time (first at line ${seen[$glob]}) -- cannot judge" >&2
            exit 2
        fi
        seen[$glob]=$n
        globs+=("$glob")
    done < "$DECL"
}

# compare <label> <name...>: both directions, over the names given.
compare() {
    local label="$1"
    shift
    local rc=0 name glob hit
    for name in "$@"; do
        hit=0
        for glob in "${globs[@]}"; do
            # shellcheck disable=SC2053  # the glob is meant to match
            [[ "$name" == $glob ]] && { hit=1; break; }
        done
        if [ "$hit" = 0 ]; then
            echo "::error::$label asset $name matches no glob in ci/release-assets.txt"
            rc=1
        fi
    done
    for glob in "${globs[@]}"; do
        hit=0
        for name in "$@"; do
            [[ "$name" == $glob ]] && { hit=1; break; }
        done
        if [ "$hit" = 0 ]; then
            echo "::error::glob $glob declared but nothing $label matches it"
            rc=1
        fi
    done
    return "$rc"
}

# ----------------------------------------------------------------- staged --
staged() {
    load_declaration
    if [ "$#" -eq 0 ]; then
        if [ "${#globs[@]}" -ne 0 ]; then
            echo "::error::--staged was given no path, so this release uploads no asset, but ci/release-assets.txt declares ${#globs[@]} glob(s)"
            return 1
        fi
        echo "check-release-assets: no asset staged, none declared"
        return 0
    fi
    local dir="$1"
    if [ ! -d "$dir" ]; then
        echo "FATAL: staging directory $dir does not exist -- a promised staging that never came to be is not a pass; cannot judge" >&2
        return 2
    fi
    local names=() rc=0 entry base
    while IFS= read -r -d '' entry; do
        base="$(basename -- "$entry")"
        if [ -d "$entry" ] && [ ! -L "$entry" ]; then
            echo "::error::staged entry $base is a directory -- gh release create refuses it"
            rc=1
            continue
        fi
        names+=("$base")
    done < <(find "$dir" -mindepth 1 -maxdepth 1 -print0 | sort -z)
    if [ "${#names[@]}" -eq 0 ] && [ "$rc" = 0 ] && [ "${#globs[@]}" -ne 0 ]; then
        echo "::error::staging directory $dir holds nothing, and ci/release-assets.txt declares ${#globs[@]} glob(s)"
        return 1
    fi
    compare staged "${names[@]}" || rc=1
    [ "$rc" = 0 ] && echo "check-release-assets: ${#names[@]} staged file(s) match the ${#globs[@]} declared glob(s)"
    return "$rc"
}

# ------------------------------------------------------------------ wired --
wired() {
    if [ ! -f "$WORKFLOW" ]; then
        echo "FATAL: no release workflow at $WORKFLOW -- cannot judge" >&2
        return 2
    fi
    command -v python3 >/dev/null 2>&1 \
        || { echo "FATAL: python3 is not on PATH -- cannot judge" >&2; return 2; }
    python3 - "$WORKFLOW" <<'PYEOF'
import re, sys
try:
    import yaml
except ImportError:
    print("FATAL: PyYAML is not installed -- cannot judge", file=sys.stderr)
    sys.exit(2)
path = sys.argv[1]
try:
    with open(path, encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
except yaml.YAMLError as exc:
    print(f"FATAL: {path} is not readable YAML ({exc}) -- cannot judge", file=sys.stderr)
    sys.exit(2)

def code(run):
    return "\n".join(l for l in str(run or "").split("\n")
                     if not l.lstrip().startswith("#"))

CREATE = re.compile(r"\bgh\s+release\s+create\b")
STAGED = re.compile(r"check-release-assets\.sh\s+--staged\b")
jobs = (doc or {}).get("jobs") or {}
creators = []
staged_in = []
disarmed = []
for jname, job in jobs.items():
    steps = (job or {}).get("steps") or []
    for i, step in enumerate(steps):
        step = step or {}
        body = code(step.get("run"))
        if CREATE.search(body):
            creators.append((jname, i))
        if STAGED.search(body):
            # A step that cannot fail the job is not a check in the chain: it
            # stays in the file and never stops a release.
            why = []
            coe = step.get("continue-on-error", False)
            if coe not in (False, "false"):
                why.append(f"continue-on-error: {coe}")
            if "if" in step:
                why.append(f"if: {step['if']}")
            for line in body.split("\n"):
                if STAGED.search(line) and re.search(r"\|\||;|&\s*$", line[STAGED.search(line).end():]):
                    why.append("its exit status is swallowed after the call (|| or ;)")
            if why:
                disarmed.append((jname, i, why))
            else:
                staged_in.append((jname, i))
if not creators:
    print(f"FATAL: no job in {path} runs gh release create -- nothing to be wired into; cannot judge",
          file=sys.stderr)
    sys.exit(2)
rc = 0
for jname, i in creators:
    mine = [k for j, k in staged_in if j == jname]
    if not mine:
        elsewhere = sorted({j for j, _ in staged_in})
        extra = f" (it runs in {', '.join(elsewhere)}, which does not publish)" if elsewhere else ""
        for j, k, why in disarmed:
            if j == jname:
                extra += f" (step {k + 1} calls it but cannot fail the job: {'; '.join(why)})"
        print(f"::error::job {jname} runs gh release create with no check-release-assets.sh --staged step before it{extra}")
        rc = 1
    elif min(mine) > i:
        print(f"::error::job {jname} runs check-release-assets.sh --staged at step {min(mine) + 1}, after gh release create at step {i + 1}")
        rc = 1
if rc == 0:
    print(f"check-release-assets: --staged runs before gh release create in {len(creators)} job(s)")
sys.exit(rc)
PYEOF
}

# -------------------------------------------------------------- published --
published() {
    local tag="$1" strict="$2" json
    load_declaration
    command -v python3 >/dev/null 2>&1 \
        || { echo "FATAL: python3 is not on PATH -- cannot judge" >&2; return 2; }
    if [ -n "${GH_ASSETS_JSON:-}" ]; then
        if [ ! -r "$GH_ASSETS_JSON" ]; then
            echo "FATAL: GH_ASSETS_JSON=$GH_ASSETS_JSON cannot be read -- cannot judge" >&2
            return 2
        fi
        json="$(cat "$GH_ASSETS_JSON")"
    else
        command -v gh >/dev/null 2>&1 \
            || { echo "FATAL: gh is not on PATH -- cannot judge" >&2; return 2; }
        local repo="${GITHUB_REPOSITORY:-}"
        [ -n "$repo" ] || { echo "FATAL: GITHUB_REPOSITORY is not set -- cannot judge which release" >&2; return 2; }
        if ! json="$(gh release view "$tag" --repo "$repo" --json assets,isDraft)"; then
            echo "FATAL: gh release view $tag --repo $repo failed -- no release to judge" >&2
            return 2
        fi
    fi
    local parsed
    if ! parsed="$(printf '%s' "$json" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("draft" if d["isDraft"] else "final")
for a in d["assets"]:
    print(a["name"])
')"; then
        echo "FATAL: the release description is not the JSON gh prints -- cannot judge" >&2
        return 2
    fi
    local shape names=()
    shape="$(printf '%s\n' "$parsed" | head -n 1)"
    mapfile -t names < <(printf '%s\n' "$parsed" | tail -n +2 | sed '/^$/d')
    if [ "$shape" = draft ]; then
        echo "DRAFT=yes"
        if [ "$strict" = 1 ]; then
            echo "FATAL: $tag is a DRAFT -- --published-strict cannot judge the published release from it" >&2
            return 2
        fi
        echo "::notice::judged a DRAFT release — this is not evidence about the published one"
    else
        echo "DRAFT=no"
    fi
    if [ "${#names[@]}" -eq 0 ]; then
        if [ "${#globs[@]}" -ne 0 ]; then
            echo "::error::release $tag carries no assets, and ci/release-assets.txt declares ${#globs[@]} glob(s)"
            return 1
        fi
        echo "check-release-assets: release $tag carries no asset, none declared"
        return 0
    fi
    compare published "${names[@]}" || return 1
    echo "check-release-assets: release $tag carries ${#names[@]} asset(s) matching the ${#globs[@]} declared glob(s)"
    return 0
}

[ "$#" -ge 1 ] || usage
case "$1" in
    --staged)
        shift
        [ "$#" -le 1 ] || usage
        staged "$@"
        ;;
    --wired)
        [ "$#" -eq 1 ] || usage
        wired
        ;;
    --published | --published-strict)
        # An empty tag would make gh answer with the latest release: evidence
        # about a different one.
        [ "$#" -eq 2 ] && [ -n "$2" ] || usage
        strict=0
        [ "$1" = --published-strict ] && strict=1
        published "$2" "$strict"
        ;;
    *) usage ;;
esac

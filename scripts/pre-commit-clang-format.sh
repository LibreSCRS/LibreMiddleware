#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# pre-commit-clang-format.sh — guard commits against unformatted C++ code.
#
# Runs clang-format-21 in --dry-run --Werror mode against every staged
# .cpp / .h / .hpp / .cc / .cxx / .hxx / .c file. Fails (non-zero) if any
# file is not formatted, blocking the commit and showing the unformatted
# diff so the author can run clang-format-21 -i and re-stage.
#
# Activate by setting `git config core.hooksPath` to a directory whose
# `pre-commit` symlinks to this script, OR by symlinking this script to
# `.git/hooks/pre-commit` on the local checkout. CONTRIBUTING.md documents
# both options.
#
# Tooling: requires clang-format-21 on PATH or at ~/.local/bin/clang-format-21
# (the project pin per CONTRIBUTING.md). The CI uses the same version, so
# the hook + CI agree by construction.
#
# Skip the hook one-off with `git commit --no-verify` (PR CI will still
# enforce — see .github/workflows/ci.yml format-check job).

set -eu

CLANG_FORMAT="${CLANG_FORMAT:-}"
if [[ -z "$CLANG_FORMAT" ]]; then
    if command -v clang-format-21 >/dev/null 2>&1; then
        CLANG_FORMAT="$(command -v clang-format-21)"
    elif [[ -x "$HOME/.local/bin/clang-format-21" ]]; then
        CLANG_FORMAT="$HOME/.local/bin/clang-format-21"
    else
        echo "pre-commit: clang-format-21 not found." >&2
        echo "  Install via 'apt install clang-format-21' (Ubuntu Noble" >&2
        echo "  + apt.llvm.org), 'brew install llvm@21' (macOS), or your" >&2
        echo "  distro's clang-21 package, then ensure it is on PATH or at" >&2
        echo "  ~/.local/bin/clang-format-21." >&2
        echo "  CONTRIBUTING.md documents the project pin." >&2
        exit 2
    fi
fi

# Collect staged C/C++ source/header files (Added, Copied, Modified).
mapfile -t staged < <(git diff --cached --name-only --diff-filter=ACM \
    | grep -E '\.(cpp|cc|cxx|c|h|hpp|hxx)$' || true)

if [[ ${#staged[@]} -eq 0 ]]; then
    exit 0
fi

# Filter to only files that still exist (renames/moves can leave stale paths).
existing=()
for f in "${staged[@]}"; do
    [[ -f "$f" ]] && existing+=("$f")
done
if [[ ${#existing[@]} -eq 0 ]]; then
    exit 0
fi

if ! "$CLANG_FORMAT" --dry-run --Werror "${existing[@]}"; then
    echo >&2
    echo "pre-commit: clang-format-21 reported unformatted code in staged files." >&2
    echo "  Fix in place:  $CLANG_FORMAT -i ${existing[*]}" >&2
    echo "  Then re-stage:  git add ${existing[*]}" >&2
    echo "  Skip (CI will fail):  git commit --no-verify" >&2
    exit 1
fi

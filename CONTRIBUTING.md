# Contributing to LibreMiddleware

Thank you for your interest in contributing to LibreMiddleware. This document
captures the conventions a contributor must follow before opening a pull
request. Plugin authors should also read [docs/CONTRIBUTING-PLUGIN.md](docs/CONTRIBUTING-PLUGIN.md).

## Code formatting

LibreMiddleware uses **`clang-format` version 21** as the canonical formatter.
CI lints `lib/` and `test/` against this exact version (see
`.github/workflows/ci.yml`, `format-check` job). Newer versions of
`clang-format` may emit slightly different layout decisions and produce false
positives or false negatives against CI.

To match CI locally:

- **Debian/Ubuntu**: `apt-get install clang-format-21`
  (use the LLVM nightly apt repo if 21 is not in your distribution)
- **Arch / Manjaro**: `pacman -S clang21`
- **macOS (Homebrew)**: `brew install llvm@21`, then use
  `$(brew --prefix llvm@21)/bin/clang-format`
- **Other distros / fallback**: download the prebuilt LLVM 21 release from
  <https://github.com/llvm/llvm-project/releases> and put the binary on
  `$PATH` as `clang-format-21`.

Run before every commit:

```bash
find lib test -name "*.cpp" -o -name "*.h" \
  | xargs clang-format-21 -i
```

If your local `clang-format` is a different major version, please install
version 21 specifically; do not commit a layout produced by another version
of the tool. The pre-commit hook (if you install one) and CI will reject
diverging layouts.

### Optional pre-commit hook

`scripts/pre-commit-clang-format.sh` runs `clang-format-21 --dry-run --Werror`
against every staged C/C++ file and rejects the commit if any file is not
formatted. Activate it via either:

```bash
# Option A: per-clone, simplest
ln -s ../../scripts/pre-commit-clang-format.sh .git/hooks/pre-commit

# Option B: shared hooks dir (works across worktrees)
git config core.hooksPath scripts/git-hooks
mkdir -p scripts/git-hooks
ln -sr scripts/pre-commit-clang-format.sh scripts/git-hooks/pre-commit
```

The hook respects `$CLANG_FORMAT` if set, otherwise tries `clang-format-21`
on PATH then `~/.local/bin/clang-format-21`. CI enforces the same check
on every PR (see the `format-check` job), so the hook is a local-only
convenience — skip individual commits with `--no-verify` if needed.

A repo-root `.editorconfig` documents the indent / EOL / charset
conventions for editors that support EditorConfig (most modern IDEs do).

## Build and test

See the top-level `README.md` for the build instructions. Cap parallel jobs
to a sensible value (`-j4` is a known-good cap on most workstations); some
contributors have observed full-CPU saturation freezing their machine.

Always run the test suite before opening a pull request:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release -DSIGNING_BACKEND=both
cmake --build build -j4
(cd build && LIBRESIGN_NETWORK_TESTS=1 ctest --output-on-failure -j4)
```

## Commit conventions

- One logical change per commit. Use Conventional-Commit-style subjects
  (e.g. `signing: ...`, `trust: ...`, `plugin: ...`, `docs: ...`).
- Do not include `Co-Authored-By:` lines unless explicitly requested.
- Describe the rationale ("why") in the body, not just the surface diff.

## API stability

LibreMiddleware follows the conventions documented in the
[LibreSCRS API Policy](https://LibreSCRS.github.io/developer-guide/sdk-reference/api-policy/).
Public API additions and changes must comply with the documented thread-safety,
exception-policy, and append-only-enum rules. ABI breaks are confined to major
version bumps.

## License

Source files carry SPDX headers. LibreMiddleware is LGPL-2.1; new files must
preserve this license unless explicitly carved out.

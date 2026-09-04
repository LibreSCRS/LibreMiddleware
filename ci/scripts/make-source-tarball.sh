#!/usr/bin/env bash
# make-source-tarball.sh [output-directory]
#
# One tarball feeds both packaging systems: it is the .orig for dpkg-source and
# Source0 for rpmbuild.
#
# Two things this script refuses to do, both because they have already gone
# wrong once:
#
#  * `git archive` does not descend into submodules, and a tree without
#    thirdparty/curl-source fails configuration with "No download info given
#    for 'curl_external'". So the tree comes from a clone with
#    --recurse-submodules, with .git removed afterwards.
#
#  * `tar --exclude-vcs-ignores` honours every .gitignore in the tree. The
#    vendored OpenSC ignores *.[0-9] while tracking a man page that matches it,
#    and dropping that one file stopped its autotools build with a
#    missing-target error naming a file nobody deleted. Only explicit excludes.
#
# Any dependency that is fetched at configure time rather than carried as a
# submodule is vendored here, at its pinned commit, so the package build never
# reaches the network.
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
name="$(basename "$repo")"
version="$(tr -d '[:space:]' < "$repo/VERSION")"
outdir="${1:-$PWD}"

case "$name" in
  LibreMiddleware) src=librescrs-middleware ;;
  LibreAgent)      src=libreagent ;;
  LibreLinux)      src=librelinux ;;
  LibreCelik)      src=librecelik ;;
  LibreKDE)        src=librekde ;;
  *) echo "make-source-tarball: unknown repository $name" >&2; exit 1 ;;
esac

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
tree="$work/$src-$version"

git clone --quiet --recurse-submodules "$repo" "$tree"
rm -rf "$tree/.git"
find "$tree" -name '.git' -maxdepth 4 -exec rm -rf {} + 2>/dev/null || true

# QCBOR is a FetchContent dependency, not a submodule, so the clone above does
# not carry it. The pin is read from the file the build would otherwise fetch
# with, so the two cannot drift.
if [ -f "$repo/cmake/FetchQCBOR.cmake" ]; then
  qcbor_sha="$(awk '/GIT_TAG/{print $2; exit}' "$repo/cmake/FetchQCBOR.cmake")"
  [ -n "$qcbor_sha" ] || { echo "cannot read the QCBOR pin" >&2; exit 1; }
  if [ -n "${QCBOR_CACHE:-}" ] && [ -d "$QCBOR_CACHE" ]; then
    git -C "$QCBOR_CACHE" rev-parse HEAD | grep -q "^$qcbor_sha" || \
      { echo "QCBOR cache is at a different commit than the pin" >&2; exit 1; }
    cp -a "$QCBOR_CACHE" "$tree/thirdparty/QCBOR"
    rm -rf "$tree/thirdparty/QCBOR/.git"
  else
    git clone --quiet https://github.com/laurencelundblade/QCBOR.git "$tree/thirdparty/QCBOR"
    git -C "$tree/thirdparty/QCBOR" checkout --quiet "$qcbor_sha"
    rm -rf "$tree/thirdparty/QCBOR/.git"
  fi
  test -f "$tree/thirdparty/QCBOR/CMakeLists.txt"
fi

mkdir -p "$outdir"
tar --exclude='./.github' --exclude='./build' --exclude='./debian' \
    -C "$work" -czf "$outdir/${src}_${version}.orig.tar.gz" "$src-$version"
sha256sum "$outdir/${src}_${version}.orig.tar.gz"

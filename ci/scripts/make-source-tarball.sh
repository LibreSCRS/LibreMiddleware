#!/usr/bin/env bash
# make-source-tarball.sh [output-directory]
#
# The tarball is named so that `<source>_<version>.orig.tar.gz` is what
# dpkg-source expects of an .orig. Neither build consumes it yet -- the deb
# build runs `dpkg-buildpackage -b`, which never touches an orig tarball, and
# the rpm build still rolls its own archive inline, under a different name and
# a different top directory than the spec's `Source0`/`%autosetup` expect.
# Today the one consumer is the Arch recipe, which fetches the published asset
# by URL.
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
#    missing-target error naming a file nobody deleted. Only explicit excludes —
#    anchored to the top directory, because an unanchored './x' matches no
#    member name tar ever writes here and excludes nothing at all.
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
# The tarball's top directory is the REPOSITORY name, not the Debian source
# name. Three PKGBUILDs cd into "$srcdir/<Repo>-$pkgver" and all three dogfood
# recipes name their git source to match it; dpkg-source -x renames whatever
# top directory it finds, so Debian does not care and Arch does.
tree="$work/$name-$version"

git clone --quiet --recurse-submodules "$repo" "$tree"
rm -rf "$tree/.git"
find "$tree" -name '.git' -exec rm -rf {} + 2>/dev/null || true

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

# The excludes are anchored to the top directory. './.github' matched NOTHING:
# tar's member names here are "<Repo>-<version>/.github/…", so the release
# tarball shipped .github/ for as long as this script existed (measured: four
# entries in a LibreKDE tarball).
#
# `--sort=name` and everything below it are what make two runs produce the same
# bytes. Without them the sum in sha256sums is a fact about one upload and
# nothing else.
#
# --sort=name settles the member ORDER. Without it the order is whatever
# readdir() hands back, which is a property of the filesystem the clone landed
# on; with it the order is the names', sorted directory-wise, so `a/c` comes
# before `a-b` even though strcmp puts `a-b` first. Two runs on one machine
# agree either way, which is why order is the arm a byte comparison cannot see.
#
# Three further facts about the machine leaked into the bytes:
#
#  * every mtime was the moment of the clone, so two runs a second apart
#    differed (two inside one second did not, which is why this survived);
#  * owner and group were whoever ran it;
#  * the MODE was the caller's umask. git clone honours it, tar records what it
#    finds. Measured on this repository, same commit, same second: umask 022
#    gave 5ea42da7... and umask 002 gave d2fc8326..., because one wrote
#    drwxr-xr-x/-rw-r--r-- and the other drwxrwxr-x/-rw-rw-r--. A packager
#    rebuilding the tarball to check the published sum would have concluded the
#    asset had been tampered with. --mode normalises all three: 755 for
#    anything executable or a directory, 644 for the rest. It reaches symlinks
#    too, where the stored mode is a constant either way -- measured with GNU
#    tar 1.35 on a fixture holding one: stored lrwxrwxrwx without --mode,
#    lrwxr-xr-x with it. Neither is the umask, but only one of them is what
#    this script writes, and that is the one the check accepts.
#
# What remains outside this script's reach is the compressor: gzip -9 output is
# a property of the gzip implementation, so the sum is reproducible for anyone
# using the same one. (gzip is fed from a pipe, so it writes no name and a zero
# MTIME field of its own either way; -n says so rather than relying on it.)
epoch="$(git -C "$repo" log -1 --format=%ct)"
tar --sort=name \
    --mtime="@$epoch" --owner=0 --group=0 --numeric-owner --format=gnu \
    --mode='go-w,a+rX' \
    --exclude="$name-$version/.github" \
    --exclude="$name-$version/build" \
    --exclude="$name-$version/debian" \
    -C "$work" -cf - "$name-$version" \
  | gzip -n -9 > "$outdir/${src}_${version}.orig.tar.gz"
sha256sum "$outdir/${src}_${version}.orig.tar.gz"

#!/usr/bin/env bash
# Build this repository's RPM packages inside a container.
#
# Contract: source tree at the working directory, /out mounted writable, and
# optionally /upstream, /lm or /la holding already-built upstream .rpm files.
#
# The same script is copied into every packaged repository.
set -euo pipefail

spec=$(ls packaging/rpm/*.spec | head -1)
name=$(awk '/^Name:/{print $2; exit}' "$spec")
version=$(awk '/^Version:/{print $2; exit}' "$spec")

dnf -y -q install rpm-build rpmdevtools dnf-plugins-core tar >/dev/null

shopt -s nullglob
upstream=( /upstream/*.rpm /upstream/*/*.rpm /lm/*.rpm /la/*.rpm )
shopt -u nullglob
# Debug packages are not build inputs and pull in nothing useful.
filtered=()
for f in "${upstream[@]}"; do
  case "$f" in *debuginfo*|*debugsource*) continue ;; esac
  filtered+=("$f")
done
if [ "${#filtered[@]}" -gt 0 ]; then
  echo "build-rpm: installing ${#filtered[@]} upstream package(s)"
  printf '  %s\n' "${filtered[@]}"
  dnf -y -q install "${filtered[@]}" >/dev/null
fi

rpmdev-setuptree
top="$(rpm --eval %{_topdir})"

# Source0 is the tarball rpmbuild unpacks. It is produced from the working
# tree, which in a packaging build is already the exported source: the same
# content the release tarball carries, submodules included.
stage="$(mktemp -d)/$name-$version"
mkdir -p "$stage"
# Explicit excludes only. --exclude-vcs-ignores looks tidier and is a trap: it
# honours every .gitignore in the tree, and the vendored OpenSC ignores *.[0-9]
# while tracking compat_strlcpy.3 anyway. Dropping that one man page made the
# vendored autotools build stop with "No rule to make target compat_strlcpy.3"
# -- a failure that names a file nobody deleted on purpose.
tar --exclude=./.git --exclude=./build --exclude=./debian --exclude='./.github' \
    -cf - . | tar -xf - -C "$stage"
tar -czf "$top/SOURCES/$name-$version.tar.gz" -C "$(dirname "$stage")" "$name-$version"
rm -rf "$(dirname "$stage")"

cp "$spec" "$top/SPECS/"

dnf -y -q builddep "$top/SPECS/$(basename "$spec")" >/dev/null

rpmbuild -bb --define "_smp_build_ncpus ${RPM_BUILD_NCPUS:-2}" "$top/SPECS/$(basename "$spec")"

mkdir -p /out
find "$top/RPMS" -name '*.rpm' -exec cp -v {} /out/ \;
ls -1 /out

#!/usr/bin/env bash
# Build this repository's Debian binary packages inside a container.
#
# Contract: run with the source tree at the working directory, /out mounted
# writable for the artefacts, and optionally /upstream, /lm or /la mounted with
# already-built upstream .deb files. In CI those directories are filled by
# `gh release download`; locally they are directories of freshly built packages.
#
# The same script is copied into every packaged repository.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
export DEB_BUILD_OPTIONS="${DEB_BUILD_OPTIONS:-parallel=2}"

apt-get update -qq
apt-get install -y -qq --no-install-recommends \
    build-essential dpkg-dev debhelper devscripts equivs ca-certificates >/dev/null

# Upstream LibreSCRS packages first: build dependencies are resolved against
# what is installed, so these have to be in place before build-dep runs.
# Both shapes: a flat directory of .deb files, and /upstream/<Repo>/ as the
# gate mounts it. A glob that expands to nothing must not be handed to apt.
shopt -s nullglob
upstream=( /upstream/*.deb /upstream/*/*.deb /lm/*.deb /la/*.deb )
shopt -u nullglob
if [ "${#upstream[@]}" -gt 0 ]; then
  echo "build-deb: installing ${#upstream[@]} upstream package(s)"
  printf '  %s\n' "${upstream[@]}"
  apt-get install -y -qq --no-install-recommends "${upstream[@]}" >/dev/null
fi

# dpkg-buildpackage reads debian/ at the root of the source tree, and the
# recipe lives under packaging/. A copy, not a symlink: some dpkg-source modes
# refuse a symlinked debian/, and there is no reason for that to be unknown.
rm -rf debian
cp -a packaging/debian debian
chmod +x debian/rules

# Resolve Build-Depends from debian/control itself. A hand-maintained install
# list drifts away from control and no gate sees it happen.
mk-build-deps --install --remove \
  --tool 'apt-get -o Debug::pkgProblemResolver=yes -y --no-install-recommends' \
  debian/control >/dev/null

dpkg-buildpackage -us -uc -b

mkdir -p /out
cp -v ../*.deb ../*.buildinfo ../*.changes /out/ 2>/dev/null || cp -v ../*.deb /out/
ls -1 /out

#!/usr/bin/env bash
# Assertions only this repository can make about its own package build.
# Run by packaging/ci/package-gate.sh after a successful build, with BUILDLOG,
# SRC, OUT and FAMILY in the environment.
set -uo pipefail
fail=0

# The bundled curl has to install where the link step looks for it. curl's own
# GNUInstallDirs chooses lib64 on a 64-bit RPM target, while the import target
# names lib/libcurl.a unconditionally, and the pin is on the installer rather
# than on the consumer. Name the path here: without this line the only evidence
# for that fix is that the link does not fail, and a regression would be silent
# on Debian, where the two layouts happen to agree.
if find "$SRC" -path '*/thirdparty/curl-install/lib/libcurl.a' | grep -q .; then
  echo "PASS  bundled curl installed to curl-install/lib/libcurl.a"
elif grep -q 'thirdparty/curl-install/lib/libcurl.a' "$BUILDLOG"; then
  echo "PASS  bundled curl path named in the build log"
else
  echo "FAIL  bundled curl is not at curl-install/lib/libcurl.a"
  find "$SRC" -path '*/curl-install/lib*' -name 'libcurl.a' 2>/dev/null | head
  fail=1
fi

exit $fail

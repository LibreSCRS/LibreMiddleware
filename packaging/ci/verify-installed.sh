#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs INSIDE a fresh container with the built packages at /pkg. Asserts what
# the packages leave on a machine, not what the build printed.
#
# FAMILY is deb or rpm. Every assertion is its own test so a failure names
# itself; nothing is measured through a pipe.
set -uo pipefail
fail=0
check() { if [ "$2" -eq 0 ]; then echo "PASS $1"; else echo "FAIL $1"; fail=1; fi; }

# openSUSE: the same assertions through zypper. The dnf calls below are
# answered by this function, which drops -y/-q and maps the one package name
# openSUSE spells differently.
if [ "${PKG_MANAGER:-}" = zypper ]; then
  zypper -n -q refresh >/dev/null
  zypper -n -q install findutils dbus-1-tools >/dev/null
  dnf() {
    local a=() x
    for x in "$@"; do
      case "$x" in -y|-q) ;; dbus-daemon) a+=(dbus-1-daemon) ;; *) a+=("$x") ;; esac
    done
    case "${a[0]}" in
      install) zypper -n -q --no-gpg-checks install --allow-unsigned-rpm "${a[@]:1}" ;;
      remove)  zypper -n -q remove "${a[@]:1}" ;;
      *) echo "dnf shim: ${a[0]} is not mapped" >&2; return 2 ;;
    esac
  }
fi


if [ "${FAMILY:-deb}" = deb ]; then
  export DEBIAN_FRONTEND=noninteractive
  # The base container is not a machine. Ubuntu's image ships
  # /etc/dpkg/dpkg.cfg.d/excludes with path-exclude=/usr/share/locale/*/LC_MESSAGES/*.mo
  # (Debian's does not), so a package that carries translations installs without
  # them there. Asserting on disk under that configuration measures the image,
  # not the package, so the exclusion goes before anything is installed.
  rm -f /etc/dpkg/dpkg.cfg.d/excludes
  apt-get update -qq
  apt-get install -y -qq p11-kit >/dev/null
  LIBDIRGLOB="/usr/lib/*"
  RUNTIME_PKG=liblibrescrs5
  owner_of() { dpkg -S "$1" 2>/dev/null | cut -d: -f1; }
  installed_list() { dpkg-query -W -f='${Package}\n'; }
  install_all() { apt-get install -y --no-install-recommends /pkg/*.deb >/dev/null; }
  install_some() { apt-get install -y --no-install-recommends "$@" >/dev/null; }
  remove_ours() {
    apt-get purge -y $(installed_list | grep -E 'librescrs|liblibrescrs') >/dev/null
  }
  dump_scripts() {
    for s in /var/lib/dpkg/info/*librescrs*.postinst /var/lib/dpkg/info/*librescrs*.postrm \
             /var/lib/dpkg/info/*librescrs*.preinst /var/lib/dpkg/info/*librescrs*.prerm; do
      [ -e "$s" ] || continue; echo "--- $s"; cat "$s"
    done
  }
else
  dnf -y -q install p11-kit >/dev/null
  LIBDIRGLOB="/usr/lib64"
  RUNTIME_PKG=librescrs-middleware
  owner_of() { rpm -qf --qf '%{NAME}' "$1" 2>/dev/null; }
  installed_list() { rpm -qa --qf '%{NAME}\n'; }
  install_all() { dnf -y -q install /pkg/*.rpm >/dev/null; }
  install_some() { dnf -y -q install "$@" >/dev/null; }
  remove_ours() {
    dnf -y -q remove $(installed_list | grep -E '^(librescrs|liblibrescrs)') >/dev/null
  }
  dump_scripts() { rpm -q --scripts $(installed_list | grep -E '^(librescrs|liblibrescrs)') 2>/dev/null | grep -v '^$'; }
fi

# ── V1 the packages install at all ────────────────────────────────────────
install_all; check "V1 install" $?

# ── V2 the registration file is on the path p11-kit reads ─────────────────
test -f /usr/share/p11-kit/modules/librescrs.module
check "V2 p11-kit declaration on /usr/share/p11-kit/modules" $?

# ── V3 all three module paths exist and belong to the RUNTIME package ─────
# VERSION/SOVERSION on the PKCS#11 target emit .so.5.0.0, .so.5 and the bare
# .so. The declaration names the bare name, so the bare name must not sit in a
# development package a headless box would never install.
ls $LIBDIRGLOB/pkcs11/librescrs-pkcs11.so   >/dev/null 2>&1; check "V3 bare module path" $?
ls $LIBDIRGLOB/pkcs11/librescrs-pkcs11.so.5 >/dev/null 2>&1; check "V3b soname path" $?
for f in $LIBDIRGLOB/pkcs11/librescrs-pkcs11.so*; do
  o="$(owner_of "$f")"
  test "$o" = "$RUNTIME_PKG"; check "V3 owner $f = $o" $?
done

# ── V4 exactly one provider ───────────────────────────────────────────────
# The anchor ^module: is not decoration: a bare `grep -c -i librescrs` counts
# the path, uri and description lines too and returns five for one correctly
# registered module.
n=$(p11-kit list-modules | grep -c '^module: librescrs')
test "$n" -eq 1; check "V4 exactly one librescrs provider (counted $n)" $?
p11-kit list-modules

# ── V8 nothing generated mentions a user's home ───────────────────────────
dump_scripts > /tmp/scripts.txt 2>&1
if [ -s /tmp/scripts.txt ]; then
  grep -nE 'HOME|\.config|\.local|\.cache' /tmp/scripts.txt
  test $? -ne 0
else
  true
fi
check "V8 no maintainer script touches a home directory" $?

# ── V11 nothing links against a library that is not there ─────────────────
miss=0
for f in $LIBDIRGLOB/libLibreSCRS_*.so.* $LIBDIRGLOB/librescrs/plugins/*.so \
         $LIBDIRGLOB/pkcs11/librescrs-pkcs11.so; do
  [ -e "$f" ] || continue
  if ldd "$f" 2>/dev/null | grep -q 'not found'; then echo "  not found in $f"; miss=1; fi
done
test "$miss" -eq 0; check "V11 no unresolved shared-library dependency" $?

# ── V3c the same claim WITHOUT the development package ────────────────────
# The run above installed everything, so it could not see the module sitting in
# the wrong package: the file would be on disk either way, just out of somebody
# else's bag. A headless box is the opposite case.
remove_ours
if [ "${FAMILY:-deb}" = deb ]; then
  install_some /pkg/liblibrescrs5_*.deb /pkg/librescrs-card-plugins_*.deb \
               /pkg/librescrs-pkcs11-direct_*.deb
else
  install_some /pkg/librescrs-middleware-5*.rpm /pkg/librescrs-card-plugins-5*.rpm \
               /pkg/librescrs-pkcs11-direct-5*.rpm
fi
check "V3c headless install (no development package)" $?
installed_list > /tmp/inst.txt 2>&1; check "V3c package list readable" $?
test "$(wc -l < /tmp/inst.txt)" -gt 10; check "V3c package list is not empty" $?
test "$(grep -cE 'liblibrescrs-dev|librescrs-middleware-devel' /tmp/inst.txt)" -eq 0
check "V3c development package really absent" $?
ls $LIBDIRGLOB/pkcs11/librescrs-pkcs11.so >/dev/null 2>&1
check "V3c bare module still present without the development package" $?
n=$(p11-kit list-modules | grep -c '^module: librescrs')
test "$n" -eq 1; check "V3c still exactly one provider" $?

# ── V9 removal leaves nothing under /usr ──────────────────────────────────
# Removing by query rather than by a hand-written list. A hand-written list
# forgets the automatic debug packages and then reports leftovers that are only
# leftovers because nobody asked for them to go.
remove_ours
find /usr -iname '*librescrs*' > /tmp/leftover.txt
test ! -s /tmp/leftover.txt; check "V9 nothing left under /usr after removal" $?
[ -s /tmp/leftover.txt ] && cat /tmp/leftover.txt

exit $fail

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Runs INSIDE a fresh container with the built packages at /pkg. Asserts what
# the packages leave on a machine, not what the build printed.
#
# FAMILY is deb, rpm or arch; anything else is refused rather than read as
# one of them. Every assertion is its own test so a failure names itself;
# nothing is measured through a pipe.
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


case "${FAMILY:-}" in
deb)
  export DEBIAN_FRONTEND=noninteractive
  # The base container is not a machine. Ubuntu's image ships
  # /etc/dpkg/dpkg.cfg.d/excludes with path-exclude=/usr/share/locale/*/LC_MESSAGES/*.mo
  # (Debian's does not), so a package that carries translations installs without
  # them there. Asserting on disk under that configuration measures the image,
  # not the package, so the exclusion goes before anything is installed.
  rm -f /etc/dpkg/dpkg.cfg.d/excludes
  apt-get update -qq
  LIBDIRGLOB="/usr/lib/*"
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
  ;;
rpm)
  LIBDIRGLOB="/usr/lib64"
  installed_list() { rpm -qa --qf '%{NAME}\n'; }
  install_all() { dnf -y -q install /pkg/*.rpm >/dev/null; }
  install_some() { dnf -y -q install "$@" >/dev/null; }
  remove_ours() {
    dnf -y -q remove $(installed_list | grep -E '^(librescrs|liblibrescrs)') >/dev/null
  }
  dump_scripts() { rpm -q --scripts $(installed_list | grep -E '^(librescrs|liblibrescrs)') 2>/dev/null | grep -v '^$'; }
  ;;
arch)
  # The PKGBUILD makes one package: Arch does not split headers or the test
  # archive into a development package.
  LIBDIRGLOB="/usr/lib"
  installed_list() { pacman -Qq; }
  install_all() { pacman -U --noconfirm /pkg/*.pkg.tar.zst >/dev/null; }
  remove_ours() {
    pacman -Rns --noconfirm $(installed_list | grep -E '^(librescrs|liblibrescrs)') >/dev/null
  }
  dump_scripts() {
    for s in /var/lib/pacman/local/*librescrs*/install; do
      [ -e "$s" ] || continue; echo "--- $s"; cat "$s"
    done
  }
  ;;
*)
  echo "FAIL FAMILY='${FAMILY:-}' is not deb, rpm or arch"
  exit 2
  ;;
esac

# ── V1 the packages install at all ────────────────────────────────────────
install_all; check "V1 install" $?

# ── V8 nothing generated mentions a user's home ───────────────────────────
dump_scripts > /tmp/scripts.txt 2>&1
if [ -s /tmp/scripts.txt ]; then
  grep -nE 'HOME|\.config|\.local|\.cache' /tmp/scripts.txt
  test $? -ne 0
else
  true
fi
check "V8 no maintainer script touches a home directory" $?

# ── V12 no library dumps what a card answered ──────────────────────────────
# An APDU response can be a certificate, a personal record or decrypted key
# material. A build that left NDEBUG unset compiled a writer of every response
# into the transport, and an RPM built that way shipped it. grep -a reads the
# binaries directly: the container has no binutils.
dump=0
for f in $LIBDIRGLOB/libLibreSCRS_*.so* $LIBDIRGLOB/librescrs/plugins/*.so; do
  [ -e "$f" ] || continue
  if grep -q -a -F '[PCSC] RX' "$f"; then echo "  response dump in $f"; dump=1; fi
done
test "$dump" -eq 0; check "V12 no library carries an APDU response dump" $?

# ── V3c the runtime packages install WITHOUT the development package ──────
# The run above installed everything, so it could not see a runtime file
# sitting in the development package. A headless box is the opposite case.
# Arch has no development package to leave out, so there is no such case.
if [ "$FAMILY" = arch ]; then
  echo "SKIP V3c headless install: the Arch recipe makes one package, with no development package to leave out"
else
  remove_ours
  if [ "$FAMILY" = deb ]; then
    install_some /pkg/liblibrescrs5_*.deb /pkg/librescrs-card-plugins_*.deb
  else
    install_some /pkg/librescrs-middleware-5*.rpm /pkg/librescrs-card-plugins-5*.rpm
  fi
  check "V3c headless install (no development package)" $?
  installed_list > /tmp/inst.txt 2>&1; check "V3c package list readable" $?
  test "$(wc -l < /tmp/inst.txt)" -gt 10; check "V3c package list is not empty" $?
  test "$(grep -cE 'liblibrescrs-dev|librescrs-middleware-devel' /tmp/inst.txt)" -eq 0
  check "V3c development package really absent" $?
fi

# ── V9 removal leaves nothing under /usr ──────────────────────────────────
# Removing by query rather than by a hand-written list. A hand-written list
# forgets the automatic debug packages and then reports leftovers that are only
# leftovers because nobody asked for them to go.
remove_ours
find /usr -iname '*librescrs*' > /tmp/leftover.txt
test ! -s /tmp/leftover.txt; check "V9 nothing left under /usr after removal" $?
[ -s /tmp/leftover.txt ] && cat /tmp/leftover.txt

exit $fail

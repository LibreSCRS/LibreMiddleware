# Arch packaging — librescrs-middleware

The `PKGBUILD` in this directory is **release-shaped**: it pulls the source
from a GitHub release tag (`v$pkgver`) the way it will once published to the
AUR. Until the tag exists, use the local-dogfood recipe below to build the
package straight from your working checkout.

## Release build (after the `v4.2.0` tag is pushed)

```sh
cd packaging/arch
updpkgsums          # fills in the two real sha256sums (tarball + OpenSC submodule)
makepkg -si
```

At tag time you MUST also refresh the OpenSC submodule pin in the second
`source=()` entry to match `git -C thirdparty/opensc-source rev-parse HEAD`.

## Local dogfood build (no remote, no tag — build from this checkout)

The release `PKGBUILD` fetches two tarballs (the project + the vendored
OpenSC fork, which a GitHub archive omits because it lives in a git
submodule). The dogfood recipe must mirror that **two-source** structure,
not collapse it into one: makepkg's `git+file://` VCS handler does **not**
fetch git submodules (see `/usr/share/makepkg/source/git.sh` — it has no
submodule handling at all), so a single `git+file://` clone of this repo
leaves `thirdparty/opensc-source/` empty and `build()` dies at OpenSC's
`./bootstrap`.

So the dogfood recipe supplies the pinned OpenSC fork as a **second local
git source**, named `OpenSC-<fullhash>` so its clone lands at
`$srcdir/OpenSC-1b2d5c5b9aa22fb174ca1f70534148e25fad1a22` — exactly the
directory the release `prepare()` already copies into
`thirdparty/opensc-source`. Because the two source dirs are named to match
what `prepare()` and the four phase `cd` lines already expect,
**neither `prepare()` nor any phase function needs editing** — only the
`source`/`sha256sums` arrays are swapped for local git equivalents.

This assumes the LibreSCRS/OpenSC fork is cloned as a **sibling** of this
repo at `../OpenSC`, with the pinned commit reachable offline (verify with
`git -C ../OpenSC cat-file -t 1b2d5c5b9aa22fb174ca1f70534148e25fad1a22`).
If your OpenSC clone lives elsewhere, adjust the `git+file://` path of the
second source accordingly.

```sh
# from the LibreMiddleware repo root
REPO="$(git rev-parse --show-toplevel)"
mkdir -p /tmp/lm-arch && cp packaging/arch/PKGBUILD /tmp/lm-arch/
cd /tmp/lm-arch
# Replace the two-entry release source=()/sha256sums=() arrays (both are
# MULTI-LINE) with local-git equivalents using the range form `/^source=(/,/^)/c\…`
# so the WHOLE array is replaced (a single-line s### would only touch the
# first line and corrupt the array). Source 1 is this repo named
# LibreMiddleware-$pkgver (matches the phase `cd` lines); source 2 is the
# sibling OpenSC fork pinned to the submodule commit and named OpenSC-<hash>
# (matches prepare()'s copy dir) so prepare() is unchanged.
sed -i \
  -e "/^source=(/,/^)/c\\source=(\"LibreMiddleware-\$pkgver::git+file://$REPO\"\n        \"OpenSC-1b2d5c5b9aa22fb174ca1f70534148e25fad1a22::git+file://$REPO/../OpenSC#commit=1b2d5c5b9aa22fb174ca1f70534148e25fad1a22\")" \
  -e "/^sha256sums=(/,/^)/c\\sha256sums=('SKIP' 'SKIP')" \
  PKGBUILD
makepkg -si
```

> Why this works: the PKGBUILD `cd`s into `$srcdir/LibreMiddleware-$pkgver`
> in all four phase functions, and `prepare()` copies
> `../OpenSC-1b2d5c5b…` into `thirdparty/opensc-source`. The first git
> source checks out to exactly `$srcdir/LibreMiddleware-$pkgver`; the second,
> named `OpenSC-1b2d5c5b…`, checks out to `$srcdir/OpenSC-1b2d5c5b…` —
> precisely where `prepare()` looks. makepkg does NOT carry submodules, so
> this explicit second source is what makes the vendored OpenSC tree present
> for the static build. Both arrays stay two-element, so `sha256sums` is two
> `'SKIP'`s.

## What the package contains

`cmake --install` lays down (under `/usr`):

- `lib/libLibreSCRS_*.so` — the core shared libraries
- `lib/librescrs/plugins/*.so` — card plugins (rs-eid, eu-vrc, rs-health,
  emrtd, pkcs15, opensc)
- `lib/pkcs11/librescrs-pkcs11.so` — the in-tree PKCS#11 module
- `include/LibreSCRS/**` — public SDK headers
- `lib/cmake/LibreMiddleware/**` — the CMake config package
- `share/librescrs/certificates/**` — bundled CA trust anchors
- `share/p11-kit/modules/librescrs.module` — p11-kit auto-discovery drop-in

OpenSSL (libcrypto) is **statically bundled** (`thirdparty/openssl-3.5.5`) and
is not a runtime dependency. The vendored OpenSC fork is built as a static
archive and linked in; there is no `system libopensc` dependency.

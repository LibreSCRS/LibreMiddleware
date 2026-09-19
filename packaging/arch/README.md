# Arch packaging — librescrs-middleware

The `PKGBUILD` in this directory is **release-shaped**: it pulls the source
tarball the release workflow uploads for the tag
(`releases/download/$pkgver/librescrs-middleware_$pkgver.orig.tar.gz`) the way
it will once published to the AUR — not GitHub's auto-generated
`archive/refs/tags/` tarball, whose bytes this project does not produce and
which omits the vendored submodule trees. Until the release exists, use the
local-dogfood recipe below to build the package straight from your working
checkout.

## Release build (after the `5.0.0` release is published)

```sh
cd packaging/arch
makepkg -g          # prints the three real sha256sums; paste them into the recipe
                    # (updpkgsums does the same but needs pacman-contrib)
makepkg -si
```

At tag time you MUST also refresh the OpenSC and curl pins in the second and
third `source=()` entries to match `git -C thirdparty/<sub> rev-parse HEAD`.
`packaging/arch/check-recipe.sh` refuses a pin that is not the gitlink, so a
stale one is caught on every push rather than at the first AUR build.

The recipe inside a release tarball is not authoritative: its `sha256sums` are
`SKIP`, because the asset they would name does not exist until the tag does. The
copy on the default branch carries the checksum of the published asset; build
from that copy, not from the one inside the tarball.

## Local dogfood build (no remote, no tag — build from this checkout)

The release `PKGBUILD` fetches three tarballs (the project's own release
asset + the two pinned upstream trees it lays over it). The dogfood recipe must
mirror that **multi-source** structure, not collapse it into one: makepkg's
`git+file://` VCS handler does **not** fetch git submodules (see
`/usr/share/makepkg/source/git.sh` — it has no submodule handling at all), so a
single `git+file://` clone of this repo leaves `thirdparty/opensc-source/` and
`thirdparty/curl-source/` empty; `build()` then dies at OpenSC's `./bootstrap`,
and configuration dies earlier still with `No download info given for
'curl_external'`.

So the dogfood recipe supplies each pinned upstream tree as its own **local git
source**, named `OpenSC-<fullhash>` and `curl-<fullhash>` so their clones land
at `$srcdir/OpenSC-07d0d40b0e4051f6fe11f3a92cec56d320670d85` and
`$srcdir/curl-75a2079d5c28debb2eaa848ca9430f1fe0d7844c` — exactly the
directories the release `prepare()` already copies into
`thirdparty/opensc-source` and `thirdparty/curl-source`. Because the source
dirs are named to match what `prepare()` and the four phase `cd` lines already
expect, **neither `prepare()` nor any phase function needs editing** — only the
`source`/`sha256sums` arrays are swapped for local git equivalents.

This assumes upstream OpenSC (OpenSC/OpenSC) and curl (curl/curl) are cloned as
**siblings** of this repo at `../OpenSC` and `../curl`, with the pinned commits
reachable offline (verify with `git -C ../OpenSC cat-file -t
07d0d40b0e4051f6fe11f3a92cec56d320670d85` and `git -C ../curl cat-file -t
75a2079d5c28debb2eaa848ca9430f1fe0d7844c`). If your clones live elsewhere,
adjust the `git+file://` paths accordingly.

The curl source is listed here for the first time. The two-entry recipe this
section used to carry named OpenSC only, so `thirdparty/curl-source` stayed
empty and configuration could not have reached `build()` at all — the third
entry is what `prepare()` has always looked for. It has not yet been exercised
end to end in a clean chroot; do that before relying on it.

```sh
# from the LibreMiddleware repo root
REPO="$(git rev-parse --show-toplevel)"
mkdir -p /var/tmp/lm-arch && cp packaging/arch/PKGBUILD /var/tmp/lm-arch/
cd /var/tmp/lm-arch
# Replace the three-entry release source=()/sha256sums=() arrays (both are
# MULTI-LINE) with local-git equivalents using the range form `/^source=(/,/^)/c\…`
# so the WHOLE array is replaced (a single-line s### would only touch the
# first line and corrupt the array). Source 1 is this repo named
# LibreMiddleware-$pkgver (matches the phase `cd` lines); sources 2 and 3 are
# the sibling upstream OpenSC and curl pinned to the submodule commits and
# named OpenSC-<hash> / curl-<hash> (matching prepare()'s copy dirs) so
# prepare() is unchanged.
sed -i \
  -e "/^source=(/,/^)/c\\source=(\"LibreMiddleware-\$pkgver::git+file://$REPO\"\n        \"OpenSC-07d0d40b0e4051f6fe11f3a92cec56d320670d85::git+file://$REPO/../OpenSC#commit=07d0d40b0e4051f6fe11f3a92cec56d320670d85\"\n        \"curl-75a2079d5c28debb2eaa848ca9430f1fe0d7844c::git+file://$REPO/../curl#commit=75a2079d5c28debb2eaa848ca9430f1fe0d7844c\")" \
  -e "/^sha256sums=(/,/^)/c\\sha256sums=('SKIP' 'SKIP' 'SKIP')" \
  PKGBUILD
makepkg -si
```

> Why this works: the PKGBUILD `cd`s into `$srcdir/LibreMiddleware-$pkgver`
> in all four phase functions, and `prepare()` copies `../OpenSC-07d0d40b…`
> and `../curl-75a2079d…` into `thirdparty/opensc-source` and
> `thirdparty/curl-source`. The first git source checks out to exactly
> `$srcdir/LibreMiddleware-$pkgver`; the second and third, named
> `OpenSC-07d0d40b…` and `curl-75a2079d…`, check out to
> `$srcdir/OpenSC-07d0d40b…` and `$srcdir/curl-75a2079d…` — precisely where
> `prepare()` looks. makepkg does NOT carry submodules, so these explicit
> extra sources are what make the vendored trees present for the static
> builds. Both arrays stay three-element, so `sha256sums` is three `'SKIP'`s.

## What the package contains

`cmake --install` lays down (under `/usr`):

- `lib/libLibreSCRS_*.so` — the core shared libraries
- `lib/librescrs/plugins/*.so` — card plugins (rs-eid, eu-vrc, rs-health,
  emrtd, pkcs15, opensc)
- `lib/pkcs11/librescrs-pkcs11.so` — the in-tree PKCS#11 module
- `include/LibreSCRS/**` — public SDK headers
- `lib/cmake/LibreMiddleware/**` — the CMake config package
- `share/librescrs/certificates/**` — bundled CA trust anchors

The package installs **no p11-kit registration**, so PKCS#11-aware
applications do not load the direct module on their own: on a desktop the card
agent is the one provider that owns the card. On a machine that deliberately
has no agent, such as a headless signing host, register the direct module with
one command:

```sh
echo 'module: /usr/lib/pkcs11/librescrs-pkcs11.so' | sudo tee /etc/pkcs11/modules/librescrs.module
```

OpenSSL (libcrypto) is **statically bundled** (`thirdparty/openssl-3.5.8`) and
is not a runtime dependency. The vendored upstream OpenSC is built as a static
archive and linked in; there is no `system libopensc` dependency.

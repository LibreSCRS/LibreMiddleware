# Vendored Third-Party Sources

## curl-source

**Upstream:** https://github.com/curl/curl
**Pinned commit:** `013468290` (tag `curl-8_22_0`, released 2026-09-02)
**License:** curl (MIT/X-derivative)
**Vendored on:** 2026-06-11 (moved to 8.22.0 on 2026-09-19)

Verifying a pin here: upstream publishes **no** `SHA256SUMS` and no per-release
hash file — only a detached `.asc` beside each tarball — so for a submodule the
signed tag is both the easier and the stronger check. The release tags are
signed by Daniel Stenberg,
`27ED EAF2 2F3A BCEB 50DB 9A12 5CC9 08FD B71E 12C2`, and unlike the OpenSSL
tags GitHub verifies them too. Check the tag, then check that the gitlink is
the commit the tag points at, because a submodule records a **commit** and not
a tag:
```
git -C thirdparty/curl-source tag -v curl-8_22_0
git -C thirdparty/curl-source rev-parse refs/tags/curl-8_22_0^{}
```

Why vendored: the host distribution's `libcurl.so` is linked against the
*system* OpenSSL, so loading it would drag a SECOND OpenSSL (the host's
`libssl`/`libcrypto.so`) into every process that also uses our bundled static
OpenSSL 3.5.8 — two OpenSSL instances in one address space. The native signing
engine registers a custom OpenSSL provider (`librescrs`) in the bundled
OpenSSL's default `OSSL_LIB_CTX`; a second OpenSSL is a portability
inconsistency (macOS universal builds have no system OpenSSL at all) and a
latent hazard. We therefore build a minimal **static** `libcurl.a` against the
**bundled** OpenSSL (`thirdparty/openssl-3.5.8`), guaranteeing exactly ONE
OpenSSL per process on every platform. curl is reached only by the TSA / CRL /
OCSP / Trusted-List HTTP paths (B-T and higher); B-B detached signing never
calls it. Built via `ExternalProject_Add(curl_external)` in
`thirdparty/CMakeLists.txt` (HTTPS-only: no ldap/psl/ssh/nghttp2/brotli/zstd/
idn2); linked through the `curl_static_with_deps` INTERFACE target.

Update procedure:
```
cd thirdparty/curl-source
git fetch origin
git tag -v <new-tag>       # must say "Good signature", then check the gitlink
git checkout <new-tag>     # e.g. curl-8_23_0
cd ../..
git add thirdparty/curl-source
# The curl build tree is keyed by LIBCURL_VERSION and the bundled OpenSSL
# directory (build/thirdparty/curl-build-<curl>-<openssl>), and curlver.h is
# a configure dependency, so the next build configures the new pin in a
# fresh tree; nothing needs deleting by hand.
# rebuild + verify the ARTEFACT, not the pin:
#   strings build/thirdparty/curl-install/lib/libcurl.a | grep -m1 'libcurl/8'
#   ldd libLibreSCRS_Signing.so shows NO system libssl/libcrypto/libcurl
```

## opensc-source

**Upstream:** https://github.com/OpenSC/OpenSC (canonical upstream — tracked directly)
**Pinned commit:** `07d0d40b0` (upstream `master`). NO downstream patches and NO fork:
every contribution we need is merged upstream —
  - Serbian CardEdge (srbeid) driver: `card-srbeid.c` / `pkcs15-srbeid.c`
    (introduced `82d8fb895`, hardened `28ace0595`, ATR-whitelist match `7d5d10ef3`).
  - srbeid RSA-2048 raw signing + decryption (`08b3debef`): advertise PKCS#1 *and* raw
    RSA, pick the MSE algorithm byte from the requested flags, P2 carries only the first
    cryptogram byte of a 256-byte block.
  - Giesecke & Devrient SCE7 PIV support in `card-piv.c` (G&D Sm@rtCafe Expert v7.0).
**License:** LGPL-2.1
**Vendored on:** 2026-06-29 (re-pointed from the LibreSCRS/OpenSC fork to upstream master;
dropped both downstream patches — the PIV SCE7 and APDU-trace patches are no longer needed).

Why vendored: avoid a runtime dependency on the host OpenSC version; pin to a known
upstream commit so the bundled `librescrs-opensc-pkcs11.so` always picks up
rs-eid / PKS / RFZO via the upstream srbeid driver irrespective of the host
distribution's OpenSC age. No patch/fork to maintain.

Update procedure:
```
cd thirdparty/opensc-source
git fetch origin
git checkout <new-sha>
cd ../..
git add thirdparty/opensc-source
# rebuild + run regression suite
```

PCSC: vendored OpenSC is built with `--enable-pcsc`; it owns its own PCSC
session per card it claims. The bundled `librescrs-opensc-pkcs11` module
runs alongside the in-tree LibreSCRS PKCS#15 module — each owns its own
PCSC connection to the card it claims, with the dispatcher in
`lib/pkcs11/` routing C_FindObjects/C_Sign requests to whichever module
asserts ownership of a given slot.

Disable: pass `-DLIBRESCRS_VENDOR_OPENSC=OFF` at configure time to skip the
~5-10 minute autoconf+make build (the resulting `librescrs-opensc-pkcs11`
fallback module will not be built either).

## openssl-3.5.x

**Upstream:** https://github.com/openssl/openssl (releases) —
https://openssl-library.org/source/
**Pinned version:** 3.5.8 (released 2026-08-25)
**License:** Apache-2.0 (`openssl-3.5.8/LICENSE.txt`)
**Source tarball SHA256:** not recorded — the archives below were vendored
before this section existed. Every version from the next one on records it.
**Signing key:** `B146 647E 45A7 B339 47AB 226B 2A2C 87D1 6169 2D40`
(primary; releases are signed by its current signing *subkey*, so compare the
fingerprint in the last field of the `VALIDSIG` line, not the first).
Keyring: https://openssl-library.org/source/pubkeys.asc — use that file, not a
keyserver: it keeps the cross-certification from the retired key
`BA54 73A2 B058 7B07 FB27 CF2D 2160 94DF D0CB 81EF`, which is the only link
back to the older, known key. `openssl-library.org/source/fingerprints.txt` is
gone (404); the historical fingerprints live in `doc/fingerprints.txt` in the
upstream git repository.

⚠ A release tag here is a signed annotated tag, but GitHub reports it as
`verified: false, reason: unknown_key` because the key is not registered with
GitHub. Verify **locally** against `pubkeys.asc`; the GitHub badge means
nothing for this project.

**This is not a source tree.** Unlike `curl-source` and `opensc-source`, what
is committed here is four prebuilt static archives —
`{linux,macosx}/lib/lib{crypto,ssl}.a` — plus the headers that match them.
`PROVENANCE.txt` beside them records what produced each one, and
`ci/scripts/check-vendored-provenance.sh` reads those properties back out of
the archives and compares. See the decisions at the end of this section for
why it is a binary and what moving to a source build would cost.

### The two platforms are not configured the same way

Measured from the `configuration.h` of the archives committed before this
section existed: Linux defined **43** `OPENSSL_NO_*` macros, macOS **49**. Six
were macOS-only — `NO_ASM`, `NO_ASYNC`, `NO_ENGINE`, `NO_AFALGENG`,
`NO_CAPIENG`, `NO_PADLOCKENG` — and **none** was Linux-only. So the macOS
archives are built without assembly, without the ENGINE API and without async,
and the Linux one had assembly and ENGINE compiled in. Neither line was written
down anywhere until now, which means a rebuild that quietly turned assembly
back on for macOS would change code paths and timings with no test able to
see it.

The Linux rebuild for 3.5.8 adds **seven** macros against that set and removes
none. Four follow from `no-engine` (`NO_ENGINE` plus the three engine
implementations `NO_AFALGENG`, `NO_CAPIENG`, `NO_PADLOCKENG`). The other three
— `NO_APPS`, `NO_DOCS`, `NO_TESTS` — follow from `no-apps no-docs no-tests`,
and their absence from the previous header says something about that build
rather than about the version: configuring 3.5.8 **without** those three emits
none of the three macros, so the archives committed before this section existed
were not built with them. None of the three changes library code; they only
skip building the apps, the manual pages and the test suite. `PROVENANCE.txt`
carries the same measurement beside the archives.

The exact configure lines, so that the `configuration.h` diff after a rebuild
is a check and not a discovery:

```
# Linux x86-64
#   no-engine: nothing in this project uses the ENGINE API, and the archive is
#   smaller and the attack surface narrower without it.
./Configure linux-x86_64 no-shared no-tests no-apps no-docs no-engine \
    --prefix=<staging> --openssldir=/usr/local

# macOS: one pass per slice, then `lipo -create`. Export the deployment
#   target first -- it pins the floor to this project's own
#   CMAKE_OSX_DEPLOYMENT_TARGET (15.0); unset, clang embeds the active SDK's
#   own version instead (26.x on a current toolchain), a floor no consumer
#   here asks for.
export MACOSX_DEPLOYMENT_TARGET=15.0
./Configure darwin64-x86_64-cc no-shared no-tests no-apps no-docs \
    no-asm no-engine no-async --prefix=<staging>
./Configure darwin64-arm64-cc  no-shared no-tests no-apps no-docs \
    no-asm no-engine no-async --prefix=<staging>
lipo -create <x86_64-staging>/lib/libcrypto.a <arm64-staging>/lib/libcrypto.a \
     -output macosx/lib/libcrypto.a          # and the same for libssl.a
```

Update procedure (the order matters; step 1 gates everything after it):
```
# 1. fetch and verify the source. No successful signature, no build: a binary
#    committed here from unverified source is worse than an old one.
cd /var/tmp && mkdir -p openssl-build && cd openssl-build
curl -sSLO https://github.com/openssl/openssl/releases/download/openssl-<ver>/openssl-<ver>.tar.gz
curl -sSLO https://github.com/openssl/openssl/releases/download/openssl-<ver>/openssl-<ver>.tar.gz.asc
curl -sSLO https://github.com/openssl/openssl/releases/download/openssl-<ver>/openssl-<ver>.tar.gz.sha256
sha256sum -c openssl-<ver>.tar.gz.sha256
curl -sSL https://openssl-library.org/source/pubkeys.asc | gpg --import
gpg --verify openssl-<ver>.tar.gz.asc openssl-<ver>.tar.gz
gpg --check-sigs B146647E45A7B33947AB226B2A2C87D161692D40 | grep -i 'D0CB81EF'

# 2. build, per platform, with the exact line above (macOS: export
#    MACOSX_DEPLOYMENT_TARGET first, see above). Never in /tmp on a box
#    where /tmp is a RAM filesystem; -j4, not -j$(nproc).
tar xf openssl-<ver>.tar.gz && cd openssl-<ver>
./Configure <line from above>
make -j4 && make install_sw
#    macOS only: replace that `make -j4` with
#    `make -j4 PLATFORM=macos-x86_64` (x86_64 slice) or
#    `make -j4 PLATFORM=macos-arm64` (arm64 slice), then `make install_sw` as
#    above. PLATFORM overrides only the "platform: " string
#    check-vendored-provenance.sh reads back out of the archive -- a plain
#    `make -j4` embeds the stock Configure target name instead
#    ("platform: darwin64-<arch>-cc"), which the gate's macOS universal-slice
#    check does not recognise (it is keyed on a `macos-` label) and which
#    does not match what PROVENANCE.txt records.

# 3. diff the OPENSSL_NO_* set of the new configuration.h against the old one,
#    per platform. Every difference is either a deliberate flag change that
#    gets written down here, or a wrong Configure line. None is ignored.
grep -oE 'OPENSSL_NO_[A-Z0-9_]+' <staging>/include/openssl/configuration.h | sort -u

# 4. copy from the INSTALLED prefix, never from the build tree: the build tree
#    still holds the .h.in templates (the Linux headers here carry 28 of them
#    from exactly that mistake, which is harmless but is the evidence that the
#    procedure was not written down).
# 5. rewrite PROVENANCE.txt from the new archives (strings -n 8 ... | grep -oE
#    'platform: |compiler: |built on: ') and record the tarball SHA256, the
#    signing key and the cross-signature output from step 1.
# 6. ci/scripts/check-vendored-provenance.sh   # must print rc 0
```

### Two recorded decisions

**The archive stays a committed binary for 5.0.** Building OpenSSL from source
in CI (a submodule plus `ExternalProject_Add`, the shape `curl-source` already
has) is the better end state and it is what this section's existence argues
for: provenance would stop being a document and become a build log, the
configure line would live in `thirdparty/CMakeLists.txt`, the version would be
a submodule pin, and roughly 33 MB of binaries would leave the git history
along with the "not a candidate for distribution packaging" objection in
`packaging/README-bundling.md`. The cost is the macOS universal build moving
into CI — two slices plus `lipo`, about ten minutes per build — and a release
cycle is the wrong place to take that on. Deferred to a 5.x cycle, deliberately.

**Linux gets `no-engine`.** The ENGINE API is unused here and has been
deprecated upstream since 3.0; leaving it compiled in costs size and surface
for nothing. macOS has been built without it since the archives were first
produced, so this also removes one of the six differences between the two
platforms rather than adding one.

## miniz

**Upstream:** https://github.com/richgel999/miniz
**Pinned release:** 3.1.2 (`thirdparty/miniz/VERSION.txt`, which the bill of
materials reads — see below for why `MZ_VERSION` is not that number). Not a
bare `VERSION`: this directory is on the include path, and on a case-insensitive
file system the standard library's own `#include <version>` opens that file.
`ci/scripts/check-include-shadowing.py` fails the build on any such name.
**License:** MIT (`thirdparty/miniz/LICENSE`)
**Vendored form:** the amalgamated `miniz.c` + `miniz.h`, generated upstream by
`amalgamate.sh`, **plus two local patches** (below), compiled into `LibreSign.a`
(`lib/libresign/CMakeLists.txt`). It is the ZIP/inflate implementation behind
the ASiC-E container reader, so it runs over a file the user brings.

### Reading the version, which does not say what it looks like

miniz's `MZ_VERSION` is the **zlib-compatibility** version, not the miniz
release. Measured against upstream tarballs:

| upstream release | `MZ_VERSION` | `MZ_VERNUM` |
|---|---|---|
| 2.1.0 | `10.1.0` | `0xA100` |
| 3.1.2 | `11.3.2` | `0xB302` |

So a copy reporting `10.1.0` / `0xA100` is upstream **2.1.0**, from 2019 — and
the leading digit is the series: `10.x` is the 2.x line, `11.x` the 3.x line.
Anyone reading `MZ_VERSION` as the release number reads it two major series
wrong, which is how a 2019 decoder can look current in a dependency listing.
The bill of materials reports this macro, so this table is what decodes it.

### Why the copy moved to 3.1.2

Upstream 3.1.2 (2026-07-01) is a security release. Two of its fixes were
measured against the copy that was here before, named rather than eyeballed,
and **both were missing**:

1. **An inflate stream that decodes a symbol in zero bits loops forever.**
   The guard exists in three places in the decoder. The vendored 2.1.0 copy
   carried it in the `TINFL_HUFF_DECODE` macro only (`if ((code_len) && (num_bits
   >= code_len))`). The two fast-path decodes inside `tinfl_decompress` --
   the literal/length pair that the inner loop runs for every symbol -- read
   `code_len`, shifted the bit buffer by it, and never checked it against zero.
   Upstream 3.1.2 ends both with `if (code_len == 0) TINFL_CR_RETURN_FOREVER(...,
   TINFL_STATUS_FAILED)`. This is the reappearance of a fault first fixed in
   2018; a crafted container makes the reader spin instead of failing.
2. **The central-directory bounds check could be passed by overflowing it.**
   The vendored copy tested `(cdir_ofs + (mz_uint64)cdir_size) > m_archive_size`.
   In the ZIP64 path both operands are 64-bit values read straight out of the
   file, so their sum can wrap and the comparison then succeeds on an offset
   that is nowhere in the archive. Upstream 3.1.2 tests the subtraction form
   instead: `cdir_size > m_archive_size || cdir_ofs > m_archive_size - cdir_size`,
   which cannot wrap.

### The two local patches, and why dropping them is not an option

This copy is **not** pristine upstream. Both patches live in
`mz_zip_writer_add_mem_ex_v2`, are marked `LibreSCRS local patch` in the
source, and are one change in two halves:

1. The data-descriptor bit (general-purpose flag bit 3) is set only for
   DEFLATED entries, whose compressed size is genuinely unknown until the
   stream ends. Upstream sets it for every entry.
2. A STORED entry therefore has no trailing descriptor, so its local file
   header is rewritten in place with the real CRC and sizes once the data is
   written.

Why it matters: ETSI EN 319 162-1 containers are read by Java tooling, and
`java.util.zip.ZipInputStream` **refuses** a STORED entry that claims a data
descriptor. An ASiC-E container written without these patches parses fine with
command-line unzip and with Python, and reports **zero signatures** to the ETSI
validator — the signature is there, and nothing can reach it. This is what the
independent validator in the signing end-to-end tests exists to catch, and it
is what it caught when the bump first landed without them re-applied.

Upstream 3.1.2 sets the bit unconditionally, so the patches had to be
re-applied by hand on top of it. **Re-apply them on every future bump**, then
run the ASiC-E end-to-end tests with the validator enabled; a container that
opens with unzip proves nothing here.

Update procedure:
```
# Upstream ships the pieces, not the amalgamation; generate it the way the
# release does, and copy only the two files.
git clone --depth 1 --branch <ver> https://github.com/richgel999/miniz
cd miniz && ./amalgamate.sh          # writes amalgamation/miniz.{c,h}
cp amalgamation/miniz.c amalgamation/miniz.h <repo>/thirdparty/miniz/
cp LICENSE <repo>/thirdparty/miniz/LICENSE
echo <ver> > <repo>/thirdparty/miniz/VERSION.txt
# RE-APPLY the two local patches above, then:
#   ctest -R 'MinizZipBounds|ZipRecords|ASiC|Asic'      with the ETSI validator
#   ci/scripts/make-sbom.sh /tmp/sbom.json              must print the new version
#   ci/scripts/abi-snapshot.sh --check build            miniz lands in LibreSign.a
```

`thirdparty/licenses.json` has no miniz row and that is not an oversight: its
`match` field names a build target, and miniz has none — it is compiled into
`LibreSign.a` alongside the other header-only vendored code. The licence text
sits beside the sources instead, and the version is in the bill of materials.

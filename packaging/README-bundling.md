# What these packages bundle, and why they are not distribution candidates

The `deb`, `rpm` and Arch packages built from this repository carry several
dependencies inside the artefact rather than resolving them against the host.
That is a deliberate position, and this file states it plainly so the next
reader does not have to reconstruct it from build files.

## What is bundled

| bundled | form | pin |
|---|---|---|
| OpenSSL 3.5.8 | pre-compiled static archives committed to the tree | `thirdparty/openssl-3.5.8/` |
| curl 8.11.1 | submodule, built statically against the bundled OpenSSL | `75a2079d5c28debb2eaa848ca9430f1fe0d7844c` |
| OpenSC | submodule, built statically | `07d0d40b0e4051f6fe11f3a92cec56d320670d85` |
| miniz, nlohmann/json | source drop-in | in tree, `thirdparty/` |
| QCBOR | FetchContent by commit, absorbed into the agent client library | pinned in LibreAgent |

The OpenSC and curl pins above are the ones the Arch recipe fetches by URL, so
`packaging/arch/PKGBUILD` and this table move together.

## Why OpenSSL cannot come from the system

The native signing engine registers its own OpenSSL provider in the default
`OSSL_LIB_CTX`. A process that loaded two OpenSSL builds would have two
default library contexts and the provider would be visible from only one of
them, so there has to be exactly one OpenSSL per process, and the only way to
guarantee that across every host layout is to carry it.

## What that costs, stated rather than hidden

These packages are built and published by the project, from the project's own
repository. They are **not** candidates for the Debian or Fedora archives while
a pre-compiled OpenSSL sits in git; both archives require the system copy.

A CVE in the bundled OpenSSL is invisible to every distribution security
tracker and every container scanner, because nothing in the shipped metadata
says OpenSSL 3.5.8 is inside. That is why a bill of materials ships beside
every artefact — it is the only place the bundled versions are ever named.

`lintian` and `rpmlint` findings in the `embedded-library` family are accepted
knowingly and **no override files are written for them**. An override would
hide the position from the next reader, which is the opposite of what this file
is for. Measured: `lintian` flags the bundled curl and says nothing at all
about the bundled OpenSSL, so the tooling catches one of the two anyway.

## Consequences for the target matrix

The committed OpenSSL archives contain x86_64 objects only, and they reference
`__isoc23_*` symbols that exist from glibc 2.38 onward. Both facts are
architecture and baseline constraints on every package built here, not
packaging choices:

- x86_64 only, on every distribution;
- glibc 2.38 or newer, which excludes Debian 12 and Ubuntu 24.04 and older.

## Is unbundling curl a one-flag change

No, and this was measured rather than assumed. `-DLIBRESCRS_VENDOR_CURL=OFF`
configures without complaint — CMake accepts the then-undefined
`curl_static_with_deps` as a plain library name — and the build fails on the
first translation unit that includes `<curl/curl.h>`, because the option has no
`else()` branch that looks for a system curl. Taking curl from the system means
writing that branch and re-testing the static link order of
libcurl/libssl/libcrypto/zlib, which is a change to this repository, not a
change to a packaging recipe.

## What the packaging lint says, measured

Run on the real Debian 13 packages:

```
E: liblibrescrs5: embedded-library curl [.../libLibreSCRS_Trust.so.5.0.0]
E: liblibrescrs5: embedded-library curl [.../libLibreSCRS_Signing.so.5.0.0]
W: liblibrescrs5: package-name-doesnt-match-sonames libLibreSCRS-Auth5 …
```

Both findings are accepted knowingly, and **no override file is written for
either**.

The `embedded-library` errors are the position this file states, showing up
where it should. Note what is *not* in that list: the bundled OpenSSL. The tool
catches one of the two bundles, which is why the bill of materials is the
obligation and the lint is not.

`package-name-doesnt-match-sonames` is the consequence of shipping seven shared
libraries in one runtime package rather than seven packages of one library each.
They have a single SOVERSION, they are released together, and nothing consumes
one without the others; splitting them would multiply the package count by seven
and buy nobody anything.

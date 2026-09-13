# LibreMiddleware libFuzzer harnesses

This directory contains continuous-fuzzing entrypoints for LibreMiddleware's
public parsers. Each harness is a libFuzzer driver built with
`-fsanitize=fuzzer,address,undefined`.

Those flags are `PRIVATE` on the executable, so they reach the harness's own
sources and nothing else: the libraries it links are built without any
sanitizer. A harness that only links the code it fuzzes therefore fuzzes
uninstrumented code, and a scalar read past the end of a buffer is not reported
at all. A harness that wants the code under test instrumented **compiles that
source into itself**, as the three eMRTD harnesses below do.

| Harness                          | Target                                                 |
| -------------------------------- | ------------------------------------------------------ |
| `fuzz_parsed_certificate`        | `LibreSCRS::Certificate::ParsedCertificate::fromDer`   |
| `fuzz_trusted_list_parser`       | `libresign::TrustedListParser::parse`                  |
| `fuzz_tl_signature_verifier`     | `libresign::TlSignatureVerifier::verify`               |
| `fuzz_csca_master_list`          | `emrtd::crypto::parseCscaMasterList`                   |
| `fuzz_emrtd_sod`                 | `emrtd::crypto::parseSOD`                              |
| `fuzz_emrtd_card_access`         | `emrtd::crypto::parseCardAccess`                       |
| `fuzz_emrtd_security_info`       | `emrtd::crypto::parseDG14` / `parseDG15`               |

The signature verifier harness embeds the committed test signing certificate
(`test/fixtures/trust/test-tl-signing-cert.pem`) so that `verify()` exercises
the libxml2 C14N + OpenSSL EVP code path on every input.

## Build

Requires Clang (libFuzzer is a Clang feature; GCC is not supported).

```bash
cmake -B build-fuzz -S . \
    -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
    -DCMAKE_BUILD_TYPE=RelWithDebInfo \
    -DSIGNING_BACKEND=both \
    -DLIBRESCRS_BUILD_FUZZ=ON
cmake --build build-fuzz -j4
```

Apple Clang on macOS additionally needs `-fexperimental-library` for the
C++23 standard-library features (`std::expected`, `std::stop_token`) that
LibreMiddleware uses; CMake configures the flag on the affected targets.

## Run

```bash
./build-fuzz/fuzz/fuzz_parsed_certificate    -max_total_time=60 fuzz/corpus/parsed_certificate
./build-fuzz/fuzz/fuzz_trusted_list_parser   -max_total_time=60 fuzz/corpus/trusted_list_parser
./build-fuzz/fuzz/fuzz_tl_signature_verifier -max_total_time=60 fuzz/corpus/tl_signature_verifier
./build-fuzz/fuzz/fuzz_csca_master_list      -max_total_time=60 fuzz/corpus/csca_master_list
./build-fuzz/fuzz/fuzz_emrtd_sod             -max_total_time=60 fuzz/corpus/emrtd_sod
./build-fuzz/fuzz/fuzz_emrtd_card_access     -max_total_time=60 fuzz/corpus/emrtd_card_access
./build-fuzz/fuzz/fuzz_emrtd_security_info   -max_total_time=60 fuzz/corpus/emrtd_security_info
```

CI runs each harness for 60 s on every PR; the Monday cron job runs longer.
Local soak runs of an hour or more are recommended before any tag.

## Adding new harnesses

1. Add `fuzz_<name>.cpp` exposing `LLVMFuzzerTestOneInput`.
2. Register the executable in `fuzz/CMakeLists.txt` with the same compile/link
   flags as the existing ones. If the code under test must be instrumented,
   list its source in the `add_executable` call rather than relying on the
   library link, and take that library's PRIVATE include directories from a
   `cmake/` module the library itself reads -- never a second hand-written
   copy. PRIVATE settings do not arrive over the link, and a copy drifts: one
   did, and three harnesses stopped compiling with nothing in an ordinary
   build to say so. `EMRTDCrypto` shares its list through
   `cmake/EmrtdCryptoPrivateIncludes.cmake`, and the top-level CMakeLists.txt
   fails the configure if the target and that list disagree. Compile
   definitions are still spelled out per target: the internal headers `#error`
   on a missing `LIBRESCRS_INTERNAL_BUILD`, so that one fails loudly by
   itself. Confirm instrumentation with
   `nm -u <target>.dir/**/<source>.cpp.o | grep -c asan_report`, which must be
   non-zero.
3. Create `fuzz/corpus/<name>/` with hermetic seed inputs (real-world fixtures
   from `test/test-data/` or `test/fixtures/` plus a few small malformed
   examples).
4. Append the harness to the matrix in `.github/workflows/fuzz.yml`.

## Reporting crashes

A crash dumps to `crash-<sha1>` (or under `-artifact_prefix=`). Save the input,
add it to the corpus as a regression seed, file an issue, and gate the fix
behind a regression test under `test/`.

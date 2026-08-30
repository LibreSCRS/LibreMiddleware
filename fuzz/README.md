# LibreMiddleware libFuzzer harnesses

This directory contains continuous-fuzzing entrypoints for LibreMiddleware's
public parsers. Each harness is a libFuzzer driver compiled against
`LibreMiddleware` static libraries with `-fsanitize=fuzzer,address,undefined`.

| Harness                          | Target                                                 |
| -------------------------------- | ------------------------------------------------------ |
| `fuzz_parsed_certificate`        | `LibreSCRS::Certificate::ParsedCertificate::fromDer`   |
| `fuzz_trusted_list_parser`       | `libresign::TrustedListParser::parse`                  |
| `fuzz_tl_signature_verifier`     | `libresign::TlSignatureVerifier::verify`               |
| `fuzz_csca_master_list`          | `emrtd::crypto::parseCscaMasterList`                   |

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
```

CI runs each harness for 60 s on every PR; the Monday cron job runs longer.
Local soak runs of an hour or more are recommended before any tag.

## Adding new harnesses

1. Add `fuzz_<name>.cpp` exposing `LLVMFuzzerTestOneInput`.
2. Register the executable in `fuzz/CMakeLists.txt` with the same compile/link
   flags as the existing ones.
3. Create `fuzz/corpus/<name>/` with hermetic seed inputs (real-world fixtures
   from `test/test-data/` or `test/fixtures/` plus a few small malformed
   examples).
4. Append the harness to the matrix in `.github/workflows/fuzz.yml`.

## Reporting crashes

A crash dumps to `crash-<sha1>` (or under `-artifact_prefix=`). Save the input,
add it to the corpus as a regression seed, file an issue, and gate the fix
behind a regression test under `test/`.

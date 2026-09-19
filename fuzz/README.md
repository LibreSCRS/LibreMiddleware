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
| `fuzz_pkcs15_parser`             | `pkcs15::parseODF` and the other directory parsers     |
| `fuzz_emrtd_dg_parser`           | `emrtd::parseDataGroups` / `parseMRZ`                  |
| `fuzz_chunked_read`              | `SmartCard::Internal::readChunkedFile`                 |
| `fuzz_pdf_parser`                | `libresign::PdfParser` xref / trailer walk             |
| `fuzz_asic_reader`               | `libresign::detail::tryParseAsic` / `probeAsic`        |
| `fuzz_rs_tlv`                    | `SmartCard::Internal::parseTLV` and the UTF-16 decode  |
| `fuzz_ber`                       | `SmartCard::Internal::parseBER` and both length decoders |
| `fuzz_eu_vrc`                    | `euvrc::detail::deriveEuVrcHeader` / `extractFields`   |

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
2. Add a row to `fuzz/instrumented-sources.txt`: either
   `fuzz_<name>: path/to/source.cpp` for each source compiled into the harness,
   or `fuzz_<name>: LINK_ONLY  # <why> -- due YYYY-MM-DD` when it
   deliberately only links. **This is not optional and not last:** three things
   read that file -- `fuzz/CMakeLists.txt` compiles what it names,
   `ci/scripts/check-fuzz-instrumentation.sh` reads the objects back to prove the
   sanitizer flags arrived, and the workflow compares it against both the corpus
   directories and the job matrix. A harness missing from it fails the configure;
   a LINK_ONLY row without a reason and a future date fails the check.
3. Register the executable in `fuzz/CMakeLists.txt`, taking its sources from
   `${LIBRESCRS_FUZZ_SRC_fuzz_<name>}` so the declaration above is what decides,
   with the same compile/link flags as the existing ones. If the code under test
   must be instrumented, list its source in the declaration rather than relying
   on the library link, and take that library's PRIVATE include directories from a
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
4. Create `fuzz/corpus/<name>/` with hermetic seed inputs and a `README.md`
   saying where each one came from. An undocumented seed is a constant with no
   provenance, and the workflow refuses a harness whose corpus directory is
   missing or empty.
5. Append the harness to the matrix in `.github/workflows/fuzz.yml`. The
   workflow checks that the matrix, the declaration and the corpus directories
   name the same set, so leaving any one of the three out is red rather than
   silently unfuzzed.

## Reporting crashes

A crash dumps to `crash-<sha1>` (or under `-artifact_prefix=`). Save the input,
add it to the corpus as a regression seed, file an issue, and gate the fix
behind a regression test under `test/`.

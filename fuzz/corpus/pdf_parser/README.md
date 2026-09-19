<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Seed corpus: `fuzz_pdf_parser`

There is no PDF under `test/test-data/` to copy: the parser tests build their
documents in code, `"%PDF-1.4\n"` first, at nine separate places in
`test/pdf_parser_test.cpp`. These seeds are the smallest of those shapes
written out, so a reader can tell where each one came from rather than
finding five constants with no provenance.

| file | what it is, and where the shape comes from |
|---|---|
| `minimal-catalog-pages-page` | the four-object document `buildMinimalPdf()` assembles: catalog, pages, one page with the common attributes, one content stream, and a classic xref table |
| `two-pages` | the same, with two `/Kids`, so the page lookup has a branch to choose |
| `nested-pages-tree` | a `/Pages` node inside `/Pages` — the recursive branch of the tree walk, the one the depth guard exists for |
| `incremental-update-prev-chain` | a second xref section appended and chained through `/Prev`, the shape an incremental signature update produces |
| `leading-wrapper-before-header` | bytes before `%PDF-`, which the engine accepts anywhere in the first 1024 and the input check once refused |
| `deep-pages-tree-needs-the-depth-guard` | **found by this harness**, not written by hand: raise `kMaxParseDepth` and these 644 bytes exhaust the stack in under a minute. Kept so the guard is exercised on every run rather than only when someone remembers to remove it |

None of these is a real document and none carries a signature: a seed only has
to reach the code, and libFuzzer does the rest.

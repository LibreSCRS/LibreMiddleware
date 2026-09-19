<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Seed corpus: `fuzz_ber`

ISO 7816-4 BER-TLV, one seed per branch the walker and the two length/tag
decoders take. The shapes come from the fixtures in `test/` and from the
`MockCardSpec` responses the vehicle-registration tests serve; they are written
out here as bytes rather than as a builder so the harness does not need the test
support library to have a corpus.

| file | what it is |
|---|---|
| `primitive-short-length` | tag `71`, short-form length, three value bytes |
| `constructed-with-two-children` | a constructed field with two primitive children — the recursive branch |
| `long-form-two-length-octets` | `82 00 04`, the long form with two length octets |
| `multi-byte-tag` | `7F 21`, the continuation-byte tag path |
| `indefinite-length-rejected` | `80`, which the decoder refuses by contract |
| `length-declares-more-than-present` | a length larger than the bytes that follow |
| `nested-24-deep` | twenty-four constructed levels, under the walker's bound of thirty-two, so the recursion is exercised without expecting a crash |

The depth bound is real and was measured: raise `maxDepth` and a 250 KB input
nested fifty thousand levels deep exhausts the stack. libFuzzer does not find
that on its own at the default input ceiling of 4096 bytes, because each level
costs bytes and the depth it can reach is bounded by the input size -- so the
bound is proved by a hand-built input rather than by a session, and that is
worth knowing before anyone reads a green run as coverage of it.

No bytes from a real card are here.

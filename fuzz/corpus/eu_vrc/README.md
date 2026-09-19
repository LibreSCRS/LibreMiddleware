<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Seed corpus: `fuzz_eu_vrc`

Every seed is eight big-endian bytes of "what the FCI said the file size was",
followed by the header bytes. The shapes come from `test/eu_vrc_test.cpp`, which
has ten cases over this path, and from the header-derivation tests added beside
them.

| file | what it is |
|---|---|
| `fci-zero-declares-two-thousand` | FCI size zero, so the BER length at the data offset is what decides — the branch that legitimately returns a number larger than the buffer in hand |
| `fci-size-wins` | the same header with an FCI size of 4096, so the length walk is skipped entirely |
| `fci-zero-larger-buffer` | the same header in a bigger buffer: the answer must not depend on the buffer's size |
| `readable-field-tree` | a BER tree the field walk can actually read — registration number, make, VIN and one national tag |
| `nxp-header-skip-fallback` | bytes that do not parse as BER from zero, so the NXP header-skip path computes the data offset from `hdr[1] + 2` |
| `indefinite-length-rejected` | `80`, which the decoder refuses by contract |
| `header-shorter-than-two-bytes` | one byte of header, the early return |

No bytes from a real vehicle registration card are here; the registration
number, make and VIN are invented.

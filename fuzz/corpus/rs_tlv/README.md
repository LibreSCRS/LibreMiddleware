<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Seed corpus: `fuzz_rs_tlv`

Both Serbian card families read their fields through this reader: a
little-endian 16-bit tag, a 16-bit length, and a UTF-16 value. The tag numbers
used here are the ones the readers really ask for, defined in
`lib/rs-eid-core/src/rs_tags.h` and reached through `protocol::TAG_*` in
`lib/rs-eid/src/card_protocol.h`.

| file | what it is |
|---|---|
| `two-utf16-fields` | surname and given name, the shape every read starts with |
| `every-requested-tag` | all six tags the harness looks up, so a lookup miss is not the only path covered |
| `length-past-the-buffer` | a field declaring 65535 bytes with two present — the card chooses this number |
| `odd-length-utf16` | three bytes in a UTF-16 value, so the decode has half a code unit at the end |
| `lone-surrogate-utf16` | a high surrogate with no low surrogate after it |
| `empty` | no bytes at all |

No bytes from a real card are here. The names are invented and the values are
the shortest thing that reaches the code.

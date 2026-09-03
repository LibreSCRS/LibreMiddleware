# `EF.CardAccess` seed corpus

`EF.CardAccess` is read from the master file over a plain channel, before any
key, PIN, CAN or MRZ exists, so every byte here is whatever the chip chose to
send. Each file is the raw file content as `parseCardAccess` receives it.

| File | What it encodes |
| --- | --- |
| `ca_good.bin` | One `SecurityInfo` SEQUENCE: PACE-ECDH-GM-AES-CBC-CMAC-128, version 2, parameter 12. |
| `ca_test_single.bin` | Same shape, parameter 13. |
| `ca_test_multi.bin` | Two `SecurityInfo` entries with different PACE OIDs. |
| `ca_test_multi_params.bin` | Two entries whose parameter IDs differ (13 and 12). |
| `ca_test_nonpace.bin` | A `SecurityInfo` carrying an OID that is not a PACE OID. |
| `ca_test_noparam.bin` | A `SecurityInfo` with the OID and version but no parameter INTEGER. |
| `ca_seqend_wrap.bin` | An eight-octet SEQUENCE length whose value makes `pos + length` wrap. |
| `ca_skip_wrap.bin` | The same eight-octet length behind a non-SEQUENCE tag, so it is taken by the skip branch. |
| `ca_fuzz_found_hang.bin` | A **four**-octet length that wraps the cursor: a cap on the number of length octets does not exclude it. |

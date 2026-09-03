# `EF.SOD` seed corpus

Each file is a CMS `SignedData`. `parseSOD` walks the `LDSSecurityObject`
eContent before any signature over it has been verified, so the eContent bytes
are attacker-chosen. Only `sod_good.bin` carries the ICAO `0x77` wrapper; the
hostile four are bare CMS, which is also what `extractCMSFromSOD` accepts.

| File | eContent |
| --- | --- |
| `sod_good.bin` | SHA-256, two data group hashes, LDS version `0108`, unicode version `040000`. |
| `sod_oob_hashlen.der` | A data group hash whose length is `04 82 0F FF` — 4095 declared, four bytes present. |
| `sod_oob_ldsver.der` | An LDS version string whose length is `13 82 02 00` — 512 declared, one byte present. |
| `sod_oob_dgnum.der` | A data group number whose length is `02 82 10 00` — 4096 declared, one byte present. |
| `sod_oob_hashlen_1g.der` | A data group hash whose length is `04 84 40 00 00 00` — 0x40000000 declared, four bytes present. |

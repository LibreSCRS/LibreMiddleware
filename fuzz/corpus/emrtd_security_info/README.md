# DG14 / DG15 seed corpus

DG14 and DG15 are read and walked before any signature over them has been
checked, so their bytes are card-controlled. Each file is the raw data group as
`parseDG14` / `parseDG15` receives it.

| File | What it encodes |
| --- | --- |
| `dg14_seqend_wrap.bin` | `0x6E` wrapper around a SET whose SEQUENCE length is eight octets and wraps `pos + length`. |
| `dg14_skip_wrap.bin` | The same wrapping length reached through the skip branch. |
| `dg14_spki_wrap.bin` | A well-formed `ChipAuthenticationPublicKeyInfo` whose `SubjectPublicKeyInfo` length wraps, so the total length underflows and yields an inverted iterator range. |
| `dg14_spki_wrap_f0.bin` | The same shape, one length value lower. |
| `dg14_spki_wrap_f5.bin` | The same shape, another length value in the wrapping range. |

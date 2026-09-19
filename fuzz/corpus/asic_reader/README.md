<!-- SPDX-License-Identifier: LGPL-2.1-or-later -->
# Seed corpus: `fuzz_asic_reader`

Where each seed comes from. `test/asic_module_test.cpp` builds its containers
with the miniz writer and `test/signing_e2e_test.cpp` carries the zip-slip
input; these are the same shapes, written here with Python's ZIP writer so that
a seed does not depend on the implementation under test in order to exist.

| file | what it is |
|---|---|
| `asice-one-signer` | the shape the reader accepts: `mimetype` stored first, one data file, one `signature001.p7s` + `ASiCManifest001.xml` pair |
| `asice-two-signers` | the same with two pairs, so the "next free signature number" walk has to arrive at three |
| `zip-slip-meta-entry-name` | a `META-INF/../../etc/passwd` entry — the name the entry-name validator exists to refuse, the same input the end-to-end signing test uses |
| `mimetype-only` | a container with nothing but the mimetype, which must be rejected rather than treated as having a data file |
| `wrong-mimetype-plain-zip` | a valid ZIP that is not ASiC-E |
| `no-mimetype-entry` | a signature present with no mimetype entry at all |
| `mimetype-declares-three-gigabytes` | **found by this harness**, not written by hand: 145 bytes whose mimetype entry declares a three-gigabyte uncompressed size. The reader capped every other entry before extracting it and this one first, so the allocation happened before any cap was consulted. Kept so the cap is exercised on every run |

No bytes from a real card or a real signed document are here: a seed only has
to reach the code.

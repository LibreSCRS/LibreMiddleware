# Vendored OID database sources

`openssl-objects.txt` is vendored from
https://github.com/openssl/openssl/blob/openssl-3.2.0/crypto/objects/objects.txt
under the OpenSSL/SSLeay license (BSD-style, compatible with LGPL-2.1-or-later).

## Update procedure

To refresh from a newer OpenSSL release:

```bash
curl -fsSL https://raw.githubusercontent.com/openssl/openssl/openssl-X.Y.Z/crypto/objects/objects.txt \
     -o openssl-objects.txt
```

Then re-run the build — `tools/generate_oid_table.py` regenerates the
sorted constexpr table from this file plus the LibreSCRS-curated TSVs
under `data/oid-database/`.

## License

The OpenSSL `objects.txt` file is part of the OpenSSL project under the
OpenSSL and SSLeay licenses (BSD-style). Both licenses are compatible with
LibreMiddleware's LGPL-2.1-or-later. See https://www.openssl.org/source/license-openssl-ssleay.txt
for the full upstream text.

The LibreSCRS-curated TSV files in `../../data/oid-database/` are authored
under LGPL-2.1-or-later (same as LibreMiddleware itself).

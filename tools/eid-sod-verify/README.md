# eid-sod-verify

Independent PC/SC diagnostic that reads a Serbian eID card's Security Object
(SOD) and verifies it end-to-end, printing the signer identity and a verdict.

It is deliberately **independent** of the in-tree `rs-eid` verification code, so it
can serve as an oracle when diagnosing a card — including future MUP certificate
generations, where the signer certificate changes but the card read path does not.

## Verification layers

A card SOD is trustworthy only if all three hold (chain-only is insufficient — an
attacker could embed a genuine public MUP signer certificate in a forged, unsigned
SOD):

1. **Signature** — the SOD content is signed by the signer's key (`PKCS7_verify`).
2. **Chain** — the signer chains to the bundled MUP masterlist (`X509_verify_cert`).
3. **Domain pin** — the signer's issuer is a MUP *Resursi* (resources) CA. The MUP
   PKI issues citizen ("Gradjani") and officials ("Sluzbenici") certificates from
   sibling CAs under the same roots, so chain-to-a-MUP-root alone is not enough.

## Build & run

```bash
cmake --build build --target eid-sod-verify
./build/tools/eid-sod-verify/eid-sod-verify            # first reader with a card
./build/tools/eid-sod-verify/eid-sod-verify --reader "Gemalto PC Twin Reader ..." --var
```

Options: `--reader <name>`, `--certs <dir>` (masterlist root holding `rs-mup/` and
`rs-mup-format/`; defaults to the bundled certificates dir), `--var` (variable-data
SOD). Exit code is `0` only on `VALID`.

## Note

The bundled masterlist contains malformed legacy MUP CA certificates (non-minimal
DER serial numbers) that OpenSSL 3.5+ rejects at load time; they are silently
skipped. Current-generation cards chain through the g4 hierarchy (`MUP Root CA 4` /
`MUP Resursi CA 4`), which loads and verifies.

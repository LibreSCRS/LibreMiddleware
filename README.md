# LibreMiddleware

**[librescrs.github.io](https://librescrs.github.io)**

Qt-free C++20 static libraries for reading smart cards via direct PC/SC APDU communication.

## Supported Cards

- **eMRTD / ePassport** — ICAO 9303 compliant passports and national ID cards (PACE, BAC, Secure Messaging)
- **Serbian eID** — Gemalto 2014+, IF2020 Foreigner (personal data, photo, certificates)
- **Serbian Vehicle Registration (EU VRC)** — EU Directive 2003/127/EC (all mandatory and optional fields)
- **Serbian Health Insurance (RFZO)** — insured person, employer, insurance details
- **PIV (NIST SP 800-73)** — certificates, photo, fingerprints, PIN management
- **PKCS#15** — generic PKI card support (certificate discovery, PIN management, digital signing)

## Libraries

- **SmartCard** — PC/SC connection management, APDU, TLV/BER-TLV encoding
- **RsEId** — Serbian eID card protocol
- **EuVrc** — EU vehicle registration card protocol
- **RsHealth** — Serbian health insurance card protocol
- **eMRTD** — electronic travel document protocol with cryptographic authentication
- **PIV** — NIST PIV card protocol
- **PKCS15** — PKCS#15 token operations
- **CardEdge** — CardEdge applet operations (PIN management, signing, certificate discovery)
- **CardEdge PKCS#11** — shared library for Firefox, Thunderbird, and other PKCS#11-aware applications
- **CardEdge OpenSC Driver** — external OpenSC driver for CardEdge-based cards

## License

LGPL-2.1-or-later — see [LICENSE](LICENSE) for details.

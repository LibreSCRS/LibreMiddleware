# eMRTD + PKCS#15 — Card Profile

## Overview

| Property | Value |
|----------|-------|
| Profile | Electronic identity card with eMRTD and PKCS#15 applets |
| Known ATRs | Varies by issuing country |
| Known Cards | Foreign eID cards with ICAO-compliant chip |

## Applets Present

| Applet | AID | Documentation |
|--------|-----|---------------|
| eMRTD | `A0 00 00 02 47 10 01` | [emrtd-applet.md](../applets/emrtd-applet.md) |
| PKCS#15 | Discovered via AID SELECT or EF.DIR | [pkcs15-applet.md](../applets/pkcs15-applet.md) |

## Card-Specific Notes

- This profile represents foreign (non-Serbian) eID cards that combine an ICAO eMRTD applet with a PKCS#15 cryptographic token applet on the same chip.
- The eMRTD applet stores biometric data (photo, MRZ, optionally fingerprints) accessible via PACE authentication.
- The PKCS#15 applet provides PKI functionality: X.509 certificates, PIN-protected private keys, and digital signing capabilities.
- The PKCS#15 applet is discovered using either direct AID SELECT or the EF.DIR fallback mechanism (reading MF/2F00 to find the DF path).
- ATR patterns vary by card manufacturer and issuing country; card detection relies on applet probing rather than ATR matching.
- Cards matching this profile expose both applets, allowing LibreSCRS to read travel document data and perform PKI operations.

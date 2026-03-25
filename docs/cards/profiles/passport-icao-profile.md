# ICAO Passport — Card Profile

## Overview

| Property | Value |
|----------|-------|
| Profile | ICAO-compliant machine readable travel document (passport) |
| Known ATRs | Varies by issuing country and chip manufacturer |
| Known Cards | Any ICAO Doc 9303 compliant e-passport |

## Applets Present

| Applet | AID | Documentation |
|--------|-----|---------------|
| eMRTD | `A0 00 00 02 47 10 01` | [emrtd-applet.md](../applets/emrtd-applet.md) |

## Card-Specific Notes

- This profile covers standard electronic passports (e-passports) from any country that implements ICAO Doc 9303.
- Only the eMRTD applet is present. There is no PKCS#15 or other PKI applet on standard passports.
- Authentication is required before reading Data Groups via PACE. The MRZ printed in the passport provides the key material.
- Mandatory data: DG1 (MRZ) and DG2 (facial image). Optional data varies by country (DG7 signature, DG11 additional personal details, DG12 issuing authority info, etc.).
- DG3 (fingerprints) and DG4 (iris) require Extended Access Control (EAC), which needs issuing-country authorization certificates.
- ATR patterns are not reliable for identifying passports; detection is based on successful eMRTD AID selection (`A0 00 00 02 47 10 01`).
- EF.CardAccess (SFI 0x1C) must be read from the MF before applet SELECT when using PACE authentication.

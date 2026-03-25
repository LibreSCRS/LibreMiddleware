# CardEdge Only — Card Profile

## Overview

| Property | Value |
|----------|-------|
| Profile | Standalone CardEdge PKI card (no identity data applet) |
| Known ATRs | `3B DE 97 00 80 31 FE 45 53 43 45 20 38 2E 30 2D 43 31 56 30 0D 0A 2E` (PKS) |
| Known Cards | PKS qualified signature card (Privredna komora Srbije — Serbian Chamber of Commerce) |

## Applets Present

| Applet | AID | Documentation |
|--------|-----|---------------|
| CardEdge PKI | `A0 00 00 00 63 50 4B 43 53 2D 31 35` | [cardedge-applet.md](../applets/cardedge-applet.md) |

## Card-Specific Notes

- This profile covers cards where the CardEdge PKI applet is the **only** applet present. There is no identity data applet (no eID, health, or vehicle data).
- The primary known card is the PKS (Privredna komora Srbije) qualified electronic signature card, used by businesses for legally binding digital signatures.
- The PKS card contains two key containers: one for key exchange (encryption) and one for digital signatures, both RSA-2048.
- PIN verification (reference `0x80`) is required before cryptographic operations. PINs are null-padded to 8 bytes. Maximum 3 retries before the card blocks.
- Card detection uses AID selection (`A0 00 00 00 63 50 4B 43 53 2D 31 35`). Factory probe ordering ensures this runs after eID probes to avoid false matches on Gemalto/IF2020 eID cards that also have CardEdge.
- PKI operations (certificate reading, PIN management, signing) are fully handled by the CardEdge plugin.

# Serbian Health Insurance — Card Profile

## Overview

| Property | Value |
|----------|-------|
| Profile | Serbian health insurance card (RFZO) |
| Known ATRs | `3B F4 13 00 00 81 31 FE 45 52 46 5A 4F ED`, `3B 9E 97 80 31 FE 45 53 43 45 20 38 2E 30 2D 43 31 56 30 0D 0A 6E` |
| Known Cards | Serbian RFZO health insurance smart card |

## Applets Present

| Applet | AID | Documentation |
|--------|-----|---------------|
| Health (SERVSZK) | `F3 81 00 00 02 53 45 52 56 53 5A 4B 01` | [health-serbian-applet.md](../applets/health-serbian-applet.md) |
| CardEdge PKI | `A0 00 00 00 63 50 4B 43 53 2D 31 35` | [cardedge-applet.md](../applets/cardedge-applet.md) |

## Card-Specific Notes

- The health insurance card contains two applets: the SERVSZK health data applet and the CardEdge PKI applet.
- The SERVSZK applet stores insurant data across four files: document data (0D01), fixed personal data (0D02), variable personal data (0D03), and variable administrative data (0D04).
- No authentication is required to read health insurance data files.
- The CardEdge PKI applet provides certificate storage and PIN-protected operations, used for pharmacist/healthcare provider authentication scenarios.
- Two ATR variants exist corresponding to different card generations/manufacturers, but both use the same applet structure and file layout.
- Data files use a 4-byte header where bytes [2:3] contain the content length as a little-endian uint16.

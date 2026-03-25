# Serbian Vehicle Registration — Card Profile

## Overview

| Property | Value |
|----------|-------|
| Profile | Serbian vehicle registration smart card (EU VRC with national extensions) |
| Standard | Commission Directive 2003/127/EC + Serbian national extensions |
| Known ATRs | Varies by card generation and manufacturer |
| Known Cards | Serbian vehicle registration card (saobraćajna dozvola) |

## Applets Present

| Applet | AID | Documentation |
|--------|-----|---------------|
| EU VRC (Vehicle Registration Certificate) | Country-specific (see AID sequences below) | [vehicle-eu-vrc-applet.md](../applets/vehicle-eu-vrc-applet.md) |

## AID Selection Sequences

The Serbian implementation uses an NXP eVL (Electronic Vehicle License) platform. Three AID selection sequences cover different card generations. Each consists of 3 SELECT commands; CMD1 must succeed, CMD2/CMD3 are sent regardless.

### Sequence 1 (pre-2015, proprietary vendor)

| Step | AID | P2 |
|------|-----|-----|
| CMD1 | `A0 00 00 01 51 00 00` | `0x00` |
| CMD2 | `A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 01 00` | `0x00` |
| CMD3 | `A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 AD F2` | `0x0C` |

### Sequence 2 (2015-2020, Serbian SERV* infrastructure)

| Step | AID | P2 |
|------|-----|-----|
| CMD1 | `A0 00 00 00 03 00 00 00` | `0x00` |
| CMD2 | `F3 81 00 00 02 53 45 52 56 4C 04 02 01` (SERVL) | `0x00` |
| CMD3 | `A0 00 00 00 77 01 08 00 07 00 00 FE 00 00 AD F2` | `0x0C` |

### Sequence 3 (2020+, GlobalPlatform + NXP eVL-001)

| Step | AID | P2 |
|------|-----|-----|
| CMD1 | `A0 00 00 00 18 43 4D 00` (GlobalPlatform CM, RID: NXP) | `0x00` |
| CMD2 | `A0 00 00 00 18 34 14 01 00 65 56 4C 2D 30 30 31` (eVL-001) | `0x00` |
| CMD3 | `A0 00 00 00 18 65 56 4C 2D 30 30 31` (eVL-001) | `0x0C` |

### Fallback Logic

```
try Sequence 1 → fail → try Sequence 2 → fail → try Sequence 3 → fail → card not recognized
```

## Card-Specific Notes

- Serbia follows the EU VRC standard (BER-TLV with tags `71`/`72`) and extends it with national tags (`C2`-`C9`) for JMBG, year of production, etc.
- Serbian cards have 4 data files (D001, D011, D021, D031) — the EU standard defines only 2 data files (D001, D011). Files D021 and D031 are national extensions.
- Serbian cards do **not** contain signature files (E001, E011) or certificate files (C001, C011) defined by the EU standard.
- The vehicle card does **not** have a CardEdge PKI applet. It is a data-only card.
- No authentication is required to read vehicle registration data.
- Detection relies entirely on AID probing, not ATR pattern matching.
- File reads use `SELECT EF` with P1=0x02 P2=0x04 (no Le byte), 32-byte header, 100-byte chunks.

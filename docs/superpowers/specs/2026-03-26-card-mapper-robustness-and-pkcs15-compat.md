# Spec: Card Mapper Robustness & PKCS#15 Compatibility

## Context

Encountered a card with eMRTD + PKCS#15 where eMRTD reads fine but PKCS#15 cannot be fully read. Card is strict about APDU formatting — rejects SELECT with P2=0x00+Le (returns 6700/6982) but accepts P2=0x0C without Le.

CAN: 123456, ATR: 3B 8E 80 01 53 43 45 20 38 2E 30 2D 43 32 56 30

## Part 1: Card Mapper SELECT Robustness

### Problem

`card_mapper --discover` and PKCS#15 probes fail because they use a single SELECT format. When that format is rejected (6700/6982/6A86), they give up instead of trying alternatives.

### Requirements

1. When SELECT by AID returns 6700/6982/6A86, retry with alternative P2/Le combinations:
   - Try 1: `P2=0x00, Le=0x00` (current — return FCI)
   - Try 2: `P2=0x0C, no Le` (no response data)
   - Try 3: `P2=0x04, Le=0x00` (return FCP)
2. When SELECT by FID returns error, try alternatives:
   - Try 1: `P1=0x02, P2=0x04, Le=0x00` (by FID, return FCP)
   - Try 2: `P1=0x02, P2=0x0C, no Le` (by FID, no response)
   - Try 3: `P1=0x00, P2=0x00, Le=0x00` (by FID from current DF)
   - Try 4: `P1=0x08, P2=0x00, Le=0x00` (absolute path from MF)
3. Remember which format works per card session and reuse it
4. Log which format succeeded so the output doc shows the correct procedure

### Affected Code

- `card_mapper/card_scanner.cpp` — AID probing
- `card_mapper/plugin_mapper.cpp` — file reads within plugins
- `smartcard/apdu.h` — may need parameterized builders

## Part 2: PKCS#15 Structure Investigation

### What We Know

- PKCS#15 AID `A0 00 00 00 63 50 4B 43 53 2D 31 35` is present but requires P2=0x0C for SELECT
- Card uses GET DATA (INS=CB, P1P2=3FFF) for metadata/key references
- Cross-DF certificate reading may require P1=0x08 (absolute path from MF)
- FIDs may differ from standard PKCS#15 layout — must discover via ODF parsing

### What We Need To Do

1. Scan the PKCS#15 structure with card_mapper using correct SELECT format
2. Read and parse EF.DIR, EF.ODF, EF.TokenInfo
3. Follow ODF pointers to discover all PKCS#15 objects (CDF, PrKDF, AODF, etc.)
4. Compare with our PKCS#15 parser to identify where it breaks
5. Determine if signing cert requires cross-DF navigation (separate DF from PKCS#15)

### Key Questions

1. Does our PKCS#15 parser discover FIDs dynamically from ODF or use hardcoded paths?
2. Do we support P1=0x08 (SELECT by absolute path from MF)?
3. Can our SM filter handle PKCS#15 file navigation after PACE?
4. What exactly fails when we try to read this card's PKCS#15?

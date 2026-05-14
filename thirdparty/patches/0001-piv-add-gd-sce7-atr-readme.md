# 0001-piv-add-gd-sce7-atr.patch

**Purpose:** Add Giesecke+Devrient PIV SCE7 ATR variant to vendored OpenSC's `piv_atrs[]` so the card is recognized as PIV via the discovery-first path.

**Captured APDU (2026-05-13/14, Gemalto PC Twin reader, real card):**

```
ATR: 3B:F9:96:00:00:80:31:FE:45:53:43:45:37:20:0F:00:20:46:4E

SELECT PIV AID (00 A4 04 00 09 A0 00 00 03 08 00 00 10 00 00):
  Response: 61 0F 4F 06 00 10 00 01 00 00 79 05 A0 00 00 03 08  SW=9000
  (PIX `00 10 00 01 00 00` in tag 0x4F; NIST PIV RID in tag 0x79.)

GET DATA Discovery Object (00 CB 3F FF 03 5C 01 7E 00):
  Response: 7E 12 4F 0B A0 00 00 03 08 00 00 10 00 01 00 5F 2F 02 40 00  SW=9000
  (Valid Discovery template with full AID + PIN Usage Policy.)
```

**Rationale:** Without this ATR entry, `piv_match_card_continued` (`card-piv.c:5373`) falls back to `SC_CARD_TYPE_PIV_II_BASE` (line 5467), which skips `piv_find_discovery` (line 5534) and goes straight to `piv_find_aid`. `piv_find_aid` rejects the card because PIX `00 10 00 01 00 00` does not match `piv_aids[0]` `00 00 10 00`. With this ATR entry, the card resolves to `SC_CARD_TYPE_PIV_II_GI_DE` and the discovery-first path is taken. Discovery succeeds → card accepted as PIV. `piv_find_aid` is never called for this card.

**Cert:** subject "Nemanja Hirsl", issuer "Giesecke+Devrient DC1 ICA", RSA-2048, validity 2025-10-02 → 2027-10-02.

**Upstream PR status:** Not submitted. Future research cycle per `[[feedback_opensc_contribution_quality]]` will sample additional G+D firmware variants before upstream contribution.

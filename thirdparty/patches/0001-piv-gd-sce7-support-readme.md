# 0001-piv-gd-sce7-support.patch

**Purpose:** Enable Giesecke+Devrient PIV SCE7 cards in OpenSC's PIV driver. The patch is internally two small changes targeting the same file (`src/libopensc/card-piv.c`); both are required to read and sign with the G+D SCE7. Downstream they ship together; before upstream contribution they will be split back into one-ATR-row + one-AID-fallback patches per upstream review convention.

## Captured APDU baseline (2026-05-13/14, Gemalto PC Twin reader, real card)

```
ATR: 3B:F9:96:00:00:80:31:FE:45:53:43:45:37:20:0F:00:20:46:4E

SELECT PIV AID (00 A4 04 00 09 A0 00 00 03 08 00 00 10 00 00):
  Response: 61 0F 4F 06 00 10 00 01 00 00 79 05 A0 00 00 03 08  SW=9000
  (PIX `00 10 00 01 00 00` in tag 0x4F; NIST PIV RID in tag 0x79.)

GET DATA Discovery Object (00 CB 3F FF 03 5C 01 7E 00):
  Response: 7E 12 4F 0B A0 00 00 03 08 00 00 10 00 01 00 5F 2F 02 40 00  SW=9000
  (Valid Discovery template with full AID + PIN Usage Policy.)
```

## Change 1 — ATR row in `piv_atrs[]`

Adds a one-line row for the G+D SCE7 ATR. Without this, `piv_match_card_continued` (`card-piv.c:5373`) falls back to `SC_CARD_TYPE_PIV_II_BASE` and skips `piv_find_discovery` (line 5534), going straight to `piv_find_aid`. `piv_find_aid` rejects the card because PIX `00 10 00 01 00 00` does not match `piv_aids[0]` `00 00 10 00`. With this ATR entry, the card resolves to `SC_CARD_TYPE_PIV_II_GI_DE` and the discovery-first path is taken; Discovery succeeds and the card is accepted as PIV. `piv_find_aid` is never called for this card on the happy path.

**Cert observed:** subject "Nemanja Hirsl", issuer "Giesecke+Devrient DC1 ICA", RSA-2048, validity 2025-10-02 → 2027-10-02.

## Change 2 — Tag 0x79 coexistent fallback in `piv_find_aid`

Extends `piv_find_aid` with an ISO 7816-4 tag 0x79 (Coexistent Tag Allocation Authority template) fallback for cards that implement NIST PIV's data model under a vendor-specific PIX but declare NIST PIV namespace compatibility by placing the NIST PIV RID in tag 0x79 of the Application Property Template (tag 0x61).

### Specification basis

**NIST SP 800-73-5 Part 1 §2.2 "PIV Card Application AID"** (canonical citation, July 2024 publication):

> "The Application IDentifier (AID) of the Personal Identity Verification Card Application (PIV Card Application) SHALL be:
> 'A0 00 00 03 08    00 00 10 00    01 00'
> The AID of the PIV Card Application consists of the NIST RID ('A0 00 00 03 08') followed by the application portion of the NIST PIX indicating the PIV Card Application ('00 00 10 00') and then the version portion of the NIST PIX ('01 00') for the first version of the PIV Card Application. **All other PIX sequences on the NIST RID are reserved for future use.**"

NIST is strict: cards with PIX ≠ `00:00:10:00:01:00` are not "the PIV Card Application". However:

**NIST SP 800-73-5 Part 1 §2.1 "Namespaces of the PIV Card Application"**:

> "Names used on the PIV interfaces are drawn from three namespaces managed by NIST: ... Basic Encoding Rules — Tag Length Value (BER-TLV) tags of the **NIST PIV coexistent tag allocation scheme**."

NIST recognises a coexistent tag allocation mechanism by which vendor-specific applications can adopt NIST PIV's data-model tag namespace (CHUID, certs, PIN, etc.) without claiming to be the NIST PIV Card Application itself.

**ISO/IEC 7816-4 Application Property Template (tag 0x61)** carries an optional **tag 0x79 ("Coexistent tag allocation authority template")** in which the card declares which tag-allocation authority's namespace its data tags follow. A card that places the NIST PIV RID `A0:00:00:03:08` in tag 0x79 is signalling "I implement NIST PIV's data-tag namespace" while remaining a vendor-specific application via its tag 0x4F PIX.

### Behaviour

Before this change (OpenSC vanilla + Change 1 only), `piv_find_aid` extracts tag 0x4F PIX, compares against `piv_aids[]` (which contains only the NIST PIX `A0:00:00:03:08:00:00:10:00`), finds no match, returns `SC_ERROR_NO_CARD_SUPPORT`. Card rejected despite the NIST PIV namespace declaration in tag 0x79.

After this change: `piv_find_aid` checks for tag 0x79 with NIST PIV RID as a fallback when tag 0x4F doesn't match. Gated on `card->type != PIV_II_BASE && != PIV_II_GENERIC` so only cards already identified by `piv_atrs[]` ATR-table are eligible — prevents accepting arbitrary unknown cards that happen to place the NIST RID in tag 0x79.

## Empirical validation (2026-05-15)

Trace captured at `knowledge/audits/captured-card-traces/2026-05-15-piv-gd-sce7-bind/` after build with this patch applied:

```
card-piv.c:2948: piv_find_aid: found NIST PIV RID via coexistent tag 0x79;
                 accepting vendor-PIX card->type=14006
card-piv.c:2957: piv_find_aid: returning with: 0 (Success)
card-piv.c:5800: piv_init: called
card-piv.c:5939: piv_init: returning with: 0 (Success)
pkcs15-piv.c:1267: sc_pkcs15emu_piv_init: returning with: 0 (Success)
pkcs15.c:1372: sc_pkcs15_bind: returning with: 0 (Success)
```

LibreCelik display path works after this patch (cert chain + metadata rendered). PIN VERIFY (PIV App PIN ref 0x80) succeeds. Sign verified end-to-end at HEAD `f7af4d7` against the on-card cert pubkey (PKCS1 v1.5 + SHA-256).

## Upstream PR status

Not submitted yet. Pre-upstream cleanup: split this combined downstream patch back into:

1. `piv-add-gd-sce7-atr.patch` — one ATR row addition (trivial, one-line).
2. `piv-tag-79-coexistent-fallback.patch` — `piv_find_aid` fallback (generic, NIST §2.1 / ISO 7816-4 aligned, benefits any vendor PIV card using the coexistent tag scheme to declare NIST PIV data-model compatibility — including potential future Yubikey / Oberthur / Gemalto cards using the same pattern).

Per `[[feedback_opensc_contribution_quality]]`: sample additional G+D firmware variants and at least one non-G+D vendor PIV using tag 0x79 before submitting. The combined downstream form here exists for our build only.

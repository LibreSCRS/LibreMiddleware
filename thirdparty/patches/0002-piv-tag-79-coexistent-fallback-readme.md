# 0002-piv-tag-79-coexistent-fallback.patch

**Purpose:** Extend OpenSC's `piv_find_aid` (`card-piv.c`) with an ISO 7816-4 tag 0x79 (Coexistent Tag Allocation Authority template) fallback for cards that implement NIST PIV's data model under a vendor-specific PIX but declare NIST PIV namespace compatibility by placing the NIST PIV RID in tag 0x79 of the Application Property Template (tag 0x61).

**Companion to:** `0001-piv-add-gd-sce7-atr.patch` (adds G+D SCE7 ATR to `piv_atrs[]`).

## Specification basis

**NIST SP 800-73-5 Part 1 §2.2 "PIV Card Application AID"** (canonical citation, July 2024 publication):

> "The Application IDentifier (AID) of the Personal Identity Verification Card Application (PIV Card Application) SHALL be:
> 'A0 00 00 03 08    00 00 10 00    01 00'
> The AID of the PIV Card Application consists of the NIST RID ('A0 00 00 03 08') followed by the application portion of the NIST PIX indicating the PIV Card Application ('00 00 10 00') and then the version portion of the NIST PIX ('01 00') for the first version of the PIV Card Application. **All other PIX sequences on the NIST RID are reserved for future use.**"

NIST is strict: cards with PIX ≠ `00:00:10:00:01:00` are not "the PIV Card Application". However:

**NIST SP 800-73-5 Part 1 §2.1 "Namespaces of the PIV Card Application"**:

> "Names used on the PIV interfaces are drawn from three namespaces managed by NIST: ... Basic Encoding Rules — Tag Length Value (BER-TLV) tags of the **NIST PIV coexistent tag allocation scheme**."

NIST recognises a coexistent tag allocation mechanism by which vendor-specific applications can adopt NIST PIV's data-model tag namespace (CHUID, certs, PIN, etc.) without claiming to be the NIST PIV Card Application itself.

**ISO/IEC 7816-4 Application Property Template (tag 0x61)** carries an optional **tag 0x79 ("Coexistent tag allocation authority template")** in which the card declares which tag-allocation authority's namespace its data tags follow. A card that places the NIST PIV RID `A0:00:00:03:08` in tag 0x79 is signalling "I implement NIST PIV's data-tag namespace" while remaining a vendor-specific application via its tag 0x4F PIX.

## Captured behaviour on G+D SCE7 (2026-05-15)

```
SELECT PIV AID (00 A4 04 00 09 A0 00 00 03 08 00 00 10 00 00):
  Response: 61 0F 4F 06 [00 10 00 01 00 00]   ← vendor PIX in tag 0x4F
                       79 05 [A0 00 00 03 08] ← NIST PIV RID in tag 0x79
            SW=9000
```

Before this patch (OpenSC vanilla + 0001 ATR patch), `piv_find_aid` extracts tag 0x4F PIX, compares against `piv_aids[]` (which contains only the NIST PIX `A0:00:00:03:08:00:00:10:00`), finds no match, returns `SC_ERROR_NO_CARD_SUPPORT`. Card is rejected despite having declared NIST PIV namespace compatibility via tag 0x79.

After this patch: `piv_find_aid` checks for tag 0x79 with NIST PIV RID as a fallback when tag 0x4F doesn't match. Gated on `card->type != PIV_II_BASE && != PIV_II_GENERIC` so only cards already identified by `piv_atrs[]` ATR-table are eligible — prevents accepting arbitrary unknown cards that happen to place the NIST RID in tag 0x79.

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

Card display path through LibreCelik works after this patch (cert chain + cert metadata rendered). PIN VERIFY (PIV App PIN ref 0x80) succeeds. Sign path is a separate investigation (LM `NativeSigningService` ↔ `opensc-plugin` sign capability surface), not blocked by this patch.

## Upstream PR status

Not submitted. Intended for upstream contribution per `[[feedback_opensc_contribution_quality]]`. The patch is generic (NIST §2.1 / ISO 7816-4 alignment, not G+D-specific) and benefits any vendor PIV card using the coexistent tag scheme to declare NIST PIV data-model compatibility — including potential future Yubikey / Oberthur / Gemalto cards using the same pattern.

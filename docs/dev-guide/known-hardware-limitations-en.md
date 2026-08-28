---
title: "Known Hardware Limitations"
weight: 50
description: >-
  Hardware behaviors of specific PC/SC reader models that LibreSCRS
  cannot work around in software. Check here before filing a report
  that a card is not being detected.
---

# Known Hardware Limitations

This page collects hardware behaviors of specific PC/SC reader
models that are not bugs in LibreSCRS, and not bugs in PC/SC either
— they cannot be fixed in software. Check the entries below before
filing a report that a card is not being detected.

## HID Omnikey 5422: contactless antenna blocked while the contact slot is connected

On the HID Omnikey 5422 — a dual-slot reader that combines a
contact slot and a contactless (CL) slot in one housing — the
contactless antenna is disabled for as long as a card stays
connected in the contact slot. A card sitting on the CL slot at that
point is invisible to PC/SC: it is not reported as an error, the CL
slot simply appears empty. This is a limitation of that reader's
hardware; neither the LibreSCRS stack nor the PC/SC layer beneath it
can detect it or work around it. Other dual-slot readers that share
similar contact/contactless RF hardware may exhibit the same
behavior, but that has only been confirmed on the Omnikey 5422 —
treat it as a possibility elsewhere, not an established fact. To
read the CL card, disconnect the contact card first, or use two
separate readers.

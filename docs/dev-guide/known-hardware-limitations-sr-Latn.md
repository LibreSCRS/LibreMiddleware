---
title: "Poznata hardverska ograničenja"
weight: 50
description: >-
  Hardverska ponašanja pojedinih modela PC/SC čitača koja LibreSCRS
  ne može da zaobiđe u softveru. Proverite ovde pre prijave da
  kartica nije prepoznata.
---

# Poznata hardverska ograničenja

Ova stranica okuplja hardverska ponašanja pojedinih modela PC/SC
čitača koja nisu greška u LibreSCRS-u, a nisu ni greška u samom
PC/SC-u — ne mogu se rešiti softverski. Proverite unose ispod pre
prijave da kartica nije prepoznata.

## HID Omnikey 5422: beskontaktna antena blokirana dok je kontaktni slot konektovan

Na HID Omnikey 5422 — dvoslotnom čitaču koji kontaktni i
beskontaktni (CL) slot drži u istom kućištu — beskontaktna antena je
onemogućena sve dok je kartica konektovana u kontaktnom slotu.
Kartica koja se u tom trenutku nalazi na CL slotu je nevidljiva za
PC/SC: ne prijavljuje se kao greška, CL slot jednostavno izgleda
prazan. Ovo je ograničenje hardvera tog čitača; ni LibreSCRS stek ni
PC/SC sloj ispod njega ne mogu to da detektuju ili zaobiđu. Drugi
dvoslotni čitači sa sličnim kontaktnim/beskontaktnim RF hardverom
mogu pokazivati isto ponašanje, ali to je potvrđeno samo na Omnikey
5422 — na drugim uređajima tretirajte to kao mogućnost, ne kao
utvrđenu činjenicu. Da biste pročitali CL karticu, prvo izvadite
kontaktnu karticu, ili koristite dva odvojena čitača.

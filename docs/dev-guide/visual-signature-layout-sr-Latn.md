---
title: "API za raspored vizuelnog potpisa"
weight: 40
description: >-
  Kako se koristi LibreSCRS::Signing::layoutVisualSignature za
  automatsko prilagođavanje izgleda PAdES vizuelnog potpisa, i kako
  se ona kombinuje sa ugrađenim Liberation Sans TTF fontom radi
  prikaza u režimu pregleda.
---

# API za raspored vizuelnog potpisa (LibreSCRS::Signing)

`<LibreSCRS/Signing/VisualSignatureLayout.h>` pruža čist,
deterministički algoritam za automatsko prilagođavanje rasporeda
teksta vizuelnog potpisa. Ista funkcija pokreće PAdES izvorni
ispisnik i svaku površinu za pregled u grafičkom interfejsu
(LibreCelik, LibreMac, budući LibreKDE), pa se **pregled potpuno
poklapa sa potpisanim PDF-om** — isti ulazi daju iste odluke o
rasporedu.

> Dostupno od LibreMiddleware 4.0.0-rc2.

## Na prvi pogled

```cpp
#include <LibreSCRS/Signing/VisualSignatureLayout.h>

using namespace LibreSCRS::Signing;

Rect box{0, 0, 200, 50};
auto layout = layoutVisualSignature(
    "Digitalno potpisao NEMANJA HIRŠL\nDatum: 2026-05-08", box);

// layout.fontSize    — izabrana veličina fonta u PDF korisničkim jedinicama
// layout.lineHeight  — rastojanje između osnova susednih linija
// layout.lines       — prelamani UTF-8 redovi (≥1, nikad prazno)
// layout.clipped     — true kada je kutija premala čak i za 6pt
```

## Algoritam

Binarnom pretragom se bira veličina fonta u opsegu
`[kFloorAppearanceFontSize, min(kMaxAppearanceFontSize, availH/leading)]`
u koracima od 0,5pt. Za svaki kandidat izvodi se pohlepno
prelamanje po razmacima do širine `availW = box.width − 2·kAppearanceTextMargin`.
Prihvata se najveći kandidat kod kojeg svaki prelamani red stane u
`availW` I ukupna visina stane u `availH`.

Ako ni `kFloorAppearanceFontSize` (6pt) ne stane, `clipped` postaje
`true` i prelamanje se vraća u podu — pozivalac emituje PDF putanju
isecanja ili Qt `setClipRect`, tako da prikazivač uredno odseče
prekoračujući tekst.

### Konstante

| Konstanta | Vrednost | Značenje |
|---|---|---|
| `kFloorAppearanceFontSize` | 6,0 pt | Najmanja veličina koja se još čita kao tekst |
| `kMaxAppearanceFontSize` | 72,0 pt | Zdravorazumski maksimum (1 inč) |
| `kAppearanceTextMargin` | 4,0 pt | Unutrašnji razmak na svakoj ivici kutije |
| `kAppearanceLineLeading` | 1,2× | `lineHeight = fontSize × ovo` |

## Granični slučajevi

| Ulaz | Ponašanje |
|---|---|
| Prazan / samo beli prostor | `{6pt, [""], clipped=false}` |
| Više `\n` | jedan pasus po `\n`; svaki se prelama nezavisno |
| Jedan jako dugačak nerastavljiv token | Pada u pod, jedan red, `clipped=true` |
| Patološki uska / niska kutija | Pod i `clipped`, jedan red |
| Glif nepostojeći u Liberation Sans-u | Meri se kao `.notdef`; pregled i PDF prikazuju identičnu praznu kutiju |
| `\r\n` | Skuplja se u `\n` |
| Samostalni `\r` | Briše se |
| `\t` | Tretira se kao razmak |

## Integracija sa grafičkim interfejsom (primer za Qt)

Da bi se pregled iscrtao istim fontom kao ugrađeni PDF podskup,
registrujte ugrađeni Liberation Sans TTF jednom u Qt-ovu bazu
fontova i zatim napravite `QFont("Liberation Sans", layout.fontSize)`:

```cpp
#include <LibreSCRS/Signing/VisualSignatureLayout.h>
#include <QByteArray>
#include <QFontDatabase>

void registerAppearanceFontOnce()
{
    static int handle = []() noexcept {
        auto bytes = LibreSCRS::Signing::embeddedAppearanceFontData();
        QByteArray ba(reinterpret_cast<const char*>(bytes.data()),
                      static_cast<int>(bytes.size()));
        int h = QFontDatabase::addApplicationFontFromData(ba);
        if (h < 0) {
            qWarning("LibreSCRS: nije uspelo registrovanje Liberation Sans-a; "
                     "pregled će pasti na sistemski sans-serif");
        }
        return h;
    }();
    Q_UNUSED(handle);
}
```

Vraćeni `span` upućuje na podatke u programskoj sekciji i važi do
kraja izvršavanja procesa — ne oslobađajte ga.

## Uobičajene zamke

- **Ne pokrećite drugi krug rasporeda nizvodno.** Redovi vraćeni
  iz `layoutVisualSignature` spremni su za direktno crtanje;
  ponavljanje preloma u GUI-ju bi odstupalo od PDF-a.
- **Poštujte `clipped == true`.** PAdES izvorni ispisnik upisuje
  `q ... re W n ... Q` putanju isecanja kada je zastavica postavljena;
  GUI pregled treba da pozove `painter.setClipRect`. Bez isecanja,
  tekst može da iscuri van pravougaonika u nekim prikazivačima.
- **Stabilno između izvršavanja.** Funkcija je deterministička po
  `(textUtf8, box)`. Keširanje po tom ključu u GUI pregledu je
  sigurno i jeftino.

## Bezbednost niti

Funkcija je čista i `noexcept`. Istovremeni pozivi iz bilo kojih
niti su bez uslova utrke.

## Performanse

Empirijski ispod 1 ms po pozivu (Release izgradnja) za uobičajeni
pravougaonik 200×50 i engleski prikaz od četiri reda, na modernom
x86_64 računaru. Podskup TTF fonta koji se koristi za merenje
konstruiše se na steku na ulazu u funkciju — bez singltona, bez
Meyers-ovog obrasca, bez skrivenog stanja.

## Videti i

- `LibreSCRS::Signing::VisualSignatureParams` — obuhvatni snop
  PAdES vizuelnog potpisa (indeks strane, pravougaonik, obrazac
  teksta).
- Samostalni Qt-nelazni demo program na
  `examples/visual_signature_layout/` — ispisuje raspored za
  par `(tekst, kutija)` dat na komandnoj liniji.

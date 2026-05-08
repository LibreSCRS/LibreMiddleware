---
title: "API за распоред визуелног потписа"
weight: 40
description: >-
  Како се користи LibreSCRS::Signing::layoutVisualSignature за
  аутоматско прилагођавање изгледа PAdES визуелног потписа, и како
  се она комбинује са уграђеним Liberation Sans TTF фонтом ради
  приказа у режиму прегледа.
---

# API за распоред визуелног потписа (LibreSCRS::Signing)

`<LibreSCRS/Signing/VisualSignatureLayout.h>` пружа чист,
детерминистички алгоритам за аутоматско прилагођавање распореда
текста визуелног потписа. Иста функција покреће PAdES изворни
исписник и сваку површину за преглед у графичком интерфејсу
(LibreCelik, LibreMac, будући LibreKDE), па се **преглед потпуно
поклапа са потписаним PDF-ом** — исти улази дају исте одлуке о
распореду.

> Доступно од LibreMiddleware 4.0.0-rc2.

## На први поглед

```cpp
#include <LibreSCRS/Signing/VisualSignatureLayout.h>

using namespace LibreSCRS::Signing;

Rect box{0, 0, 200, 50};
auto layout = layoutVisualSignature(
    "Дигитално потписао НЕМАЊА ХИРШЛ\nДатум: 2026-05-08", box);

// layout.fontSize    — изабрана величина фонта у PDF корисничким јединицама
// layout.lineHeight  — растојање између основа суседних линија
// layout.lines       — преламани UTF-8 редови (≥1, никад празно)
// layout.clipped     — true када је кутија премала чак и за 6pt
```

## Алгоритам

Бинарном претрагом се бира величина фонта у опсегу
`[kFloorAppearanceFontSize, min(kMaxAppearanceFontSize, availH/leading)]`
у корацима од 0,5pt. За сваки кандидат изводи се похлепно
преламање по размацима до ширине `availW = box.width − 2·kAppearanceTextMargin`.
Прихвата се највећи кандидат код којег сваки преламани ред стане у
`availW` И укупна висина стане у `availH`.

Ако ни `kFloorAppearanceFontSize` (6pt) не стане, `clipped` постаје
`true` и преламање се враћа у поду — позивалац емитује PDF путању
исецања или Qt `setClipRect`, тако да приказивач уредно одсече
прекорачујући текст.

### Константе

| Константа | Вредност | Значење |
|---|---|---|
| `kFloorAppearanceFontSize` | 6,0 pt | Најмања величина која се још чита као текст |
| `kMaxAppearanceFontSize` | 72,0 pt | Здраворазумски максимум (1 инч) |
| `kAppearanceTextMargin` | 4,0 pt | Унутрашњи размак на свакој ивици кутије |
| `kAppearanceLineLeading` | 1,2× | `lineHeight = fontSize × ово` |

## Гранични случајеви

| Улаз | Понашање |
|---|---|
| Празан / само бели простор | `{6pt, [""], clipped=false}` |
| Више `\n` | један пасус по `\n`; сваки се прелама независно |
| Један јако дугачак нерастављиви токен | Пада у под, један ред, `clipped=true` |
| Патолошки уска / ниска кутија | Под и `clipped`, један ред |
| Глиф непостојећи у Liberation Sans-у | Мери се као `.notdef`; преглед и PDF приказују идентичну празну кутију |
| `\r\n` | Скупља се у `\n` |
| Самостални `\r` | Брише се |
| `\t` | Третира се као размак |

## Интеграција са графичким интерфејсом (пример за Qt)

Да би се преглед исцртао истим фонтом као уграђени PDF подскуп,
региструјте уграђени Liberation Sans TTF једном у Qt-ову базу
фонтова и затим направите `QFont("Liberation Sans", layout.fontSize)`:

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
            qWarning("LibreSCRS: није успело регистровање Liberation Sans-а; "
                     "преглед ће пасти на системски sans-serif");
        }
        return h;
    }();
    Q_UNUSED(handle);
}
```

Враћени `span` упућује на податке у програмској секцији и важи до
краја извршавања процеса — не ослобађајте га.

## Уобичајене замке

- **Не покрећите други круг распореда низводно.** Редови враћени
  из `layoutVisualSignature` спремни су за директно цртање;
  понављање прелома у GUI-ју би одступало од PDF-а.
- **Поштујте `clipped == true`.** PAdES изворни исписник уписује
  `q ... re W n ... Q` путању исецања када је заставица постављена;
  GUI преглед треба да позове `painter.setClipRect`. Без исецања,
  текст може да исцури ван правоугаоника у неким приказивачима.
- **Стабилно између извршавања.** Функција је детерминистичка по
  `(textUtf8, box)`. Кеширање по том кључу у GUI прегледу је
  сигурно и јефтино.

## Безбедност нити

Функција је чиста и `noexcept`. Истовремени позиви из било којих
нити су без услова утрке.

## Перформансе

Емпиријски испод 1 ms по позиву (Release изградња) за уобичајени
правоугаоник 200×50 и енглески приказ од четири реда, на модерном
x86_64 рачунару. Подскуп TTF фонта који се користи за мерење
конструише се на стеку на улазу у функцију — без синглтона, без
Меyерс-овог обрасца, без скривеног стања.

## Видети и

- `LibreSCRS::Signing::VisualSignatureParams` — обухватни сноп
  PAdES визуелног потписа (индекс стране, правоугаоник, образац
  текста).
- Самостални Qt-нелазни демо програм на
  `examples/visual_signature_layout/` — исписује распоред за
  пар `(текст, кутија)` дат на командној линији.

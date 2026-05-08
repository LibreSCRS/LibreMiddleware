---
title: "Visual Signature Layout API"
weight: 40
description: >-
  How to use LibreSCRS::Signing::layoutVisualSignature to compute
  the auto-fit appearance of a PAdES visual signature, and how to
  pair it with the bundled Liberation Sans TTF for preview-mode
  rendering.
---

# Visual Signature Layout API (LibreSCRS::Signing)

`<LibreSCRS/Signing/VisualSignatureLayout.h>` provides a pure,
deterministic auto-fit layout algorithm for visual signature
appearance text. The same function drives the PAdES native emitter
and every GUI preview surface (LibreCelik, LibreMac, future
LibreKDE) so **the preview matches the signed PDF exactly** —
identical inputs produce identical layout decisions.

> Available since LibreMiddleware 4.0.0-rc2.

## At a glance

```cpp
#include <LibreSCRS/Signing/VisualSignatureLayout.h>

using namespace LibreSCRS::Signing;

Rect box{0, 0, 200, 50};
auto layout = layoutVisualSignature(
    "Digitally signed by NEMANJA HIRŠL\nDate: 2026-05-08", box);

// layout.fontSize    — selected font size in PDF user units
// layout.lineHeight  — baseline-to-baseline distance
// layout.lines       — wrapped UTF-8 lines (≥1, never empty)
// layout.clipped     — true when the box is too small even at 6pt
```

## Algorithm

Binary search the font size in
`[kFloorAppearanceFontSize, min(kMaxAppearanceFontSize, availH/leading)]`
in 0.5pt steps. For each candidate, run a greedy whitespace word-wrap
to width `availW = box.width − 2·kAppearanceTextMargin`. Accept the
largest candidate where every wrapped line measures within `availW`
AND total height fits `availH`.

If even `kFloorAppearanceFontSize` (6pt) does not fit, `clipped`
becomes `true` and the wrap is returned at the floor — the caller
emits a PDF clipping path or a Qt `setClipRect` so the viewer crops
neatly.

### Constants

| Constant | Value | Meaning |
|---|---|---|
| `kFloorAppearanceFontSize` | 6.0 pt | Smallest font size that still reads as text |
| `kMaxAppearanceFontSize` | 72.0 pt | Sanity ceiling (1 inch) |
| `kAppearanceTextMargin` | 4.0 pt | Inset on every edge of the box |
| `kAppearanceLineLeading` | 1.2× | `lineHeight = fontSize × this` |

## Edge-case behaviour

| Input | Behaviour |
|---|---|
| Empty / whitespace-only | `{6pt, [""], clipped=false}` |
| Multiple `\n` | one paragraph per `\n`; each wraps independently |
| Single huge unbreakable token | Falls to floor, single line, `clipped=true` |
| Pathologically narrow / short box | Floor + clipped, single line |
| Glyph absent from Liberation Sans | Measured at `.notdef`; preview & PDF render identical empty box |
| `\r\n` | Collapsed to `\n` |
| Bare `\r` | Stripped |
| `\t` | Treated as space |

## GUI integration (Qt example)

To render a preview with the same font as the embedded PDF subset,
register the bundled Liberation Sans TTF once with Qt's font
database, then construct a `QFont("Liberation Sans", layout.fontSize)`:

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
            qWarning("LibreSCRS: failed to register Liberation Sans; "
                     "preview will fall back to system sans-serif");
        }
        return h;
    }();
    Q_UNUSED(handle);
}
```

The returned span aliases program data and is valid for the program
lifetime — do not free.

## Common pitfalls

- **Do not run a second layout pass downstream.** The lines returned
  by `layoutVisualSignature` are ready to render verbatim; reflowing
  them in the GUI would diverge from the PDF.
- **Honour `clipped == true`.** The PAdES native emitter writes a
  `q ... re W n ... Q` clipping path when the flag is set; a GUI
  preview should call `painter.setClipRect`. Without the clip, text
  may leak past the annotation rectangle in some viewers.
- **Stable across runs.** The function is deterministic with respect
  to `(textUtf8, box)`. Caching by that key in a GUI preview is safe
  and cheap.

## Thread-safety

The function is pure and `noexcept`. Concurrent calls from any
thread are race-free.

## Performance

Empirically < 1 ms per call (Release build) for the typical 200×50
default rectangle and a 4-line English appearance, on a modern
x86_64 host. The TTF subset used for measurement is constructed
on-stack at call entry — no singletons, no Meyers, no hidden state.

## See also

- `LibreSCRS::Signing::VisualSignatureParams` — the surrounding
  PAdES visual-signature appearance bundle (page index, rectangle,
  text template).
- The standalone Qt-free demo program at
  `examples/visual_signature_layout/` — prints the layout for a
  command-line `(text, box)` pair.

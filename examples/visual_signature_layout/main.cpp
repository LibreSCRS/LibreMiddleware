// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Minimal Qt-free demonstration of
///        @ref LibreSCRS::Signing::layoutVisualSignature.
///
/// Build: enable `LIBRESCRS_BUILD_EXAMPLES=ON` and run
/// `cmake --build <build> --target visual_signature_layout_example`.
/// Without the option set, the target is added EXCLUDE_FROM_ALL so IDEs
/// see the source while the default build skips it.
///
/// Usage:
///   visual_signature_layout_example "Some text"
///   visual_signature_layout_example "Some text" 200 50
///   visual_signature_layout_example "Some text" 200 50 0 0
///
/// Default rectangle: 200×50 at the origin (matches LM's
/// @ref LibreSCRS::Signing::kDefaultVisualSignatureRect).

#include <LibreSCRS/Signing/VisualSignatureLayout.h>
#include <LibreSCRS/Signing/VisualSignatureParams.h>

#include <cstdio>
#include <cstdlib>
#include <string>

int main(int argc, char** argv)
{
    using namespace LibreSCRS::Signing;

    std::string text;
    if (argc >= 2)
        text = argv[1];

    Rect box = kDefaultVisualSignatureRect;
    if (argc >= 4) {
        box.width = std::atoi(argv[2]);
        box.height = std::atoi(argv[3]);
    }
    if (argc >= 6) {
        box.x = std::atoi(argv[4]);
        box.y = std::atoi(argv[5]);
    }

    auto layout = layoutVisualSignature(text, box);

    std::printf("box   = (%d, %d) %dx%d\n", box.x, box.y, box.width, box.height);
    std::printf("input = %zu bytes\n", text.size());
    std::printf("---\n");
    std::printf("fontSize   = %.2f pt\n", layout.fontSize);
    std::printf("lineHeight = %.2f pt\n", layout.lineHeight);
    std::printf("clipped    = %s\n", layout.clipped ? "true" : "false");
    std::printf("lines      = %zu\n", layout.lines.size());
    for (std::size_t i = 0; i < layout.lines.size(); ++i)
        std::printf("  [%2zu] \"%s\"\n", i, layout.lines[i].c_str());

    return 0;
}

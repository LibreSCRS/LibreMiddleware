// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include "libresign/types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token;

class PAdESModule
{
public:
    SigningResult sign(const std::vector<uint8_t>& pdfData, Pkcs11Token& token, SignatureLevel level,
                       const TSAConfig& tsa, const VisualSignatureParams& visual);

private:
    struct PreparedPdf
    {
        std::vector<uint8_t> bytes;
        size_t contentsHexStart; // offset where hex string starts (after '<')
        size_t contentsHexLen;   // length of hex placeholder in bytes (chars/2)
    };

    PreparedPdf preparePdf(const std::vector<uint8_t>& pdfData, const VisualSignatureParams& visual,
                           size_t contentsAllocBytes);

    std::vector<uint8_t> createAppearanceStream(const VisualSignatureParams& visual, const std::string& signerName);
};

} // namespace libresign

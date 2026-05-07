// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "types.h"

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

class Pkcs11Token;

class ASiCModule
{
public:
    SigningResult signWithCAdES(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                                SignatureLevel level, const TSAConfig& tsa);
};

} // namespace libresign

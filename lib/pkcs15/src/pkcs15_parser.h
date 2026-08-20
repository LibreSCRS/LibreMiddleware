// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "pkcs15_types.h"

#include <cstdint>
#include <span>
#include <vector>

namespace pkcs15 {

ObjectDirectory parseODF(std::span<const uint8_t> data);
TokenInfo parseTokenInfo(std::span<const uint8_t> data);
std::vector<CertificateInfo> parseCDF(std::span<const uint8_t> data);
std::vector<PrivateKeyInfo> parsePrKDF(std::span<const uint8_t> data);
std::vector<PublicKeyInfo> parsePuKDF(std::span<const uint8_t> data);
std::vector<PinInfo> parseAODF(std::span<const uint8_t> data);

} // namespace pkcs15

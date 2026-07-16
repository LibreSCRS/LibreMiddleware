// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <smartcard/secure_wipe.h>

#include <openssl/crypto.h>

namespace LibreSCRS::SmartCard::Internal {

void secureWipe(void* p, std::size_t n) noexcept
{
    if (p != nullptr && n != 0) {
        OPENSSL_cleanse(p, n);
    }
}

} // namespace LibreSCRS::SmartCard::Internal

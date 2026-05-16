// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SecureChannel/SessionKeys.h>

#include <openssl/crypto.h>

namespace LibreSCRS::SecureChannel {

SessionKeys::~SessionKeys() noexcept
{
    if (!encKey.empty()) {
        OPENSSL_cleanse(encKey.data(), encKey.size());
    }
    if (!macKey.empty()) {
        OPENSSL_cleanse(macKey.data(), macKey.size());
    }
    if (!ssc.empty()) {
        OPENSSL_cleanse(ssc.data(), ssc.size());
    }
}

} // namespace LibreSCRS::SecureChannel

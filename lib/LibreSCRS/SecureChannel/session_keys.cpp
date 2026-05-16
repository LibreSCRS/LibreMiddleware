// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/SecureChannel/SessionKeys.h>

#include <openssl/crypto.h>

namespace LibreSCRS::SecureChannel {

namespace {

void cleanseFields(SessionKeys& k) noexcept
{
    if (!k.encKey.empty()) {
        OPENSSL_cleanse(k.encKey.data(), k.encKey.size());
    }
    if (!k.macKey.empty()) {
        OPENSSL_cleanse(k.macKey.data(), k.macKey.size());
    }
    if (!k.ssc.empty()) {
        OPENSSL_cleanse(k.ssc.data(), k.ssc.size());
    }
}

} // namespace

SessionKeys& SessionKeys::operator=(const SessionKeys& other)
{
    if (this != &other) {
        cleanseFields(*this);
        encKey = other.encKey;
        macKey = other.macKey;
        ssc = other.ssc;
        cipher = other.cipher;
    }
    return *this;
}

SessionKeys& SessionKeys::operator=(SessionKeys&& other) noexcept
{
    if (this != &other) {
        cleanseFields(*this);
        encKey = std::move(other.encKey);
        macKey = std::move(other.macKey);
        ssc = std::move(other.ssc);
        cipher = other.cipher;
    }
    return *this;
}

SessionKeys::~SessionKeys() noexcept
{
    cleanseFields(*this);
}

} // namespace LibreSCRS::SecureChannel

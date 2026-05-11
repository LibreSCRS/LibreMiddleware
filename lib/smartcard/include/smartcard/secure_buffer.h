// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/crypto.h>

namespace LibreSCRS::SmartCard::Internal {

/// RAII wrapper around std::vector<uint8_t> that zeroizes memory on destruction.
/// Use for PIN data and other secrets to ensure cleanup even on exception paths.
class SecureBuffer
{
public:
    SecureBuffer() = default;

    explicit SecureBuffer(size_t size, uint8_t fill = 0) : buf(size, fill) {}

    SecureBuffer(const std::string& s) : buf(s.begin(), s.end()) {}

    /// Copy the bytes viewed by @p s into the buffer. Enables constructing a
    /// SecureBuffer directly from a @ref LibreSCRS::Secure::String::view()
    /// without materialising an intermediate std::string that would escape
    /// cleansing.
    SecureBuffer(std::string_view s) : buf(s.begin(), s.end()) {}

    SecureBuffer(std::initializer_list<uint8_t> init) : buf(init) {}

    ~SecureBuffer()
    {
        cleanse();
    }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;

    SecureBuffer(SecureBuffer&& other) noexcept : buf(std::move(other.buf)) {}

    SecureBuffer& operator=(SecureBuffer&& other) noexcept
    {
        if (this != &other) {
            cleanse();
            buf = std::move(other.buf);
        }
        return *this;
    }

    uint8_t* data()
    {
        return buf.data();
    }
    const uint8_t* data() const
    {
        return buf.data();
    }
    size_t size() const
    {
        return buf.size();
    }
    bool empty() const
    {
        return buf.empty();
    }

    uint8_t& operator[](size_t i)
    {
        return buf[i];
    }
    const uint8_t& operator[](size_t i) const
    {
        return buf[i];
    }

    void resize(size_t n, uint8_t fill = 0)
    {
        buf.resize(n, fill);
    }

    auto begin()
    {
        return buf.begin();
    }
    auto end()
    {
        return buf.end();
    }
    auto begin() const
    {
        return buf.begin();
    }
    auto end() const
    {
        return buf.end();
    }

    /// Implicit conversion to span for APDU functions that take span<const uint8_t>.
    operator std::span<const uint8_t>() const
    {
        return {buf.data(), buf.size()};
    }

private:
    void cleanse()
    {
        if (!buf.empty())
            OPENSSL_cleanse(buf.data(), buf.size());
    }

    std::vector<uint8_t> buf;
};

/// RAII wrapper that zeroizes a std::string on scope exit. Use when a PIN
/// (or other short secret) must be materialized as a std::string to cross a
/// C++ API boundary — OPENSSL_cleanse runs on every exit path including
/// exceptions, so the intermediate buffer never outlives the call.
///
/// Note: SSO-safe for PINs shorter than std::string's SSO capacity
/// (~15–22 bytes on libstdc++). Longer strings allocate heap, which is
/// also covered — cleanse() runs before the allocator frees it.
struct PinStringScrubber
{
    std::string& s;
    ~PinStringScrubber()
    {
        if (!s.empty())
            OPENSSL_cleanse(s.data(), s.size());
    }
};

} // namespace LibreSCRS::SmartCard::Internal

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware."
#endif

#pragma once

#include <LibreSCRS_internal/Secure/secure_allocator.h>

#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#include <smartcard/secure_wipe.h>

namespace LibreSCRS::SmartCard::Internal {

/// @note Not the same concept as `LibreSCRS::Secure::Buffer`, and deliberately
/// not merged with it: that one is a sealed carrier a consumer receives across
/// the published surface and cannot resize, this one is the scratch a card read
/// fills in place. Collapsing them would hand a caller a buffer it can grow.
/// Byte buffer for PIN data and other secrets. Its storage uses the same
/// allocator as `Secure::Buffer`, which wipes every block it gives back, so a
/// reallocation on growth, a move-assignment and destruction all leave no copy
/// of the secret in freed memory.
class SecureBuffer
{
public:
    /// The storage type: a vector whose every deallocation is wiped first.
    using Storage = std::vector<uint8_t, LibreSCRS::Secure::detail::secure_allocator<uint8_t>>;

    SecureBuffer() = default;

    explicit SecureBuffer(size_t size, uint8_t fill = 0) : buf(size, fill) {}

    SecureBuffer(const std::string& s) : buf(s.begin(), s.end()) {}

    /// Copy the bytes viewed by @p s into the buffer. Enables constructing a
    /// SecureBuffer directly from a @ref LibreSCRS::Secure::String::view()
    /// without materialising an intermediate std::string that would escape
    /// cleansing.
    SecureBuffer(std::string_view s) : buf(s.begin(), s.end()) {}

    SecureBuffer(std::initializer_list<uint8_t> init) : buf(init) {}

    /// Take the bytes of an ordinary vector (e.g. an APDU serialization from
    /// APDUCommand::toBytes()). Its storage has the default allocator and
    /// cannot be adopted, so the bytes are copied and the source is wiped and
    /// released, on the failure path too.
    explicit SecureBuffer(std::vector<uint8_t>&& bytes)
    {
        struct WipeSource
        {
            std::vector<uint8_t>& v;
            ~WipeSource()
            {
                if (!v.empty())
                    secureWipe(v.data(), v.size());
                v.clear();
                v.shrink_to_fit();
            }
        } wipeSource{bytes};
        buf.assign(bytes.begin(), bytes.end());
    }

    SecureBuffer(const SecureBuffer&) = delete;
    SecureBuffer& operator=(const SecureBuffer&) = delete;
    SecureBuffer(SecureBuffer&&) noexcept = default;
    SecureBuffer& operator=(SecureBuffer&&) noexcept = default;
    ~SecureBuffer() = default;

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
        // A shrink keeps the capacity, and the dropped tail would otherwise
        // sit in the block until it is freed; wipe it now.
        if (n < buf.size()) {
            secureWipe(buf.data() + n, buf.size() - n);
        }
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
    Storage buf;
};

/// RAII wrapper that zeroizes a std::string on scope exit. Use when a PIN
/// (or other short secret) must be materialized as a std::string to cross a
/// C++ API boundary — secureWipe runs on every exit path including
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
            secureWipe(s.data(), s.size());
    }
};

} // namespace LibreSCRS::SmartCard::Internal

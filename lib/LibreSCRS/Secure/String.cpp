// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Secure/String.h>

#include "secure_allocator.h"

#include <openssl/crypto.h>

#include <cstring>
#include <utility>
#include <vector>

namespace LibreSCRS::Secure {

// The pimpl deliberately uses std::vector<char> (not std::string) because
// std::string's Small-String Optimisation leaves secret bytes in the
// on-stack inline buffer when size() <= SSO threshold. OPENSSL_cleanse on
// vector storage is well-defined (heap-allocated, single contiguous block,
// no SSO). We pay a small allocation for tiny strings to guarantee the
// cleanse semantics the class promises.
struct LIBRESCRS_INTERNAL String::Impl
{
    // secure_allocator cleanses on every deallocate; assignment, clear,
    // and destruction all route through the allocator, eliminating the
    // need for an explicit cleanse() member.
    std::vector<char, detail::secure_allocator<char>> bytes;

    Impl() = default;
    explicit Impl(std::string_view s)
    {
        if (!s.empty())
            bytes.assign(s.begin(), s.end());
    }
};

String::String() : d(nullptr) {}

String::String(std::string_view s) : d(std::make_unique<Impl>(s)) {}

String::String(const char* s) : d(std::make_unique<Impl>(s ? std::string_view(s) : std::string_view{})) {}

String::String(std::string&& src)
{
    // Cleanse @p src on every exit path, including the std::bad_alloc that
    // make_unique<Impl> may throw — without this guard the rvalue's bytes
    // would leak into deallocated heap on the throw path. std::string::data()
    // is mutable since C++17, so writing through it is well-defined; SSO
    // strings are zeroed in their inline buffer before the rvalue dies.
    struct Cleanser
    {
        std::string& s;
        ~Cleanser()
        {
            if (!s.empty())
                OPENSSL_cleanse(s.data(), s.size());
        }
    } guard{src};
    if (!src.empty())
        d = std::make_unique<Impl>(std::string_view{src});
}

String::~String() = default;

String::String(const String& other) : d(other.d ? std::make_unique<Impl>(other.view()) : nullptr) {}

String& String::operator=(const String& other)
{
    if (this == &other)
        return *this;
    // Self-view snapshot is unnecessary because self-assignment short-circuits
    // above; any aliasing through other.view() into our own bytes cannot
    // occur (different instances own disjoint heap blocks).
    // Replacement assignment to d destroys the old Impl, which destroys the
    // old vector — secure_allocator cleanses on deallocate.
    d = other.d ? std::make_unique<Impl>(other.view()) : nullptr;
    return *this;
}

String::String(String&& other) noexcept : d(std::move(other.d)) {}

String& String::operator=(String&& other) noexcept
{
    if (this == &other)
        return *this;
    // Replacement (move) of d destroys the old Impl → vector destructor →
    // secure_allocator cleanses freed storage.
    d = std::move(other.d);
    return *this;
}

String::operator bool() const noexcept
{
    return d != nullptr;
}

bool String::empty() const noexcept
{
    return !d || d->bytes.empty();
}

std::size_t String::size() const noexcept
{
    return d ? d->bytes.size() : 0;
}

std::string_view String::view() const noexcept
{
    if (!d || d->bytes.empty())
        return {};
    return std::string_view(d->bytes.data(), d->bytes.size());
}

void String::clear() noexcept
{
    if (!d)
        return;
    // bytes.clear() leaves capacity; shrink_to_fit() forces deallocation,
    // which routes through secure_allocator → OPENSSL_cleanse.
    d->bytes.clear();
    d->bytes.shrink_to_fit();
}

bool String::operator==(const String& other) const noexcept
{
    const auto a = view();
    const auto b = other.view();
    if (a.size() != b.size())
        return false;
    if (a.empty())
        return true;
    return std::memcmp(a.data(), b.data(), a.size()) == 0;
}

// operator!= synthesised by the compiler from operator== under C++20
// rewriting rules; no hand-written body required.

bool String::equalConstantTime(const String& other) const noexcept
{
    const auto a = view();
    const auto b = other.view();
    // Length-mismatch returns false immediately; before doing so, consume the
    // bytes of the longer input via CRYPTO_memcmp against itself so the
    // length-divergent path's runtime tracks size, not the length-equal path.
    // (The narrow-and-honest version would surface the length difference as a
    // data-dependent timing channel; that's almost always acceptable for a
    // PIN/MAC use-case, but the routine documents constant-time semantics so
    // we hold to them.)
    if (a.size() != b.size()) {
        const auto& longer = a.size() > b.size() ? a : b;
        if (!longer.empty()) {
            // Compare longer against itself; the result is discarded. Used as
            // a stable-time consumer of the bytes.
            (void)CRYPTO_memcmp(longer.data(), longer.data(), longer.size());
        }
        return false;
    }
    if (a.empty()) {
        return true;
    }
    return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

} // namespace LibreSCRS::Secure

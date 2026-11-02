// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Secure/Buffer.h>

#include "secure_allocator.h"

#include <utility>
#include <vector>

namespace LibreSCRS::Secure {

struct LIBRESCRS_INTERNAL Buffer::Impl
{
    // secure_allocator cleanses on deallocate, which the vector destructor
    // triggers automatically. No explicit ~Impl() body needed; future growth
    // APIs (push_back, reserve, …) inherit the cleanse-on-free invariant
    // for free, since every freed allocation routes through the allocator.
    std::vector<std::uint8_t, detail::secure_allocator<std::uint8_t>> bytes;
};

Buffer::Buffer() : d(nullptr) {}

Buffer::Buffer(std::string_view s) : d(std::make_unique<Impl>())
{
    if (!s.empty())
        d->bytes.assign(s.begin(), s.end());
}

Buffer::Buffer(std::span<const std::uint8_t> bytes) : d(std::make_unique<Impl>())
{
    if (!bytes.empty())
        d->bytes.assign(bytes.begin(), bytes.end());
}

Buffer::~Buffer() = default;

Buffer::Buffer(Buffer&& other) noexcept : d(std::move(other.d)) {}

Buffer& Buffer::operator=(Buffer&& other) noexcept
{
    if (this != &other)
        d = std::move(other.d);
    return *this;
}

const std::uint8_t* Buffer::data() const noexcept
{
    return (d && !d->bytes.empty()) ? d->bytes.data() : nullptr;
}

std::size_t Buffer::size() const noexcept
{
    return d ? d->bytes.size() : 0;
}

} // namespace LibreSCRS::Secure

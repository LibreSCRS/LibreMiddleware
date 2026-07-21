// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
#include "docp_parser.h"

namespace LibreSCRS::pkcs15 {
namespace {

// One BER-TLV field: tag/length parsed, value located. Short and 1-byte
// long-form lengths (0x81 LL) cover every DOCP field.
struct Tlv
{
    unsigned tag = 0;
    std::uint8_t firstByte = 0; // for constructed-tag detection (bit 0x20)
    std::span<const std::uint8_t> value;
    std::size_t next = 0; // offset just past this field
    bool ok = false;
};

Tlv readTlv(std::span<const std::uint8_t> b, std::size_t pos) noexcept
{
    Tlv t;
    if (pos >= b.size())
        return t;
    t.firstByte = b[pos];
    unsigned tag = b[pos++];
    if ((tag & 0x1F) == 0x1F) { // multi-byte tag
        while (pos < b.size()) {
            const std::uint8_t x = b[pos++];
            tag = (tag << 8) | x;
            if ((x & 0x80) == 0)
                break;
        }
    }
    if (pos >= b.size())
        return t;
    std::size_t len = b[pos++];
    if (len == 0x81) {
        if (pos >= b.size())
            return t;
        len = b[pos++];
    }
    if (pos + len > b.size())
        return t;
    t.tag = tag;
    t.value = b.subspan(pos, len);
    t.next = pos + len;
    t.ok = true;
    return t;
}

// Locate the '62' DOCP template, descending through the 70 / BF80xx wrap.
std::span<const std::uint8_t> findDocp(std::span<const std::uint8_t> b) noexcept
{
    for (std::size_t pos = 0; pos < b.size();) {
        const Tlv t = readTlv(b, pos);
        if (!t.ok)
            break;
        if (t.firstByte == 0x62)
            return t.value;
        // Descend into any constructed field (bit 0x20 of the first tag
        // byte): the 70 interindustry template and the multi-byte BF80xx
        // SDO tag both qualify; the 62 DOCP lives inside them.
        if ((t.firstByte & 0x20) != 0) {
            const auto inner = findDocp(t.value);
            if (!inner.empty())
                return inner;
        }
        pos = t.next;
    }
    return {};
}

int signedBE16(std::span<const std::uint8_t> v) noexcept
{
    return static_cast<std::int16_t>((v[0] << 8) | v[1]);
}

} // namespace

LibreSCRS::Plugin::CredentialCounters parseDocpCounters(std::span<const std::uint8_t> resp) noexcept
{
    LibreSCRS::Plugin::CredentialCounters c;
    const auto docp = findDocp(resp);
    for (std::size_t pos = 0; pos < docp.size();) {
        const Tlv t = readTlv(docp, pos);
        if (!t.ok)
            break;
        switch (t.tag) {
        case 0x99:
            if (t.value.size() == 1)
                c.unblocksLeft = t.value[0];
            break;
        case 0x9A:
            if (t.value.size() == 1)
                c.retriesMax = t.value[0];
            break;
        case 0x9B:
            if (t.value.size() == 1)
                c.retriesLeft = t.value[0];
            break;
        case 0x9C:
            if (t.value.size() == 2)
                c.usesMax = signedBE16(t.value);
            break;
        case 0x9D:
            if (t.value.size() == 2)
                c.usesLeft = signedBE16(t.value);
            break;
        default:
            break;
        }
        pos = t.next;
    }
    return c;
}

} // namespace LibreSCRS::pkcs15

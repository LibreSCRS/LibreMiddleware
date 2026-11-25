// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// Synthetic card files for the four Serbian eID document types, laid out as the
// chips store them: tag(2 LE) || len(2 LE) || inner TLVs, then zero padding up to
// the allocation. Text values are those read from the test cards; the photo is a
// JPEG stub and signed objects are absent (a real photo or SOD would carry the
// holder's face or the issuer's certificates, which do not belong in this repo).
//
// Protected files (0F07, 0D06, 0D11) are not listed: the card answers 6982 to
// their READ, which a test scripts with CardEdgeFileRig::protectFile.

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include "rs-eid-core/synthetic_annex.h"

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace LibreSCRS::RsEId::Test {

using CardFiles = std::map<std::uint16_t, std::vector<std::uint8_t>>;

namespace detail {

using Field = std::pair<std::uint16_t, std::string>;

inline std::vector<std::uint8_t> file(std::uint16_t fid, const std::vector<Field>& fields, std::size_t alloc)
{
    return Core::TestData::makeContainer(fid, fields, alloc);
}

/// The two-byte-per-character form the EL chip uses for most text.
inline std::string utf16le(std::u16string_view text)
{
    std::string out;
    for (const char16_t c : text) {
        out.push_back(static_cast<char>(c & 0xFF));
        out.push_back(static_cast<char>(c >> 8));
    }
    return out;
}

/// A JPEG stub: SOI, a JFIF marker, EOI.
inline std::string jpegStub()
{
    return std::string("\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\xFF\xD9", 14);
}

inline std::string ids(std::initializer_list<std::uint16_t> fids)
{
    std::string out;
    for (const auto f : fids) {
        out.push_back(static_cast<char>(f & 0xFF));
        out.push_back(static_cast<char>(f >> 8));
    }
    return out;
}

/// The public key file has no tag/length header, only the key.
inline std::vector<std::uint8_t> publicKeyFile()
{
    std::vector<std::uint8_t> key(141, 0x11);
    key[0] = 0x00;
    key[1] = 0x02;
    key[2] = 0x07;
    key[3] = 0x0D;
    return key;
}

/// Files every ID/IF/RP card carries besides the demographic ones.
inline void addCommonCardEdgeFiles(CardFiles& f, std::string_view version)
{
    f[0x0F1B] =
        file(0x0F1B,
             {{1537, std::string(version)},
              {1538, "01"},
              {1539, ids({0x0F02, 0x0F03, 0x0F04, 0x0F06, 0x0F07, 0x0D10, 0x0FA1, 0x0FA2, 0x0F12, 0x0F1C, 0x0F1D})}},
             148);
    f[0x0F06] = file(0x0F06, {{0x0110, jpegStub()}}, 0);
    f[0x0FA1] = file(0x0FA1, {{554, std::string(16, '\x5A')}}, 30);
    f[0x0FA2] = file(0x0FA2, {{556, std::string(10, '\xA5')}}, 18);
    f[0x0F12] = file(0x0F12, {{2625, "SSecFormat"}, {2626, "MUP Resursi CA 4"}}, 530);
    f[0x0D10] = publicKeyFile();
}

} // namespace detail

/// Citizen ID card (SERID).
inline CardFiles citizenFiles()
{
    using detail::file;
    CardFiles f;
    f[0x0F02] = file(0x0F02,
                     {{1546, "400000099"},
                      {1545, "SRB"},
                      {1547, "ID"},
                      {1548, "ID400000099"},
                      {1549, "20112026"},
                      {1550, "20112036"},
                      {1551, "ПУ ЗА ГРАД БЕОГРАД"},
                      {1552, "SC"},
                      {1553, "SC"}},
                     118);
    f[0x0F03] = file(0x0F03,
                     {{1558, "2902000000000"},
                      {1559, "ТЕСТ"},
                      {1560, "МИЛИЦА"},
                      {1561, "JOVAN"},
                      {1562, "Ž"},
                      {1563, "BEOGRAD"},
                      {1564, "SAVSKI VENAC"},
                      {1565, "REPUBLIKA SRBIJA"},
                      {1566, "29022000"},
                      {1567, "SRB"}},
                     130);
    f[0x0F04] = file(0x0F04,
                     {{1568, "SRBIJA"},
                      {1569, "NOVI BEOGRAD"},
                      {1570, "BEOGRAD"},
                      {1571, "UTOPIJA"},
                      {1572, "BB"},
                      {1575, "1"},
                      {1578, "8"},
                      {1580, "06082016"},
                      {1581, "PREBIVALIŠTE"}},
                     874);
    detail::addCommonCardEdgeFiles(f, "05");
    return f;
}

/// Foreigner ID card (SERIF).
inline CardFiles foreignerFiles()
{
    using detail::file;
    CardFiles f;
    f[0x0F02] = file(0x0F02,
                     {{1546, "400000020"},
                      {1545, "SRB"},
                      {1547, "IF"},
                      {1548, "IF400000020"},
                      {1549, "20112026"},
                      {1550, "20112031"},
                      {1551, "ПУ ЗА ГРАД БЕОГРАД"},
                      {1552, "SL"},
                      {1553, "SL"},
                      {1681, "LS00036515"},
                      {1557, "917d20b304b647"}},
                     150);
    f[0x0F03] = file(0x0F03,
                     {{1558, "2902000000000"},
                      {1559, "TEST"},
                      {1560, "MILICA"},
                      {1562, "Ž"},
                      {1565, "UTOPIJA"},
                      {1566, "29022000"},
                      {1567, "UTO"},
                      {1582, "Stalno nastanjenje"},
                      {1583, "UTOPIJA"}},
                     108);
    f[0x0F04] = file(0x0F04,
                     {{1568, "SRBIJA"},
                      {1569, "NOVI BEOGRAD"},
                      {1570, "BEOGRAD"},
                      {1571, "UTOPIJA"},
                      {1572, "BB"},
                      {1580, "01012024"}},
                     874);
    detail::addCommonCardEdgeFiles(f, "07");
    return f;
}

/// Residence permit (SERRP): no state in the address file, placeholder address date.
inline CardFiles residencePermitFiles()
{
    using detail::file;
    CardFiles f;
    f[0x0F02] = file(0x0F02,
                     {{1546, "400000071"},
                      {1545, "SRB"},
                      {1547, "RP"},
                      {1548, "RP400000071"},
                      {1549, "20112026"},
                      {1550, "20112031"},
                      {1551, "PU ZA GRAD BEOGRAD"},
                      {1681, "BD00169609"},
                      {1682, "DOZVOLA ZA PRIVREMENI BORAVAK I RAD"}},
                     144);
    f[0x0F03] = file(0x0F03,
                     {{1558, "2902000000000"},
                      {1559, "TEST"},
                      {1560, "MILICA"},
                      {1562, "Ž"},
                      {1565, "UTOPIJA"},
                      {1566, "29022000"},
                      {1567, "UTO"},
                      {1583, "UTOPIJA"},
                      {1683, "KRETANJE U OKVIRU PRIVREDNOG DRUŠTVA"},
                      {1684, "JEDINSTVENA DOZVOLA"}},
                     150);
    f[0x0F04] = file(
        0x0F04, {{1569, "NOVI BEOGRAD"}, {1570, "BEOGRAD"}, {1571, "UTOPIJA"}, {1572, "BB"}, {1580, "01010001"}}, 874);
    detail::addCommonCardEdgeFiles(f, "08");
    return f;
}

/// Official ID (SEREL): text is UTF-16LE except the ASCII and UTF-8 fields.
inline CardFiles serviceIdFiles()
{
    using detail::file;
    using detail::utf16le;
    CardFiles f;
    f[0x0D00] = file(
        0x0D00,
        {{1537, "01"},
         {1538, "01"},
         {1539, detail::ids({0x0D01, 0x0D02, 0x0D03, 0x0D04, 0x0D05, 0x0D06, 0x0D07, 0x0D08, 0x0D09, 0x0D0A, 0x0D10})}},
        148);
    f[0x0D01] = file(
        0x0D01,
        {{1553, utf16le(u"MUP Republike Srbije")}, {1554, "20112026"}, {1556, "400000097"}, {1557, "196d0056006d8218"}},
        93);
    f[0x0D02] = file(0x0D02,
                     {{1568, utf16le(u"ЈОВАНА")},
                      {1569, utf16le(u"ШАЈЕРМАН")},
                      {1570, "31071972"},
                      {1571, "3107972777016"},
                      {1572, "A-"},
                      {1573, "М"}, // UTF-8, not UTF-16
                      {1574, utf16le(u"1")},
                      {1575, "00000097"},
                      {1576, utf16le(u"Načelnik")}},
                     119);
    f[0x0D03] = file(
        0x0D03, {{1600, utf16le(u"Personalizacija")}, {1601, utf16le(u"Šef")}, {1602, utf16le(u"Kneza Miloša 101")}},
        1416);
    f[0x0D04] = file(0x0D04, {}, 1798);
    f[0x0D05] = file(0x0D05, {{0x0720, detail::jpegStub()}}, 0);
    f[0x0D07] = file(0x0D07, {{1872, std::string(16, '\x11')}}, 24);
    f[0x0D10] = detail::publicKeyFile();
    return f;
}

} // namespace LibreSCRS::RsEId::Test

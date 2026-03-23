// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <emrtd/data_group.h>

#include <algorithm>
#include <cstring>

namespace emrtd {

namespace {

// Trim trailing '<' characters (used as filler in MRZ) from a string
std::string trimFillers(const std::string& s)
{
    size_t end = s.size();
    while (end > 0 && s[end - 1] == '<')
        --end;
    return s.substr(0, end);
}

// Replace '<' with space and trim leading/trailing spaces
std::string mrzFieldToText(const std::string& s)
{
    std::string result = s;
    std::replace(result.begin(), result.end(), '<', ' ');
    // Trim leading spaces
    size_t start = result.find_first_not_of(' ');
    if (start == std::string::npos)
        return "";
    // Trim trailing spaces
    size_t end = result.find_last_not_of(' ');
    return result.substr(start, end - start + 1);
}

// Parse name field "SURNAME<<GIVEN<NAMES" into surname and given names
void parseName(const std::string& nameField, std::string& surname, std::string& givenNames)
{
    auto sep = nameField.find("<<");
    if (sep == std::string::npos) {
        surname = mrzFieldToText(nameField);
        givenNames = "";
        return;
    }
    surname = trimFillers(nameField.substr(0, sep));
    std::string given = nameField.substr(sep + 2);
    // Replace inner '<' with spaces, trim fillers
    std::replace(given.begin(), given.end(), '<', ' ');
    // Collapse multiple spaces
    std::string collapsed;
    bool prevSpace = false;
    for (char c : given) {
        if (c == ' ') {
            if (!prevSpace && !collapsed.empty())
                collapsed += ' ';
            prevSpace = true;
        } else {
            collapsed += c;
            prevSpace = false;
        }
    }
    // Trim trailing space
    while (!collapsed.empty() && collapsed.back() == ' ')
        collapsed.pop_back();
    givenNames = collapsed;
}

// Parse a TLV value: given a buffer and starting position, return the value bytes and advance pos.
// Returns empty vector on error.
[[maybe_unused]] std::vector<uint8_t> parseTLVValue(const std::vector<uint8_t>& data, size_t& pos)
{
    if (pos >= data.size())
        return {};

    // Skip tag (handle multi-byte tags)
    if ((data[pos] & 0x1F) == 0x1F) {
        ++pos;
        while (pos < data.size() && (data[pos] & 0x80))
            ++pos;
        if (pos >= data.size())
            return {};
        ++pos; // skip last tag byte
    } else {
        ++pos;
    }

    if (pos >= data.size())
        return {};

    // Parse length
    size_t len = 0;
    size_t headerLen = 0;
    uint8_t lenByte = data[pos];
    if (lenByte < 0x80) {
        len = lenByte;
        headerLen = 1;
    } else if (lenByte == 0x81 && pos + 1 < data.size()) {
        len = data[pos + 1];
        headerLen = 2;
    } else if (lenByte == 0x82 && pos + 2 < data.size()) {
        len = (static_cast<size_t>(data[pos + 1]) << 8) | data[pos + 2];
        headerLen = 3;
    } else if (lenByte == 0x83 && pos + 3 < data.size()) {
        len = (static_cast<size_t>(data[pos + 1]) << 16) | (static_cast<size_t>(data[pos + 2]) << 8) | data[pos + 3];
        headerLen = 4;
    } else {
        return {};
    }

    pos += headerLen;
    if (pos + len > data.size())
        return {};
    std::vector<uint8_t> value(data.begin() + static_cast<ptrdiff_t>(pos),
                               data.begin() + static_cast<ptrdiff_t>(pos + len));
    pos += len;
    return value;
}

// Find a specific tag inside a TLV-encoded buffer, return its value bytes.
// Handles simple (1-byte) and two-byte tags.
std::vector<uint8_t> findTag(const std::vector<uint8_t>& data, size_t start, size_t end, uint8_t tag1, uint8_t tag2 = 0)
{
    size_t pos = start;
    while (pos < end && pos < data.size()) {
        // Read tag
        bool twoByteTag = (data[pos] & 0x1F) == 0x1F;
        uint8_t t1 = data[pos];
        ++pos;
        uint8_t t2 = 0;
        if (twoByteTag) {
            if (pos >= data.size())
                break;
            // Handle multi-byte tags (only support up to 2 extra bytes here)
            while (pos < data.size() && (data[pos] & 0x80)) {
                t2 = data[pos];
                ++pos;
            }
            if (pos < data.size()) {
                t2 = data[pos];
                ++pos;
            }
        }

        if (pos >= data.size())
            break;

        // Read length
        size_t len = 0;
        size_t headerLen = 0;
        uint8_t lenByte = data[pos];
        if (lenByte < 0x80) {
            len = lenByte;
            headerLen = 1;
        } else if (lenByte == 0x81 && pos + 1 < data.size()) {
            len = data[pos + 1];
            headerLen = 2;
        } else if (lenByte == 0x82 && pos + 2 < data.size()) {
            len = (static_cast<size_t>(data[pos + 1]) << 8) | data[pos + 2];
            headerLen = 3;
        } else if (lenByte == 0x83 && pos + 3 < data.size()) {
            len =
                (static_cast<size_t>(data[pos + 1]) << 16) | (static_cast<size_t>(data[pos + 2]) << 8) | data[pos + 3];
            headerLen = 4;
        } else {
            break;
        }
        pos += headerLen;

        if (pos + len > data.size())
            break;

        // Check if this is our tag
        bool matched = (tag2 == 0) ? (t1 == tag1) : (t1 == tag1 && t2 == tag2);
        if (matched) {
            return std::vector<uint8_t>(data.begin() + static_cast<ptrdiff_t>(pos),
                                        data.begin() + static_cast<ptrdiff_t>(pos + len));
        }

        pos += len;
    }
    return {};
}

// Parse DG1 (MRZ data): tag 0x61, inner tag 0x5F1F containing raw MRZ
ParsedMRZ parseDG1(const std::vector<uint8_t>& data)
{
    // Find outer 0x61 wrapper
    std::vector<uint8_t> innerContent = findTag(data, 0, data.size(), 0x61);
    if (innerContent.empty()) {
        // Try parsing directly
        innerContent = data;
    }

    // Find tag 0x5F 0x1F inside
    std::vector<uint8_t> mrzBytes = findTag(innerContent, 0, innerContent.size(), 0x5F, 0x1F);
    if (mrzBytes.empty())
        return {};

    std::string mrzStr(mrzBytes.begin(), mrzBytes.end());
    return parseMRZ(mrzStr);
}

// Extract biometric image from DG2 or DG7 CBEFF/BIT data.
// Strategy: search for JPEG (FF D8 FF) or JPEG2000 magic bytes in the raw data.
BiometricImage extractBiometricImage(const std::vector<uint8_t>& data)
{
    BiometricImage img;

    // Search for JPEG magic bytes: FF D8 FF
    for (size_t i = 0; i + 2 < data.size(); ++i) {
        if (data[i] == 0xFF && data[i + 1] == 0xD8 && data[i + 2] == 0xFF) {
            img.mimeType = "image/jpeg";
            img.imageData.assign(data.begin() + static_cast<ptrdiff_t>(i), data.end());
            return img;
        }
    }

    // Search for JPEG2000 magic: 00 00 00 0C 6A 50 20 20
    for (size_t i = 0; i + 7 < data.size(); ++i) {
        if (data[i] == 0x00 && data[i + 1] == 0x00 && data[i + 2] == 0x00 && data[i + 3] == 0x0C &&
            data[i + 4] == 0x6A && data[i + 5] == 0x50) {
            img.mimeType = "image/jp2";
            img.imageData.assign(data.begin() + static_cast<ptrdiff_t>(i), data.end());
            return img;
        }
    }

    return img;
}

// Parse a sub-tag value as a UTF-8 string
std::string tagValueToString(const std::vector<uint8_t>& value)
{
    return std::string(value.begin(), value.end());
}

// Parse DG11 (Additional Personal Data)
AdditionalPersonalData parseDG11(const std::vector<uint8_t>& data)
{
    AdditionalPersonalData result;
    // Find outer tag 0x6B
    std::vector<uint8_t> content = findTag(data, 0, data.size(), 0x6B);
    if (content.empty())
        content = data;

    // Sub-tags (ICAO 9303 Part 10)
    auto val = findTag(content, 0, content.size(), 0x5F, 0x0E);
    if (!val.empty())
        result.fullName = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x0F);
    if (!val.empty())
        result.otherNames = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x10);
    if (!val.empty())
        result.personalNumber = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x11);
    if (!val.empty())
        result.placeOfBirth = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x42);
    if (!val.empty())
        result.address = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x12);
    if (!val.empty())
        result.telephone = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x13);
    if (!val.empty())
        result.profession = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x14);
    if (!val.empty())
        result.title = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x15);
    if (!val.empty())
        result.custodyInfo = tagValueToString(val);

    return result;
}

// Parse DG12 (Additional Document Data)
AdditionalDocumentData parseDG12(const std::vector<uint8_t>& data)
{
    AdditionalDocumentData result;
    // Find outer tag 0x6C
    std::vector<uint8_t> content = findTag(data, 0, data.size(), 0x6C);
    if (content.empty())
        content = data;

    auto val = findTag(content, 0, content.size(), 0x5F, 0x19);
    if (!val.empty())
        result.issuingAuthority = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x26);
    if (!val.empty())
        result.dateOfIssue = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x1B);
    if (!val.empty())
        result.endorsements = tagValueToString(val);

    val = findTag(content, 0, content.size(), 0x5F, 0x1C);
    if (!val.empty())
        result.taxExitRequirements = tagValueToString(val);

    return result;
}

} // anonymous namespace

ParsedMRZ parseMRZ(const std::string& mrz)
{
    if (mrz.empty())
        return {};

    // Split into lines (by '\n' if present, or by total length if contiguous)
    std::vector<std::string> lines;
    if (mrz.find('\n') != std::string::npos) {
        std::string current;
        for (char c : mrz) {
            if (c == '\n') {
                if (!current.empty())
                    lines.push_back(current);
                current.clear();
            } else {
                current += c;
            }
        }
        if (!current.empty())
            lines.push_back(current);
    } else {
        // No newlines — split by total length (ICAO 9303 Part 4)
        if (mrz.size() == 88) {
            // TD3: 2 × 44
            lines = {mrz.substr(0, 44), mrz.substr(44, 44)};
        } else if (mrz.size() == 72) {
            // TD2: 2 × 36
            lines = {mrz.substr(0, 36), mrz.substr(36, 36)};
        } else if (mrz.size() == 90) {
            // TD1: 3 × 30
            lines = {mrz.substr(0, 30), mrz.substr(30, 30), mrz.substr(60, 30)};
        } else {
            // Unknown format — try as single line (will fail gracefully)
            lines = {mrz};
        }
    }

    if (lines.empty())
        return {};

    ParsedMRZ result;
    result.rawMRZ = mrz;

    // Detect format by number of lines and length
    if (lines.size() >= 2 && lines[0].size() == 44 && lines[1].size() == 44) {
        // TD3 (passport, 2 lines of 44)
        const std::string& l1 = lines[0];
        const std::string& l2 = lines[1];

        // Line 1: positions 0-1=docCode, 2-4=issuingState, 5-43=name
        result.documentCode = trimFillers(l1.substr(0, 2));
        result.issuingState = trimFillers(l1.substr(2, 3));
        parseName(l1.substr(5, 39), result.surname, result.givenNames);

        // Line 2: 0-8=docNumber, 9=checkDigit, 10-12=nationality, 13-18=DOB, 19=check,
        //          20=sex, 21-26=DOE, 27=check, 28-42=optional
        result.documentNumber = trimFillers(l2.substr(0, 9));
        result.nationality = trimFillers(l2.substr(10, 3));
        result.dateOfBirth = l2.substr(13, 6);
        result.sex = l2.substr(20, 1);
        result.dateOfExpiry = l2.substr(21, 6);
        result.optionalData = trimFillers(l2.substr(28, 14));
    } else if (lines.size() >= 2 && lines[0].size() == 36 && lines[1].size() == 36) {
        // TD2 (2 lines of 36)
        const std::string& l1 = lines[0];
        const std::string& l2 = lines[1];

        result.documentCode = trimFillers(l1.substr(0, 2));
        result.issuingState = trimFillers(l1.substr(2, 3));
        parseName(l1.substr(5, 31), result.surname, result.givenNames);

        result.documentNumber = trimFillers(l2.substr(0, 9));
        result.nationality = trimFillers(l2.substr(10, 3));
        result.dateOfBirth = l2.substr(13, 6);
        result.sex = l2.substr(20, 1);
        result.dateOfExpiry = l2.substr(21, 6);
        result.optionalData = trimFillers(l2.substr(28, 7));
    } else if (lines.size() >= 3 && lines[0].size() >= 30 && lines[1].size() >= 30 && lines[2].size() >= 30) {
        // TD1 (ID card, 3 lines of 30)
        const std::string& l1 = lines[0];
        const std::string& l2 = lines[1];
        const std::string& l3 = lines[2];

        // Line 1: 0-1=docCode, 2-4=issuingState, 5-13=docNumber, 14=checkDigit, 15-29=optional
        result.documentCode = trimFillers(l1.substr(0, 2));
        result.issuingState = trimFillers(l1.substr(2, 3));
        result.documentNumber = trimFillers(l1.substr(5, 9));
        result.optionalData = trimFillers(l1.substr(15, 15));

        // Line 2: 0-5=DOB, 6=check, 7=sex, 8-13=DOE, 14=check, 15-17=nationality, 18-28=optional2
        result.dateOfBirth = l2.substr(0, 6);
        result.sex = l2.substr(7, 1);
        result.dateOfExpiry = l2.substr(8, 6);
        result.nationality = trimFillers(l2.substr(15, 3));
        auto opt2 = trimFillers(l2.substr(18, 11));
        if (!opt2.empty() && !result.optionalData.empty())
            result.optionalData += " " + opt2;
        else if (!opt2.empty())
            result.optionalData = opt2;

        // Line 3: name field
        parseName(l3, result.surname, result.givenNames);
    }

    return result;
}

DataGroups parseDataGroups(const std::map<int, std::vector<uint8_t>>& rawDGs)
{
    DataGroups result;

    for (const auto& [dg, data] : rawDGs) {
        try {
            switch (dg) {
            case 1: {
                auto parsed = parseDG1(data);
                if (!parsed.documentCode.empty() || !parsed.surname.empty()) {
                    result.dg1 = std::move(parsed);
                } else {
                    result.raw[dg] = data;
                }
                break;
            }
            case 2: {
                auto img = extractBiometricImage(data);
                if (!img.imageData.empty()) {
                    result.dg2 = std::move(img);
                } else {
                    result.raw[dg] = data;
                }
                break;
            }
            case 7: {
                auto img = extractBiometricImage(data);
                if (!img.imageData.empty()) {
                    result.dg7 = std::move(img);
                } else {
                    result.raw[dg] = data;
                }
                break;
            }
            case 11: {
                result.dg11 = parseDG11(data);
                break;
            }
            case 12: {
                result.dg12 = parseDG12(data);
                break;
            }
            case 13: {
                result.dg13 = data;
                break;
            }
            default:
                result.raw[dg] = data;
                break;
            }
        } catch (...) {
            // Tolerant: on any parse error, put DG in raw map
            result.raw[dg] = data;
        }
    }

    return result;
}

} // namespace emrtd

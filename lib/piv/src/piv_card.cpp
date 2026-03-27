// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <piv/piv_card.h>
#include "piv_protocol.h"

#include <smartcard/apdu.h>
#include <smartcard/ber.h>
#include <smartcard/pcsc_connection.h>
#include <smartcard/secure_buffer.h>

#include <array>

namespace piv {

namespace {

struct CertSlotDef
{
    std::array<uint8_t, 3> objectTag;
    uint8_t keyRef;
    const char* name;
};

constexpr std::array<CertSlotDef, 4> STANDARD_CERT_SLOTS = {{
    {protocol::OBJ_CERT_PIV_AUTH, protocol::KEY_PIV_AUTH, "PIV Authentication"},
    {protocol::OBJ_CERT_DIGITAL_SIG, protocol::KEY_DIGITAL_SIG, "Digital Signature"},
    {protocol::OBJ_CERT_KEY_MGMT, protocol::KEY_KEY_MGMT, "Key Management"},
    {protocol::OBJ_CERT_CARD_AUTH, protocol::KEY_CARD_AUTH, "Card Authentication"},
}};

// Tag 53 is primitive per BER rules (bit 5 clear), so parseBER stores its content
// as raw value bytes without recursing into children. We need to re-parse the
// value bytes of tag 53 to extract the nested TLV structure.
// PIV data objects are wrapped in tag 53 which is primitive (not constructed).
// parseBER can't recurse into its value. We manually extract the tag-53 value
// bytes, then parse them as a new BER stream. If strict BER parsing fails on
// the inner content (PIV uses some non-standard tags like FE), we do a lenient
// manual TLV walk that builds a flat BERField tree.
smartcard::BERField unwrapTag53(const std::vector<uint8_t>& raw)
{
    // First parse to find the tag-53 wrapper
    smartcard::BERField root;
    try {
        root = smartcard::parseBER(raw.data(), raw.size());
    } catch (...) {
        return {};
    }

    // Find tag 53 and get its raw value bytes
    const uint8_t* inner = nullptr;
    size_t innerLen = 0;
    for (const auto& child : root.children) {
        if (child.tag == 0x53 && !child.value.empty()) {
            inner = child.value.data();
            innerLen = child.value.size();
            break;
        }
    }
    if (!inner)
        return root; // No tag 53, return original tree

    // Try strict BER parse first
    try {
        return smartcard::parseBER(inner, innerLen);
    } catch (...) {
    }

    // Lenient manual TLV walk for PIV-specific content
    smartcard::BERField result;
    result.constructed = true;
    size_t pos = 0;
    while (pos < innerLen) {
        // Read tag (1 or 2 bytes)
        uint32_t tag = inner[pos++];
        if ((tag & 0x1F) == 0x1F) {
            // Multi-byte tag
            if (pos >= innerLen)
                break;
            tag = (tag << 8) | inner[pos++];
        }

        // Read length (1 or 2 bytes)
        if (pos >= innerLen)
            break;
        size_t len = inner[pos++];
        if (len == 0x81) {
            if (pos >= innerLen)
                break;
            len = inner[pos++];
        } else if (len == 0x82) {
            if (pos + 1 >= innerLen)
                break;
            len = (inner[pos] << 8) | inner[pos + 1];
            pos += 2;
        } else if (len >= 0x80) {
            break; // Invalid
        }

        if (pos + len > innerLen)
            break;

        smartcard::BERField field;
        field.tag = tag;
        field.constructed = false;
        field.value.assign(inner + pos, inner + pos + len);
        result.children.push_back(std::move(field));

        pos += len;
    }

    return result;
}

} // anonymous namespace

PIVCard::PIVCard(smartcard::PCSCConnection& conn) : conn(conn) {}

bool PIVCard::probe()
{
    std::vector<uint8_t> aid(protocol::AID.begin(), protocol::AID.end());
    auto cmd = smartcard::selectByAID(aid);
    auto resp = conn.transmit(cmd);
    // 9000 = success, 62xx = warning, 61xx = success with pending response data
    if (!resp.isSuccess() && resp.sw1 != 0x62 && resp.sw1 != 0x61)
        return false;

    // AID SELECT alone is insufficient — some non-PIV cards (e.g. Gemalto PKCS#15)
    // accept the PIV AID without error.  Validate by reading the CHUID data object
    // which is mandatory on genuine PIV cards (NIST SP 800-73-4 §4.2.1).
    auto chuid = getData(protocol::OBJ_CHUID);
    return !chuid.empty();
}

std::vector<uint8_t> PIVCard::getData(std::span<const uint8_t> objectTag)
{
    // Build data field: tag 5C + length + objectTag bytes
    std::vector<uint8_t> data;
    data.push_back(0x5C);
    data.push_back(static_cast<uint8_t>(objectTag.size()));
    data.insert(data.end(), objectTag.begin(), objectTag.end());

    smartcard::APDUCommand cmd{};
    cmd.cla = 0x00;
    cmd.ins = protocol::INS_GET_DATA;
    cmd.p1 = protocol::GET_DATA_P1;
    cmd.p2 = protocol::GET_DATA_P2;
    cmd.data = data;
    cmd.le = 0;
    cmd.hasLe = true;

    auto resp = conn.transmit(cmd);
    if (resp.isSuccess() || resp.sw1 == 0x62 || resp.sw1 == 0x61)
        return resp.data;
    return {};
}

CCCInfo PIVCard::readCCC()
{
    CCCInfo info;
    auto raw = getData(protocol::OBJ_CCC);
    if (raw.empty())
        return info;

    auto root = unwrapTag53(raw);
    info.cardIdentifier = smartcard::berFindBytes(root, {0xF0});
    info.capabilityContainer = smartcard::berFindBytes(root, {0xF1});
    info.capabilityVersion = smartcard::berFindBytes(root, {0xF2});
    info.capabilityGrammar = smartcard::berFindBytes(root, {0xF3});
    return info;
}

CHUIDInfo PIVCard::readCHUID()
{
    CHUIDInfo info;
    auto raw = getData(protocol::OBJ_CHUID);
    if (raw.empty())
        return info;

    auto root = unwrapTag53(raw);
    info.fascn = smartcard::berFindBytes(root, {0x30});
    info.guid = smartcard::berFindBytes(root, {0x34});
    info.expirationDate = smartcard::berFindString(root, {0x35});
    info.issuerAsymSignature = smartcard::berFindBytes(root, {0x3E});
    return info;
}

DiscoveryInfo PIVCard::readDiscovery()
{
    DiscoveryInfo info;
    auto raw = getData(protocol::OBJ_DISCOVERY);
    if (raw.empty())
        return info;

    auto root = smartcard::parseBER(raw.data(), raw.size());

    // Discovery uses 7E wrapper (not 53)
    auto aid = smartcard::berFindBytes(root, {0x7E, 0x4F});
    if (aid.empty())
        aid = smartcard::berFindBytes(root, {0x4F});
    info.pivAID = std::move(aid);

    auto policy = smartcard::berFindBytes(root, {0x7E, 0x5F2F});
    if (policy.empty())
        policy = smartcard::berFindBytes(root, {0x5F2F});
    if (policy.size() >= 2) {
        info.pinUsagePolicy = static_cast<uint16_t>((policy[0] << 8) | policy[1]);
    } else if (policy.size() == 1) {
        info.pinUsagePolicy = static_cast<uint16_t>(policy[0] << 8);
    }

    return info;
}

std::optional<PrintedInfo> PIVCard::readPrintedInfo()
{
    auto raw = getData(protocol::OBJ_PRINTED_INFO);
    if (raw.empty())
        return std::nullopt;

    auto root = unwrapTag53(raw);

    PrintedInfo info;
    auto tryFind = [&](uint32_t tag) -> std::string { return smartcard::berFindString(root, {tag}); };

    info.name = tryFind(0x01);
    info.employeeAffiliation = tryFind(0x02);
    info.expirationDate = tryFind(0x04);
    info.agencyCardSerialNumber = tryFind(0x05);
    info.issuerIdentification = tryFind(0x06);
    info.organizationAffiliation1 = tryFind(0x07);
    info.organizationAffiliation2 = tryFind(0x08);

    // Return nullopt if all fields are empty
    if (info.name.empty() && info.employeeAffiliation.empty() && info.expirationDate.empty() &&
        info.agencyCardSerialNumber.empty() && info.issuerIdentification.empty() &&
        info.organizationAffiliation1.empty() && info.organizationAffiliation2.empty()) {
        return std::nullopt;
    }

    return info;
}

std::optional<KeyHistoryInfo> PIVCard::readKeyHistory()
{
    auto raw = getData(protocol::OBJ_KEY_HISTORY);
    if (raw.empty())
        return std::nullopt;

    auto root = unwrapTag53(raw);

    KeyHistoryInfo info;

    auto onCard = smartcard::berFindBytes(root, {0xC1});
    if (!onCard.empty())
        info.keysWithOnCardCerts = onCard[0];

    auto offCard = smartcard::berFindBytes(root, {0xC2});
    if (!offCard.empty())
        info.keysWithOffCardCerts = offCard[0];

    info.offCardCertURL = smartcard::berFindString(root, {0xF3});

    if (info.keysWithOnCardCerts == 0 && info.keysWithOffCardCerts == 0 && info.offCardCertURL.empty()) {
        return std::nullopt;
    }

    return info;
}

std::vector<PIVCertificate> PIVCard::readCertificates()
{
    std::vector<PIVCertificate> certs;

    // Extract a TLV field's raw value bytes by walking the buffer manually.
    // This avoids BER constructed/primitive ambiguity for tags like 70.
    auto extractTlvValue = [](const uint8_t* buf, size_t bufLen, uint8_t targetTag) -> std::vector<uint8_t> {
        size_t pos = 0;
        while (pos < bufLen) {
            if (pos >= bufLen)
                break;
            uint8_t tag = buf[pos++];
            // Skip multi-byte tags
            if ((tag & 0x1F) == 0x1F) {
                while (pos < bufLen && (buf[pos] & 0x80))
                    ++pos;
                if (pos < bufLen)
                    ++pos; // last byte of tag
            }

            if (pos >= bufLen)
                break;
            size_t len = buf[pos++];
            if (len == 0x81) {
                if (pos >= bufLen)
                    break;
                len = buf[pos++];
            } else if (len == 0x82) {
                if (pos + 1 >= bufLen)
                    break;
                len = (size_t(buf[pos]) << 8) | buf[pos + 1];
                pos += 2;
            } else if (len == 0x83) {
                if (pos + 2 >= bufLen)
                    break;
                len = (size_t(buf[pos]) << 16) | (size_t(buf[pos + 1]) << 8) | buf[pos + 2];
                pos += 3;
            } else if (len >= 0x80) {
                break;
            }

            if (pos + len > bufLen)
                break;

            if (tag == targetTag)
                return {buf + pos, buf + pos + len};

            pos += len;
        }
        return {};
    };

    auto parseCertContainer = [&extractTlvValue](const std::vector<uint8_t>& raw, const std::string& slotName,
                                                 uint8_t keyRef) -> std::optional<PIVCertificate> {
        if (raw.empty())
            return std::nullopt;

        // Find tag 53 value, then extract tag 70 (cert) and 71 (certInfo) from it
        // Use raw TLV extraction to avoid BER constructed/primitive issues
        auto tag53value = extractTlvValue(raw.data(), raw.size(), 0x53);
        if (tag53value.empty())
            return std::nullopt;

        auto certBytes = extractTlvValue(tag53value.data(), tag53value.size(), 0x70);
        if (certBytes.empty())
            return std::nullopt;

        PIVCertificate cert;
        cert.slotName = slotName;
        cert.keyReference = keyRef;
        cert.certBytes = std::move(certBytes);

        auto certInfo = extractTlvValue(tag53value.data(), tag53value.size(), 0x71);
        if (!certInfo.empty())
            cert.certInfo = certInfo[0];

        return cert;
    };

    // Standard 4 certificate slots
    for (const auto& slot : STANDARD_CERT_SLOTS) {
        auto raw = getData(slot.objectTag);
        auto cert = parseCertContainer(raw, slot.name, slot.keyRef);
        if (cert)
            certs.push_back(std::move(*cert));
    }

    // 20 retired certificate slots
    for (int i = 0; i < 20; ++i) {
        std::array<uint8_t, 3> tag = {0x5F, 0xC1, static_cast<uint8_t>(0x0D + i)};
        uint8_t keyRef = static_cast<uint8_t>(0x82 + i);
        std::string name = "Retired Key " + std::to_string(i + 1);

        auto raw = getData(tag);
        auto cert = parseCertContainer(raw, name, keyRef);
        if (cert)
            certs.push_back(std::move(*cert));
    }

    return certs;
}

std::vector<PINInfo> PIVCard::discoverPINs()
{
    std::vector<PINInfo> pins;

    auto discovery = readDiscovery();
    uint8_t policyByte = static_cast<uint8_t>(discovery.pinUsagePolicy >> 8);

    bool foundAny = false;

    if (policyByte & protocol::PIN_POLICY_APP_PIN_PRIMARY) {
        pins.push_back({"PIV Application PIN", protocol::PIN_APPLICATION});
        foundAny = true;
    }
    if (policyByte & protocol::PIN_POLICY_GLOBAL_PIN) {
        pins.push_back({"Global PIN", protocol::PIN_GLOBAL});
        foundAny = true;
    }

    // Default to application PIN if nothing found
    if (!foundAny) {
        pins.push_back({"PIV Application PIN", protocol::PIN_APPLICATION});
    }

    return pins;
}

plugin::PINResult PIVCard::verifyPIN(uint8_t keyRef, const std::string& pin)
{
    // Pad PIN with 0xFF to 8 bytes — SecureBuffer ensures zeroization even on exception.
    smartcard::SecureBuffer paddedPin(8, 0xFF);
    for (size_t i = 0; i < pin.size() && i < 8; ++i) {
        paddedPin[i] = static_cast<uint8_t>(pin[i]);
    }

    auto cmd = smartcard::verifyPIN(keyRef, paddedPin);
    auto resp = conn.transmit(cmd);

    plugin::PINResult result;
    if (resp.isSuccess()) {
        result.success = true;
    } else if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0) {
        result.retriesLeft = resp.sw2 & 0x0F;
    } else if (resp.sw1 == 0x69 && resp.sw2 == 0x83) {
        result.blocked = true;
        result.retriesLeft = 0;
    }

    return result;
}

int PIVCard::getPINTriesLeft(uint8_t keyRef)
{
    auto cmd = smartcard::verifyPINStatus(keyRef);
    auto resp = conn.transmit(cmd);

    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0) {
        return resp.sw2 & 0x0F;
    }
    if (resp.sw1 == 0x69 && resp.sw2 == 0x83) {
        return 0; // blocked
    }
    if (resp.isSuccess()) {
        return -1; // already verified
    }
    return -1;
}

std::vector<std::pair<std::string, uint16_t>> PIVCard::discoverKeys()
{
    std::vector<std::pair<std::string, uint16_t>> keys;
    auto certs = readCertificates();
    for (const auto& cert : certs) {
        keys.emplace_back(cert.slotName, cert.keyReference);
    }
    return keys;
}

PIVData PIVCard::readAll()
{
    PIVData data;
    data.ccc = readCCC();
    data.chuid = readCHUID();
    data.discovery = readDiscovery();
    data.printedInfo = readPrintedInfo();
    data.keyHistory = readKeyHistory();
    data.certificates = readCertificates();
    return data;
}

} // namespace piv

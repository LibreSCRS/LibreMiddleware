// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkcs15/pkcs15_card.h>
#include <pkcs15/pkcs15_parser.h>
#include <smartcard/apdu.h>
#include <smartcard/pcsc_connection.h>

#include <stdexcept>

namespace pkcs15 {

namespace {

const std::vector<uint8_t> PKCS15_AID = {0xA0, 0x00, 0x00, 0x00, 0x63, 0x50, 0x4B, 0x43, 0x53, 0x2D, 0x31, 0x35};
constexpr size_t MAX_FILE_SIZE = 65536;
constexpr uint8_t READ_CHUNK_SIZE = 128;

} // namespace

PKCS15Card::PKCS15Card(smartcard::PCSCConnection& conn) : conn(conn) {}

bool PKCS15Card::probe()
{
    return selectApplet();
}

bool PKCS15Card::selectApplet()
{
    auto resp = conn.transmit(smartcard::selectByAID(PKCS15_AID));
    return resp.isSuccess();
}

PKCS15Profile PKCS15Card::readProfile()
{
    smartcard::CardTransaction tx(conn);

    if (!selectApplet())
        throw std::runtime_error("Failed to select PKCS#15 applet");

    // Read ODF (EF.ODF = 5031)
    const uint8_t odfFid[] = {0x50, 0x31};
    if (!selectByPath(odfFid))
        throw std::runtime_error("Failed to select EF.ODF");
    auto odfData = readSelectedFile();
    auto odf = parseODF(odfData);

    // Re-select applet before reading TokenInfo
    selectApplet();

    // Read TokenInfo (EF.TokenInfo = 5032)
    const uint8_t tokenInfoFid[] = {0x50, 0x32};
    if (!selectByPath(tokenInfoFid))
        throw std::runtime_error("Failed to select EF.TokenInfo");
    auto tokenData = readSelectedFile();
    auto tokenInfo = parseTokenInfo(tokenData);

    PKCS15Profile profile;
    profile.odf = odf;
    profile.tokenInfo = tokenInfo;

    // Read CDF if present
    if (!odf.certificatesPath.empty()) {
        selectApplet();
        if (selectByPath(odf.certificatesPath))
            profile.certificates = parseCDF(readSelectedFile());
    }

    // Read PrKDF if present
    if (!odf.privateKeysPath.empty()) {
        selectApplet();
        if (selectByPath(odf.privateKeysPath))
            profile.privateKeys = parsePrKDF(readSelectedFile());
    }

    // Read AODF if present
    if (!odf.authObjectsPath.empty()) {
        selectApplet();
        if (selectByPath(odf.authObjectsPath))
            profile.pins = parseAODF(readSelectedFile());
    }

    return profile;
}

std::vector<uint8_t> PKCS15Card::readCertificate(const CertificateInfo& cert)
{
    smartcard::CardTransaction tx(conn);
    selectApplet();

    if (!selectByPath(cert.path))
        throw std::runtime_error("Failed to select certificate file");

    return readSelectedFile();
}

int PKCS15Card::getPINTriesLeft(const PinInfo& pin)
{
    smartcard::CardTransaction tx(conn);
    selectApplet();

    // Navigate to PIN's DF if path is given
    if (!pin.path.empty())
        selectByPath(pin.path);

    // Try pinReference directly
    auto resp = conn.transmit(smartcard::verifyPINStatus(pin.pinReference));
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return resp.sw2 & 0x0F;
    if (resp.isSuccess())
        return -1; // already verified

    // Fallback: strip local bit (0x80)
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference) {
        resp = conn.transmit(smartcard::verifyPINStatus(altRef));
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
            return resp.sw2 & 0x0F;
        if (resp.isSuccess())
            return -1;
    }

    return -1; // unknown
}

PinResult PKCS15Card::verifyPIN(const PinInfo& pin, const std::string& pinValue)
{
    smartcard::CardTransaction tx(conn);
    selectApplet();

    if (!pin.path.empty())
        selectByPath(pin.path);

    // Encode PIN data
    std::vector<uint8_t> pinData(pinValue.begin(), pinValue.end());
    if (pin.storedLength > 0 && static_cast<int>(pinData.size()) > pin.storedLength)
        pinData.resize(pin.storedLength);
    if (pin.storedLength > 0 && static_cast<int>(pinData.size()) < pin.storedLength)
        pinData.resize(pin.storedLength, pin.padChar);

    // Try pinReference directly
    auto resp = conn.transmit(smartcard::verifyPIN(pin.pinReference, pinData));
    if (resp.isSuccess())
        return {true, -1, false};
    if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
        return {false, resp.sw2 & 0x0F, false};
    if (resp.statusWord() == 0x6983)
        return {false, 0, true};

    // Fallback: strip local bit
    uint8_t altRef = pin.pinReference & 0x7F;
    if (altRef != pin.pinReference) {
        resp = conn.transmit(smartcard::verifyPIN(altRef, pinData));
        if (resp.isSuccess())
            return {true, -1, false};
        if (resp.sw1 == 0x63 && (resp.sw2 & 0xF0) == 0xC0)
            return {false, resp.sw2 & 0x0F, false};
        if (resp.statusWord() == 0x6983)
            return {false, 0, true};
    }

    return {false, -1, false};
}

bool PKCS15Card::selectByPath(std::span<const uint8_t> path)
{
    if (path.empty() || path.size() % 2 != 0)
        return false;

    for (size_t i = 0; i + 1 < path.size(); i += 2) {
        auto resp = conn.transmit(smartcard::selectByFileId(path[i], path[i + 1]));
        if (!resp.isSuccess())
            return false;
    }
    return true;
}

std::vector<uint8_t> PKCS15Card::readSelectedFile()
{
    std::vector<uint8_t> result;
    size_t offset = 0;

    while (true) {
        auto resp = conn.transmit(smartcard::readBinary(static_cast<uint16_t>(offset), READ_CHUNK_SIZE));
        if (resp.data.empty() || (!resp.isSuccess() && resp.statusWord() != 0x6282))
            break;

        result.insert(result.end(), resp.data.begin(), resp.data.end());
        offset += resp.data.size();

        if (offset >= MAX_FILE_SIZE)
            break;
        if (resp.statusWord() == 0x6282) // end of file
            break;
    }

    return result;
}

} // namespace pkcs15

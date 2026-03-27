// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "rseid/eidcard.h"
#include "card_protocol.h"
#include "card_reader_base.h"
#include "card_reader_gemalto.h"
#include "card_reader_apollo.h"
#include "card_verifier.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/tlv.h"
#include "smartcard/apdu.h"
#include <algorithm>

namespace eidcard {

// Format "DDMMYYYY" → "DD.MM.YYYY", pass through anything else unchanged
static std::string formatDate(const std::string& raw)
{
    if (raw.size() == 8 && std::all_of(raw.begin(), raw.end(), ::isdigit))
        return raw.substr(0, 2) + "." + raw.substr(2, 2) + "." + raw.substr(4, 4);
    return raw;
}

bool EIdCard::probe(const std::string& readerName)
{
    try {
        smartcard::PCSCConnection conn(readerName);
        auto atr = conn.getATR();
        if (protocol::isGemaltoATR(atr) || protocol::isApolloATR(atr))
            return true;
        // Unknown ATR — try Gemalto AID selection as fallback
        return CardReaderGemalto::selectApplication(conn) != CardType::Unknown;
    } catch (...) {
        return false;
    }
}

// Shared init logic for both constructors
void EIdCard::detectCardType()
{
    auto atr = conn->getATR();

    if (protocol::isGemaltoATR(atr)) {
        cardType = CardReaderGemalto::selectApplication(*conn);
        cardReader = std::make_unique<CardReaderGemalto>();
    } else if (protocol::isApolloATR(atr)) {
        cardType = CardType::Apollo2008;
        cardReader = std::make_unique<CardReaderApollo>();
    } else {
        cardType = CardReaderGemalto::selectApplication(*conn);
        if (cardType != CardType::Unknown) {
            cardReader = std::make_unique<CardReaderGemalto>();
        } else {
            throw std::runtime_error("Unknown card type, ATR not recognized");
        }
    }
}

EIdCard::EIdCard(const std::string& readerName)
{
    ownedConnection = std::make_unique<smartcard::PCSCConnection>(readerName);
    conn = ownedConnection.get();
    detectCardType();
}

EIdCard::EIdCard(smartcard::PCSCConnection& externalConn) : conn(&externalConn)
{
    detectCardType();
}

EIdCard::~EIdCard() = default;

CardType EIdCard::getCardType() const
{
    return cardType;
}

DocumentData EIdCard::readDocumentData()
{
    smartcard::CardTransaction tx(*conn);
    auto raw = cardReader->readFile(*conn, protocol::FILE_DOCUMENT_DATA_H, protocol::FILE_DOCUMENT_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    DocumentData doc;
    doc.docRegNo = smartcard::findString(fields, protocol::TAG_DOC_REG_NO);
    doc.documentType = smartcard::findString(fields, protocol::TAG_DOCUMENT_TYPE);
    doc.documentSerialNumber = smartcard::findString(fields, protocol::TAG_DOCUMENT_SERIAL_NO);
    doc.issuingDate = formatDate(smartcard::findString(fields, protocol::TAG_ISSUING_DATE));
    doc.expiryDate = formatDate(smartcard::findString(fields, protocol::TAG_EXPIRY_DATE));
    doc.issuingAuthority = smartcard::findString(fields, protocol::TAG_ISSUING_AUTHORITY);
    doc.chipSerialNumber = smartcard::findString(fields, protocol::TAG_CHIP_SERIAL_NUMBER);
    return doc;
}

FixedPersonalData EIdCard::readFixedPersonalData()
{
    smartcard::CardTransaction tx(*conn);
    auto raw = cardReader->readFile(*conn, protocol::FILE_PERSONAL_DATA_H, protocol::FILE_PERSONAL_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    FixedPersonalData fpd;
    fpd.personalNumber = smartcard::findString(fields, protocol::TAG_PERSONAL_NUMBER);
    fpd.surname = smartcard::findString(fields, protocol::TAG_SURNAME);
    fpd.givenName = smartcard::findString(fields, protocol::TAG_GIVEN_NAME);
    fpd.parentGivenName = smartcard::findString(fields, protocol::TAG_PARENT_GIVEN_NAME);
    fpd.sex = smartcard::findString(fields, protocol::TAG_SEX);
    fpd.placeOfBirth = smartcard::findString(fields, protocol::TAG_PLACE_OF_BIRTH);
    fpd.communityOfBirth = smartcard::findString(fields, protocol::TAG_COMMUNITY_OF_BIRTH);
    fpd.stateOfBirth = smartcard::findString(fields, protocol::TAG_STATE_OF_BIRTH);
    fpd.dateOfBirth = formatDate(smartcard::findString(fields, protocol::TAG_DATE_OF_BIRTH));
    fpd.nationalityFull = smartcard::findString(fields, protocol::TAG_NATIONALITY_FULL);
    fpd.statusOfForeigner = smartcard::findString(fields, protocol::TAG_STATUS_OF_FOREIGNER);
    return fpd;
}

VariablePersonalData EIdCard::readVariablePersonalData()
{
    smartcard::CardTransaction tx(*conn);
    auto raw = cardReader->readFile(*conn, protocol::FILE_VARIABLE_DATA_H, protocol::FILE_VARIABLE_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    VariablePersonalData vpd;
    vpd.state = smartcard::findString(fields, protocol::TAG_STATE);
    vpd.community = smartcard::findString(fields, protocol::TAG_COMMUNITY);
    vpd.place = smartcard::findString(fields, protocol::TAG_PLACE);
    vpd.street = smartcard::findString(fields, protocol::TAG_STREET);
    vpd.houseNumber = smartcard::findString(fields, protocol::TAG_HOUSE_NUMBER);
    vpd.houseLetter = smartcard::findString(fields, protocol::TAG_HOUSE_LETTER);
    vpd.entrance = smartcard::findString(fields, protocol::TAG_ENTRANCE);
    vpd.floor = smartcard::findString(fields, protocol::TAG_FLOOR);
    vpd.apartmentNumber = smartcard::findString(fields, protocol::TAG_APARTMENT_NUMBER);
    vpd.addressDate = formatDate(smartcard::findString(fields, protocol::TAG_ADDRESS_DATE));
    vpd.addressLabel = smartcard::findString(fields, protocol::TAG_ADDRESS_LABEL);
    return vpd;
}

PhotoData EIdCard::readPortrait()
{
    smartcard::CardTransaction tx(*conn);
    auto raw = cardReader->readFile(*conn, protocol::FILE_PORTRAIT_H, protocol::FILE_PORTRAIT_L);
    // Photo file data has a 4-byte TLV header (tag + length); trim it
    if (raw.size() > 4) {
        return PhotoData(raw.begin() + 4, raw.end());
    }
    return {};
}

void EIdCard::setCertificateFolderPath(const std::string& path)
{
    certFolderPath = path;
    verifier.reset(); // force re-creation with new path
}

void EIdCard::addTrustedCertificate(const std::vector<uint8_t>& derCert)
{
    if (!verifier)
        verifier = std::make_unique<CardVerifier>(""); // empty path = cert-by-cert mode
    verifier->addCertificate(derCert);
}

void EIdCard::ensureVerifier()
{
    if (!verifier && !certFolderPath.empty()) {
        verifier = std::make_unique<CardVerifier>(certFolderPath);
    }
}

VerificationResult EIdCard::verifyCard()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyCard(*conn, *cardReader, cardType);
}

VerificationResult EIdCard::verifyFixedData()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyFixedData(*conn, *cardReader, cardType);
}

VerificationResult EIdCard::verifyVariableData()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyVariableData(*conn, *cardReader, cardType);
}

} // namespace eidcard

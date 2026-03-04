// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#include "eidcard/eidcard.h"
#include "card_protocol.h"
#include "card_reader_base.h"
#include "card_reader_gemalto.h"
#include "card_reader_apollo.h"
#include "card_verifier.h"
#include "cardedge/cardedge.h"
#include "cardedge/pki_applet_guard.h"
#include "smartcard/pcsc_connection.h"
#include "smartcard/tlv.h"
#include "smartcard/apdu.h"
#include <algorithm>

namespace eidcard {

// Format "DDMMYYYY" → "DD.MM.YYYY", pass through anything else unchanged
static std::string formatDate(const std::string& raw) {
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

EIdCard::EIdCard(const std::string& readerName)
{
    connection = std::make_unique<smartcard::PCSCConnection>(readerName);

    // Detect card type from ATR
    auto atr = connection->getATR();

    if (protocol::isGemaltoATR(atr)) {
        // Gemalto card: try AID selection to determine citizen/foreigner
        cardType = CardReaderGemalto::selectApplication(*connection);
        cardReader = std::make_unique<CardReaderGemalto>();
    } else if (protocol::isApolloATR(atr)) {
        cardType = CardType::Apollo2008;
        cardReader = std::make_unique<CardReaderApollo>();
    } else {
        // Unknown ATR - try Gemalto AID selection as fallback
        cardType = CardReaderGemalto::selectApplication(*connection);
        if (cardType != CardType::Unknown) {
            cardReader = std::make_unique<CardReaderGemalto>();
        } else {
            throw std::runtime_error("Unknown card type, ATR not recognized");
        }
    }
}

EIdCard::~EIdCard() = default;

CardType EIdCard::getCardType() const
{
    return cardType;
}

DocumentData EIdCard::readDocumentData()
{
    smartcard::CardTransaction tx(*connection);
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_DOCUMENT_DATA_H,
                                     protocol::FILE_DOCUMENT_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    DocumentData doc;
    doc.docRegNo            = smartcard::findString(fields, protocol::TAG_DOC_REG_NO);
    doc.documentType        = smartcard::findString(fields, protocol::TAG_DOCUMENT_TYPE);
    doc.documentSerialNumber = smartcard::findString(fields, protocol::TAG_DOCUMENT_SERIAL_NO);
    doc.issuingDate         = formatDate(smartcard::findString(fields, protocol::TAG_ISSUING_DATE));
    doc.expiryDate          = formatDate(smartcard::findString(fields, protocol::TAG_EXPIRY_DATE));
    doc.issuingAuthority    = smartcard::findString(fields, protocol::TAG_ISSUING_AUTHORITY);
    doc.chipSerialNumber    = smartcard::findString(fields, protocol::TAG_CHIP_SERIAL_NUMBER);
    return doc;
}

FixedPersonalData EIdCard::readFixedPersonalData()
{
    smartcard::CardTransaction tx(*connection);
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_PERSONAL_DATA_H,
                                     protocol::FILE_PERSONAL_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    FixedPersonalData fpd;
    fpd.personalNumber   = smartcard::findString(fields, protocol::TAG_PERSONAL_NUMBER);
    fpd.surname          = smartcard::findString(fields, protocol::TAG_SURNAME);
    fpd.givenName        = smartcard::findString(fields, protocol::TAG_GIVEN_NAME);
    fpd.parentGivenName  = smartcard::findString(fields, protocol::TAG_PARENT_GIVEN_NAME);
    fpd.sex              = smartcard::findString(fields, protocol::TAG_SEX);
    fpd.placeOfBirth     = smartcard::findString(fields, protocol::TAG_PLACE_OF_BIRTH);
    fpd.communityOfBirth = smartcard::findString(fields, protocol::TAG_COMMUNITY_OF_BIRTH);
    fpd.stateOfBirth     = smartcard::findString(fields, protocol::TAG_STATE_OF_BIRTH);
    fpd.dateOfBirth      = formatDate(smartcard::findString(fields, protocol::TAG_DATE_OF_BIRTH));
    fpd.nationalityFull  = smartcard::findString(fields, protocol::TAG_NATIONALITY_FULL);
    fpd.statusOfForeigner = smartcard::findString(fields, protocol::TAG_STATUS_OF_FOREIGNER);
    return fpd;
}

VariablePersonalData EIdCard::readVariablePersonalData()
{
    smartcard::CardTransaction tx(*connection);
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_VARIABLE_DATA_H,
                                     protocol::FILE_VARIABLE_DATA_L);
    auto fields = smartcard::parseTLV(raw.data(), raw.size());

    VariablePersonalData vpd;
    vpd.state           = smartcard::findString(fields, protocol::TAG_STATE);
    vpd.community       = smartcard::findString(fields, protocol::TAG_COMMUNITY);
    vpd.place           = smartcard::findString(fields, protocol::TAG_PLACE);
    vpd.street          = smartcard::findString(fields, protocol::TAG_STREET);
    vpd.houseNumber     = smartcard::findString(fields, protocol::TAG_HOUSE_NUMBER);
    vpd.houseLetter     = smartcard::findString(fields, protocol::TAG_HOUSE_LETTER);
    vpd.entrance        = smartcard::findString(fields, protocol::TAG_ENTRANCE);
    vpd.floor           = smartcard::findString(fields, protocol::TAG_FLOOR);
    vpd.apartmentNumber = smartcard::findString(fields, protocol::TAG_APARTMENT_NUMBER);
    vpd.addressDate     = formatDate(smartcard::findString(fields, protocol::TAG_ADDRESS_DATE));
    vpd.addressLabel    = smartcard::findString(fields, protocol::TAG_ADDRESS_LABEL);
    return vpd;
}

PhotoData EIdCard::readPortrait()
{
    smartcard::CardTransaction tx(*connection);
    auto raw = cardReader->readFile(*connection,
                                     protocol::FILE_PORTRAIT_H,
                                     protocol::FILE_PORTRAIT_L);
    // Photo file data has a 4-byte TLV header (tag + length); trim it
    if (raw.size() > 4) {
        return PhotoData(raw.begin() + 4, raw.end());
    }
    return {};
}

CertificateList EIdCard::readCertificates()
{
    if (cardType != CardType::Gemalto2014 && cardType != CardType::ForeignerIF2020)
        return {};

    cardedge::PkiAppletGuard guard(*connection, [](auto& c) {
        CardReaderGemalto::selectApplication(c);
    });
    return cardedge::readCertificates(*connection);
}

PINResult EIdCard::getPINTriesLeft()
{
    if (cardType == CardType::Apollo2008)
        throw std::runtime_error("PIN operations not supported on Apollo2008 cards");

    cardedge::PkiAppletGuard guard(*connection, [](auto& c) {
        CardReaderGemalto::selectApplication(c);
    });
    return cardedge::getPINTriesLeft(*connection);
}

PINResult EIdCard::verifyPIN(const std::string& pin)
{
    if (cardType == CardType::Apollo2008)
        throw std::runtime_error("PIN operations not supported on Apollo2008 cards");

    cardedge::PkiAppletGuard guard(*connection, [](auto& c) {
        CardReaderGemalto::selectApplication(c);
    });
    return cardedge::verifyPIN(*connection, pin);
}

PINResult EIdCard::changePIN(const std::string& oldPin, const std::string& newPin)
{
    if (cardType == CardType::Apollo2008)
        throw std::runtime_error("PIN operations not supported on Apollo2008 cards");

    cardedge::PkiAppletGuard guard(*connection, [](auto& c) {
        CardReaderGemalto::selectApplication(c);
    });
    return cardedge::changePIN(*connection, oldPin, newPin);
}

std::vector<uint8_t> EIdCard::signData(uint16_t keyReference,
                                        const std::vector<uint8_t>& data)
{
    if (cardType != CardType::Gemalto2014 && cardType != CardType::ForeignerIF2020)
        throw std::runtime_error("signData not supported on this card type");

    cardedge::PkiAppletGuard guard(*connection, [](auto& c) {
        CardReaderGemalto::selectApplication(c);
    });
    return cardedge::signData(*connection, keyReference, data);
}

std::vector<std::pair<std::string, uint16_t>> EIdCard::discoverKeyReferences()
{
    if (cardType != CardType::Gemalto2014 && cardType != CardType::ForeignerIF2020)
        return {};

    cardedge::PkiAppletGuard guard(*connection, [](auto& c) {
        CardReaderGemalto::selectApplication(c);
    });
    return cardedge::discoverKeyReferences(*connection);
}

void EIdCard::reconnectConnection()
{
    if (connection)
        connection->reconnect();
}

void EIdCard::setCertificateFolderPath(const std::string& path)
{
    certFolderPath = path;
    verifier.reset();  // force re-creation with new path
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
    return verifier->verifyCard(*connection, *cardReader, cardType);
}

VerificationResult EIdCard::verifyFixedData()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyFixedData(*connection, *cardReader, cardType);
}

VerificationResult EIdCard::verifyVariableData()
{
    ensureVerifier();
    if (!verifier)
        return VerificationResult::Unknown;
    return verifier->verifyVariableData(*connection, *cardReader, cardType);
}

} // namespace eidcard

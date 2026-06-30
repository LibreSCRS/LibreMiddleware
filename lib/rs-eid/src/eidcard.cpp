// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "eidcard.h"
#include "card_protocol.h"
#include "card_reader_base.h"
#include "card_reader_gemalto.h"
#include "card_reader_apollo.h"
#include "card_verifier.h"
#include <pcsc_connection.h>
#include "date_format.h"
#include "tlv.h"
#include "apdu.h"

namespace eidcard {

using LibreSCRS::SmartCard::Internal::formatDateDMY;

// Init logic for the constructor
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

EIdCard::EIdCard(LibreSCRS::SmartCard::Internal::PCSCConnection& externalConn) : conn(&externalConn)
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
    LibreSCRS::SmartCard::Internal::CardTransaction tx(*conn);
    auto raw = cardReader->readFile(*conn, protocol::FILE_DOCUMENT_DATA_H, protocol::FILE_DOCUMENT_DATA_L);
    auto fields = LibreSCRS::SmartCard::Internal::parseTLV(raw.data(), raw.size());

    DocumentData doc;
    doc.docRegNo = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_DOC_REG_NO);
    doc.documentType = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_DOCUMENT_TYPE);
    doc.documentSerialNumber = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_DOCUMENT_SERIAL_NO);
    doc.issuingDate = formatDateDMY(LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_ISSUING_DATE));
    doc.expiryDate = formatDateDMY(LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_EXPIRY_DATE));
    doc.issuingAuthority = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_ISSUING_AUTHORITY);
    doc.chipSerialNumber = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_CHIP_SERIAL_NUMBER);
    return doc;
}

FixedPersonalData EIdCard::readFixedPersonalData()
{
    LibreSCRS::SmartCard::Internal::CardTransaction tx(*conn);
    auto raw = cardReader->readFile(*conn, protocol::FILE_PERSONAL_DATA_H, protocol::FILE_PERSONAL_DATA_L);
    auto fields = LibreSCRS::SmartCard::Internal::parseTLV(raw.data(), raw.size());

    FixedPersonalData fpd;
    fpd.personalNumber = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_PERSONAL_NUMBER);
    fpd.surname = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_SURNAME);
    fpd.givenName = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_GIVEN_NAME);
    fpd.parentGivenName = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_PARENT_GIVEN_NAME);
    fpd.sex = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_SEX);
    fpd.placeOfBirth = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_PLACE_OF_BIRTH);
    fpd.communityOfBirth = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_COMMUNITY_OF_BIRTH);
    fpd.stateOfBirth = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_STATE_OF_BIRTH);
    fpd.dateOfBirth = formatDateDMY(LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_DATE_OF_BIRTH));
    fpd.nationalityFull = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_NATIONALITY_FULL);
    fpd.statusOfForeigner = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_STATUS_OF_FOREIGNER);
    return fpd;
}

VariablePersonalData EIdCard::readVariablePersonalData()
{
    LibreSCRS::SmartCard::Internal::CardTransaction tx(*conn);
    auto raw = cardReader->readFile(*conn, protocol::FILE_VARIABLE_DATA_H, protocol::FILE_VARIABLE_DATA_L);
    auto fields = LibreSCRS::SmartCard::Internal::parseTLV(raw.data(), raw.size());

    VariablePersonalData vpd;
    vpd.state = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_STATE);
    vpd.community = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_COMMUNITY);
    vpd.place = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_PLACE);
    vpd.street = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_STREET);
    vpd.houseNumber = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_HOUSE_NUMBER);
    vpd.houseLetter = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_HOUSE_LETTER);
    vpd.entrance = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_ENTRANCE);
    vpd.floor = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_FLOOR);
    vpd.apartmentNumber = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_APARTMENT_NUMBER);
    vpd.addressDate = formatDateDMY(LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_ADDRESS_DATE));
    vpd.addressLabel = LibreSCRS::SmartCard::Internal::findString(fields, protocol::TAG_ADDRESS_LABEL);
    return vpd;
}

PhotoData EIdCard::readPortrait()
{
    LibreSCRS::SmartCard::Internal::CardTransaction tx(*conn);
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

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0
//
// The four Serbian eID document types as data. Content comes from measurements
// of test cards; a tag is named here only where its meaning is confirmed.

#include "rs_document_profile.h"

#include "rs_tags.h"

#include <array>

namespace LibreSCRS::RsEId::Core {
namespace {

namespace t = tags;

constexpr auto kUtf8 = TextEncoding::Utf8;
constexpr auto kUtf16 = TextEncoding::Utf16Le;
constexpr auto kText = FieldFormat::Text;
constexpr auto kDate = FieldFormat::Date;
constexpr auto kEdge = static_cast<std::uint8_t>(Surface::CardEdge);
constexpr auto kAnnex = static_cast<std::uint8_t>(Surface::Annex);
constexpr auto kBoth = static_cast<std::uint8_t>(kEdge | kAnnex);

constexpr auto kHeader = ReadMode::Header;
constexpr auto kAllocation = ReadMode::Allocation;

// --- ID, IF, RP: one layout, told apart by AID and by which tags are present ---

constexpr std::array<std::uint8_t, 11> kAidId{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x44, 0x01};
constexpr std::array<std::uint8_t, 11> kAidIf{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x49, 0x46, 0x01};
constexpr std::array<std::uint8_t, 11> kAidRp{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x52, 0x50, 0x01};
constexpr std::array<std::uint8_t, 11> kAidEl{0xF3, 0x81, 0x00, 0x00, 0x02, 0x53, 0x45, 0x52, 0x45, 0x4C, 0x01};

// 0F07 (protected) and 0D11 are not listed: nothing can read them.
constexpr std::array kCardEdgeFiles{
    FileSpec{t::kFidManifest, kHeader},      FileSpec{t::kFidDocumentData, kHeader},
    FileSpec{t::kFidPersonalData, kHeader},  FileSpec{t::kFidVariableData, kHeader},
    FileSpec{t::kFidPhoto, kHeader},         FileSpec{t::kFidIdHash, kHeader},
    FileSpec{t::kFidIssuerHash, kHeader},    FileSpec{t::kFidCertDigests, kAllocation},
    FileSpec{t::kFidPublicKey, kAllocation}, FileSpec{t::kFidSodFixed, kHeader},
    FileSpec{t::kFidSodVariable, kHeader},
};

constexpr std::array kCardEdgeGroups{
    GroupSpec{"personal", "Personal Data"},
    GroupSpec{"address", "Address"},
    GroupSpec{"document", "Document Data"},
};

// Rows are ordered by file id, and within a file by display order; the annex
// rows sit where today's annex emits them, so its output does not move.
constexpr std::array kCardEdgeFields{
    // 0F02
    FieldSpec{t::kFidDocumentData, t::kDocRegNo, "doc_reg_no", "Registration Number", "document", kUtf8, kText, kEdge},
    FieldSpec{t::kFidDocumentData, t::kDocumentType, "document_type", "Document Type", "document", kUtf8, kText, kEdge},
    FieldSpec{t::kFidDocumentData, t::kDocumentSerialNo, "document_serial_number", "Serial Number", "document", kUtf8,
              kText, kEdge},
    FieldSpec{t::kFidDocumentData, t::kDocumentSerialNo, "document_serial", "Document Number", "personal", kUtf8, kText,
              kAnnex},
    FieldSpec{t::kFidDocumentData, t::kIssuingDate, "issuing_date", "Issuing Date", "document", kUtf8, kDate, kEdge},
    FieldSpec{t::kFidDocumentData, t::kExpiryDate, "expiry_date", "Expiry Date", "document", kUtf8, kDate, kEdge},
    FieldSpec{t::kFidDocumentData, t::kIssuingAuthority, "issuing_authority", "Issuing Authority", "document", kUtf8,
              kText, kEdge},
    FieldSpec{t::kFidDocumentData, t::kDocumentName, "document_name", "Document Name", "document", kUtf8, kText, kEdge},
    FieldSpec{t::kFidDocumentData, t::kCardNumber, "card_number", "Card Number", "document", kUtf8, kText, kEdge},
    // 0F03
    FieldSpec{t::kFidPersonalData, t::kPersonalNumber, "personal_number", "Personal Number", "personal", kUtf8, kText,
              kEdge},
    FieldSpec{t::kFidPersonalData, t::kSurname, "surname", "Surname", "personal", kUtf8, kText, kEdge},
    FieldSpec{t::kFidPersonalData, t::kGivenName, "given_name", "Given Name", "personal", kUtf8, kText, kEdge},
    FieldSpec{t::kFidPersonalData, t::kParentGivenName, "parent_given_name", "Parent Given Name", "personal", kUtf8,
              kText, kBoth},
    FieldSpec{t::kFidPersonalData, t::kSex, "sex", "Sex", "personal", kUtf8, kText, kEdge},
    FieldSpec{t::kFidPersonalData, t::kPlaceOfBirth, "place_of_birth", "Place of Birth", "personal", kUtf8, kText,
              kEdge},
    FieldSpec{t::kFidPersonalData, t::kCommunityOfBirth, "community_of_birth", "Community of Birth", "personal", kUtf8,
              kText, kBoth},
    FieldSpec{t::kFidPersonalData, t::kStateOfBirth, "state_of_birth", "State of Birth", "personal", kUtf8, kText,
              kBoth},
    FieldSpec{t::kFidPersonalData, t::kStateOfBirthCode, "state_of_birth_code", "State of Birth Code", "personal",
              kUtf8, kText, kEdge},
    FieldSpec{t::kFidPersonalData, t::kDateOfBirth, "date_of_birth", "Date of Birth", "personal", kUtf8, kDate, kEdge},
    FieldSpec{t::kFidPersonalData, t::kNationalityFull, "nationality", "Nationality", "personal", kUtf8, kText, kEdge},
    FieldSpec{t::kFidPersonalData, t::kStatusOfForeigner, "status_of_foreigner", "Status of Foreigner", "personal",
              kUtf8, kText, kEdge},
    FieldSpec{t::kFidPersonalData, t::kPurposeOfStay, "purpose_of_stay", "Purpose of Stay", "personal", kUtf8, kText,
              kEdge},
    FieldSpec{t::kFidPersonalData, t::kNote, "note", "Note", "personal", kUtf8, kText, kEdge},
    // 0F04
    FieldSpec{t::kFidVariableData, t::kState, "state", "State", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kCommunity, "community", "Community", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kPlace, "place", "Place", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kStreet, "street", "Street", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kHouseNumber, "house_number", "House Number", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kHouseLetter, "house_letter", "House Letter", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kEntrance, "entrance", "Entrance", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kFloor, "floor", "Floor", "address", kUtf8, kText, kBoth},
    FieldSpec{t::kFidVariableData, t::kApartmentNumber, "apartment_number", "Apartment Number", "address", kUtf8, kText,
              kEdge},
    FieldSpec{t::kFidVariableData, t::kApartmentNumber, "apartment_number", "Apartment", "address", kUtf8, kText,
              kAnnex},
    FieldSpec{t::kFidVariableData, t::kAddressDate, "address_date", "Address Date", "address", kUtf8, kDate, kBoth},
    FieldSpec{t::kFidVariableData, t::kAddressLabel, "address_label", "Address Label", "address", kUtf8, kText, kAnnex},
};

// Known to be on the card, meaning unconfirmed: 1545/1552/1553/1557 in 0F02,
// 1576/1577 as filler in 0F03 of the dual-interface card.
constexpr std::array<std::uint16_t, 6> kCardEdgeUnnamed{1545, 1552, 1553, 1557, 1576, 1577};

constexpr std::array<std::uint16_t, 9> kCardEdgeFixedSlots{
    t::kFidManifest,  t::kFidDocumentData, t::kFidPersonalData, t::kFidPhoto,      kProtectedSlot,
    t::kFidPublicKey, t::kFidIdHash,       t::kFidCertDigests,  t::kFidIssuerHash,
};
constexpr std::array<std::uint16_t, 1> kCardEdgeVariableSlots{t::kFidVariableData};

constexpr std::array kCardEdgeSods{
    SodSpec{t::kFidSodFixed, SodRole::Fixed, kCardEdgeFixedSlots},
    SodSpec{t::kFidSodVariable, SodRole::Variable, kCardEdgeVariableSlots},
};

// --- EL: same tag numbers, other meanings, and text encoded per field ---

constexpr std::array kElFiles{
    FileSpec{t::kFidElManifest, kHeader},  FileSpec{t::kFidElDocument, kHeader},
    FileSpec{t::kFidElPersonal, kHeader},  FileSpec{t::kFidElService, kHeader},
    FileSpec{t::kFidElSealed, kHeader},    FileSpec{t::kFidElPhoto, kHeader},
    FileSpec{t::kFidElDigest, kHeader},    FileSpec{t::kFidPublicKey, kAllocation},
    FileSpec{t::kFidElSodFixed, kHeader},  FileSpec{t::kFidElSodService, kHeader},
    FileSpec{t::kFidElSodSealed, kHeader},
};

constexpr std::array kElGroups{
    GroupSpec{"personal", "Personal Data"},
    GroupSpec{"service", "Service"},
    GroupSpec{"document", "Document Data"},
};

constexpr std::array kElFields{
    // 0D01
    FieldSpec{t::kFidElDocument, t::el::kDocRegNo, "doc_reg_no", "Registration Number", "document", kUtf8, kText,
              kEdge},
    FieldSpec{t::kFidElDocument, t::el::kIssuingDate, "issuing_date", "Issuing Date", "document", kUtf8, kDate, kEdge},
    FieldSpec{t::kFidElDocument, t::el::kIssuingAuthority, "issuing_authority", "Issuing Authority", "document", kUtf16,
              kText, kEdge},
    // 0D02
    FieldSpec{t::kFidElPersonal, t::el::kPersonalNumber, "personal_number", "Personal Number", "personal", kUtf8, kText,
              kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kSurname, "surname", "Surname", "personal", kUtf16, kText, kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kGivenName, "given_name", "Given Name", "personal", kUtf16, kText, kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kSex, "sex", "Sex", "personal", kUtf8, kText, kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kDateOfBirth, "date_of_birth", "Date of Birth", "personal", kUtf8, kDate,
              kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kBloodGroup, "blood_group", "Blood Group", "personal", kUtf8, kText, kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kStatus, "status", "Status", "service", kUtf16, kText, kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kBadgeNumber, "badge_number", "Badge Number", "service", kUtf8, kText, kEdge},
    FieldSpec{t::kFidElPersonal, t::el::kRank, "rank", "Rank", "service", kUtf16, kText, kEdge},
    // 0D03
    FieldSpec{t::kFidElService, t::el::kOrganisationalUnit, "organisational_unit", "Organisational Unit", "service",
              kUtf16, kText, kEdge},
    FieldSpec{t::kFidElService, t::el::kPosition, "position", "Position", "service", kUtf16, kText, kEdge},
    FieldSpec{t::kFidElService, t::el::kServiceAddress, "service_address", "Service Address", "service", kUtf16, kText,
              kEdge},
};

// Printed on the back, meaning unconfirmed: 0D01 tag 1557.
constexpr std::array<std::uint16_t, 1> kElUnnamed{1557};

constexpr std::array<std::uint16_t, 7> kElFixedSlots{
    t::kFidElManifest, t::kFidElDocument, t::kFidElPersonal, t::kFidElPhoto,
    kProtectedSlot,    t::kFidPublicKey,  t::kFidElDigest,
};
constexpr std::array<std::uint16_t, 1> kElServiceSlots{t::kFidElService};
constexpr std::array<std::uint16_t, 1> kElSealedSlots{t::kFidElSealed};

constexpr std::array kElSods{
    SodSpec{t::kFidElSodFixed, SodRole::Fixed, kElFixedSlots},
    SodSpec{t::kFidElSodService, SodRole::Variable, kElServiceSlots},
    SodSpec{t::kFidElSodSealed, SodRole::Variable, kElSealedSlots},
};

constexpr DocumentProfile cardEdgeProfile(std::string_view code, std::span<const std::uint8_t> aid)
{
    return DocumentProfile{
        code,          aid,          kCardEdgeFiles, kCardEdgeGroups, kCardEdgeFields, kCardEdgeUnnamed,
        kCardEdgeSods, t::kFidPhoto, t::kFidSodFixed};
}

constexpr std::array kProfiles{
    cardEdgeProfile("ID", kAidId),
    cardEdgeProfile("IF", kAidIf),
    cardEdgeProfile("RP", kAidRp),
    DocumentProfile{"EL", kAidEl, kElFiles, kElGroups, kElFields, kElUnnamed, kElSods, t::kFidElPhoto,
                    t::kFidElSodFixed},
};

} // namespace

std::span<const DocumentProfile> documentProfiles()
{
    return kProfiles;
}

const DocumentProfile* profileForAid(std::span<const std::uint8_t> aid) noexcept
{
    for (const auto& p : kProfiles) {
        if (std::equal(p.aid.begin(), p.aid.end(), aid.begin(), aid.end())) {
            return &p;
        }
    }
    return nullptr;
}

const DocumentProfile& annexProfile() noexcept
{
    return kProfiles[0];
}

} // namespace LibreSCRS::RsEId::Core

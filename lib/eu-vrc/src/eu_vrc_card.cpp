// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "eu_vrc_card.h"
#include "eu_vrc_detection.h"
#include "eu_vrc_protocol.h"

#include <apdu.h>
#include <ber.h>
#include <date_format.h>
#include <pcsc_connection.h>
#include <smartcard/chunked_read.h>

#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <optional>
#include <span>
#include <stdexcept>

namespace euvrc {

std::string formatVrcDate(const std::string& raw)
{
    return LibreSCRS::SmartCard::Internal::formatDateYMD(raw);
}

bool EuVrcCard::probe(LibreSCRS::SmartCard::Internal::PCSCConnection& conn)
{
    try {
        return euvrc::probe(conn);
    } catch (...) {
        return false;
    }
}

EuVrcCard::EuVrcCard(LibreSCRS::SmartCard::Internal::PCSCConnection& externalConn) : conn(&externalConn)
{
    if (!detect(*conn)) {
        throw std::runtime_error("EU VRC card initialization failed");
    }
}

EuVrcCard::~EuVrcCard() = default;

namespace detail {

// Decide, from the first bytes of a file and whatever the FCI said about its
// size, where the body starts and how many bytes still have to be read.
//
// Lifted out of the lambda it used to be so that a test and a fuzz harness can
// reach it; the behaviour is unchanged, including the catch-all, which is the
// walker's documented rejection path.
//
// The two branches decode two different things, and that distinction is the
// point. When the FCI carried a size, that size IS the answer. When it did not,
// the BER length at the data offset is read as a DECLARATION of how many bytes
// the card still has to hand over -- a value that legitimately exceeds the
// header buffer in hand, because the rest has not been read yet. Every other
// caller of the same length decoder is asking the opposite question, whether a
// length fits bytes that have already arrived.
std::optional<LibreSCRS::SmartCard::Internal::HeaderParseResult> deriveEuVrcHeader(std::span<const std::uint8_t> hdr,
                                                                                   std::size_t fciFileSize)
{
    if (hdr.size() < 2) {
        return std::nullopt;
    }

    // Try BER parse from byte 0 to decide if the file starts with TLV.
    bool parsedFromZero = false;
    try {
        auto testParse = LibreSCRS::SmartCard::Internal::parseBER(hdr.data(), hdr.size());
        if (!testParse.children.empty()) {
            parsedFromZero = true;
        }
    } catch (...) {
    }

    size_t dataOffset = 0;
    if (!parsedFromZero) {
        // Header-skip fallback for NXP eVL cards
        dataOffset = static_cast<size_t>(hdr[1]) + 2;
        if (dataOffset >= hdr.size()) {
            return std::nullopt;
        }
    }

    size_t totalToRead = 0;
    if (fciFileSize > 0 && fciFileSize > dataOffset) {
        // FCI-reported file size is the most reliable signal
        totalToRead = fciFileSize - dataOffset;
    } else {
        // Otherwise reuse the shared BER tag+length parser to derive
        // body length from the header bytes starting at dataOffset.
        try {
            size_t parseOffset = dataOffset;
            const size_t tagStart = parseOffset;
            LibreSCRS::SmartCard::Internal::parseTag(hdr.data(), hdr.size(), parseOffset);
            const size_t tagLen = parseOffset - tagStart;
            const size_t lenStart = parseOffset;
            const size_t dataLength = LibreSCRS::SmartCard::Internal::parseLength(hdr.data(), hdr.size(), parseOffset);
            const size_t lenBytes = parseOffset - lenStart;
            totalToRead = tagLen + lenBytes + dataLength;
        } catch (...) {
            return std::nullopt;
        }
    }

    return LibreSCRS::SmartCard::Internal::HeaderParseResult{dataOffset, totalToRead};
}

} // namespace detail

std::vector<uint8_t> EuVrcCard::readFile(uint8_t fidHi, uint8_t fidLo)
{
    // SELECT file: P1=02 P2=04 no Le
    LibreSCRS::SmartCard::Internal::APDUCommand selectCmd{
        .cla = 0x00, .ins = 0xA4, .p1 = 0x02, .p2 = 0x04, .data = {fidHi, fidLo}, .le = 0, .hasLe = false};
    auto selectResp = conn->transmit(selectCmd);
    if (!selectResp.isSuccess()) {
        return {}; // File not present
    }

    // Extract file size from FCI response (tag 81 = file size in SELECT response)
    // FCI format: 62 <len> 81 02 <sizeHi> <sizeLo> ...
    size_t fciFileSize = 0;
    if (selectResp.data.size() >= 4) {
        try {
            auto fci = LibreSCRS::SmartCard::Internal::parseBER(selectResp.data.data(), selectResp.data.size());
            for (const auto& child : fci.children) {
                if (child.tag == 0x62) {
                    for (const auto& field : child.children) {
                        if (field.tag == 0x81 && field.value.size() >= 2) {
                            fciFileSize = (static_cast<size_t>(field.value[0]) << 8) | field.value[1];
                        }
                    }
                }
                // Some cards return 81 directly (not wrapped in 62)
                if (child.tag == 0x81 && child.value.size() >= 2) {
                    fciFileSize = (static_cast<size_t>(child.value[0]) << 8) | child.value[1];
                }
            }
        } catch (...) {
        }
    }

    // Custom header parser: try BER from byte 0, fall back to NXP eVL
    // header-skip (offset = hdr[1] + 2); body length comes from FCI when
    // available, otherwise from a BER tag+length walk at the data offset.
    LibreSCRS::SmartCard::Internal::ChunkedReadOptions opts;
    opts.headerSpec.headerSize = protocol::FILE_HEADER_SIZE;
    opts.chunkSize = protocol::READ_CHUNK_LARGE;
    opts.fallbackChunkSize = protocol::READ_CHUNK_SMALL;
    opts.errorPrefix = "EU VRC";
    opts.parseHeader = [fciFileSize](std::span<const uint8_t> hdr) {
        return detail::deriveEuVrcHeader(hdr, fciFileSize);
    };

    return LibreSCRS::SmartCard::Internal::readChunkedFile(*conn, opts);
}

EuVrcData EuVrcCard::readCard()
{
    // Read all data files and merge BER trees
    LibreSCRS::SmartCard::Internal::BERField merged;
    merged.tag = 0;
    merged.constructed = true;

    auto standardFids = getStandardFileFids();
    auto nationalFids = getNationalExtensionFids();

    // Collect binary file data separately
    std::vector<uint8_t> sigA, sigB, crtA, crtB;
    std::vector<std::pair<uint16_t, std::vector<uint8_t>>> addSigs, addCerts;

    auto parseBerFile = [&](const std::vector<uint8_t>& raw) {
        try {
            auto parsed = LibreSCRS::SmartCard::Internal::parseBER(raw.data(), raw.size());
            LibreSCRS::SmartCard::Internal::mergeBER(merged, parsed);
        } catch (...) {
            // If BER parse fails from byte 0, try header-skip
            if (raw.size() > 2) {
                size_t skipOffset = static_cast<size_t>(raw[1]) + 2;
                if (skipOffset < raw.size()) {
                    try {
                        auto parsed =
                            LibreSCRS::SmartCard::Internal::parseBER(raw.data() + skipOffset, raw.size() - skipOffset);
                        LibreSCRS::SmartCard::Internal::mergeBER(merged, parsed);
                    } catch (...) {
                    }
                }
            }
        }
    };

    // Read standard files
    for (const auto& fid : standardFids) {
        auto raw = readFile(fid.fidHi, fid.fidLo);
        if (raw.empty())
            continue;

        uint16_t fidWord = (static_cast<uint16_t>(fid.fidHi) << 8) | fid.fidLo;

        if (fid.isBerTlv) {
            parseBerFile(raw);
        } else {
            if (fidWord == 0xE001)
                sigA = std::move(raw);
            else if (fidWord == 0xE011)
                sigB = std::move(raw);
            else if (fidWord == 0xC001)
                crtA = std::move(raw);
            else if (fidWord == 0xC011)
                crtB = std::move(raw);
        }
    }

    // Probe national extension files
    for (const auto& fid : nationalFids) {
        auto raw = readFile(fid.fidHi, fid.fidLo);
        if (raw.empty())
            continue;

        uint16_t fidWord = (static_cast<uint16_t>(fid.fidHi) << 8) | fid.fidLo;

        if (fid.isBerTlv) {
            parseBerFile(raw);
        } else {
            if (fid.fidHi == 0xE0)
                addSigs.push_back({fidWord, std::move(raw)});
            else if (fid.fidHi == 0xC0)
                addCerts.push_back({fidWord, std::move(raw)});
        }
    }

    // Extract fields from merged BER tree
    EuVrcData result = extractFields(merged);

    // Attach binary data
    result.signatureA = std::move(sigA);
    result.signatureB = std::move(sigB);
    result.certA = std::move(crtA);
    result.certB = std::move(crtB);
    result.additionalSignatures = std::move(addSigs);
    result.additionalCerts = std::move(addCerts);

    return result;
}

namespace {

// Recursively collect national extension tags from all levels of a container
void collectNationalTags(const LibreSCRS::SmartCard::Internal::BERField& container, EuVrcData& data)
{
    for (const auto& child : container.children) {
        if (protocol::isNationalExtensionTag(child.tag) && !child.value.empty()) {
            data.nationalTags.push_back({child.tag, child.asString()});
        }
        // Recurse into constructed (container) children
        if (child.constructed && !child.children.empty()) {
            collectNationalTags(child, data);
        }
    }
}

} // anonymous namespace

EuVrcData extractFields(const LibreSCRS::SmartCard::Internal::BERField& root)
{
    using namespace protocol;
    const auto field = [&root](std::initializer_list<uint32_t> path) {
        return LibreSCRS::SmartCard::Internal::berFindString(root, path);
    };
    EuVrcData data;

    // Metadata
    data.version = field({TAG_MANDATORY_CONTAINER, TAG_VERSION});
    data.memberState = field({TAG_MANDATORY_CONTAINER, TAG_MEMBER_STATE});
    data.competentAuthority = field({TAG_MANDATORY_CONTAINER, TAG_COMPETENT_AUTH});
    data.issuingAuthority = field({TAG_MANDATORY_CONTAINER, TAG_ISSUING_AUTH});
    data.documentNumber = field({TAG_MANDATORY_CONTAINER, TAG_DOC_NUMBER});
    data.previousDocument = field({TAG_MANDATORY_CONTAINER, TAG_PREVIOUS_DOC});

    // EU mandatory (tag 71)
    data.registrationNumber = field({TAG_MANDATORY_CONTAINER, TAG_REG_NUMBER});
    data.firstRegistration = formatVrcDate(field({TAG_MANDATORY_CONTAINER, TAG_FIRST_REG}));
    data.holderName = field({TAG_MANDATORY_CONTAINER, TAG_PERSONAL_DATA, TAG_REG_HOLDER, TAG_NAME});
    data.holderOtherNames = field({TAG_MANDATORY_CONTAINER, TAG_PERSONAL_DATA, TAG_REG_HOLDER, TAG_OTHER_NAMES});
    data.holderAddress = field({TAG_MANDATORY_CONTAINER, TAG_PERSONAL_DATA, TAG_REG_HOLDER, TAG_ADDRESS});
    data.ownershipStatus = field({TAG_MANDATORY_CONTAINER, TAG_OWNERSHIP_STATUS});
    data.vehicleMake = field({TAG_MANDATORY_CONTAINER, TAG_VEHICLE_DATA, TAG_VEHICLE_MAKE});
    data.vehicleType = field({TAG_MANDATORY_CONTAINER, TAG_VEHICLE_DATA, TAG_VEHICLE_TYPE});
    data.commercialDesc = field({TAG_MANDATORY_CONTAINER, TAG_VEHICLE_DATA, TAG_COMMERCIAL_DESC});
    data.vin = field({TAG_MANDATORY_CONTAINER, TAG_VIN});
    data.maxLadenMass = field({TAG_MANDATORY_CONTAINER, TAG_MASS_DATA, TAG_MAX_LADEN_MASS});
    data.vehicleMass = field({TAG_MANDATORY_CONTAINER, TAG_VEHICLE_MASS});
    data.expiryDate = formatVrcDate(field({TAG_MANDATORY_CONTAINER, TAG_EXPIRY}));
    data.registrationDate = formatVrcDate(field({TAG_MANDATORY_CONTAINER, TAG_REG_DATE}));
    data.typeApproval = field({TAG_MANDATORY_CONTAINER, TAG_TYPE_APPROVAL});
    data.engineCapacity = field({TAG_MANDATORY_CONTAINER, TAG_ENGINE_DATA, TAG_ENGINE_CAPACITY});
    data.maxNetPower = field({TAG_MANDATORY_CONTAINER, TAG_ENGINE_DATA, TAG_MAX_NET_POWER});
    data.fuelType = field({TAG_MANDATORY_CONTAINER, TAG_ENGINE_DATA, TAG_FUEL_TYPE});
    data.powerWeightRatio = field({TAG_MANDATORY_CONTAINER, TAG_POWER_WEIGHT});
    data.numberOfSeats = field({TAG_MANDATORY_CONTAINER, TAG_SEATING_DATA, TAG_NUM_SEATS});
    data.standingPlaces = field({TAG_MANDATORY_CONTAINER, TAG_SEATING_DATA, TAG_STANDING_PLACES});

    // EU optional (tag 72)
    data.maxLadenMassService = field({TAG_OPTIONAL_CONTAINER, TAG_MASS_DATA, TAG_MAX_LADEN_SERVICE});
    data.maxLadenMassWhole = field({TAG_OPTIONAL_CONTAINER, TAG_MASS_DATA, TAG_MAX_LADEN_WHOLE});
    data.vehicleCategory = field({TAG_OPTIONAL_CONTAINER, TAG_VEHICLE_CATEGORY});
    data.numberOfAxles = field({TAG_OPTIONAL_CONTAINER, TAG_NUM_AXLES});
    data.wheelbase = field({TAG_OPTIONAL_CONTAINER, TAG_WHEELBASE});
    data.brakedTrailerMass = field({TAG_OPTIONAL_CONTAINER, TAG_BRAKED_TRAILER});
    data.unbrakedTrailerMass = field({TAG_OPTIONAL_CONTAINER, TAG_UNBRAKED_TRAILER});
    data.ratedEngineSpeed = field({TAG_OPTIONAL_CONTAINER, TAG_ENGINE_DATA, TAG_RATED_ENGINE_SPEED});
    data.engineIdNumber = field({TAG_OPTIONAL_CONTAINER, TAG_ENGINE_DATA, TAG_ENGINE_ID});
    data.colour = field({TAG_OPTIONAL_CONTAINER, TAG_COLOUR});
    data.maxSpeed = field({TAG_OPTIONAL_CONTAINER, TAG_MAX_SPEED});
    data.stationarySoundLevel = field({TAG_OPTIONAL_CONTAINER, TAG_STATIONARY_SOUND});
    data.engineSpeedRef = field({TAG_OPTIONAL_CONTAINER, TAG_ENGINE_SPEED_REF});
    data.driveBySound = field({TAG_OPTIONAL_CONTAINER, TAG_DRIVEBY_SOUND});
    data.fuelConsumption = field({TAG_OPTIONAL_CONTAINER, TAG_FUEL_CONSUMPTION});
    data.co2 = field({TAG_OPTIONAL_CONTAINER, TAG_CO2});
    data.envCategory = field({TAG_OPTIONAL_CONTAINER, TAG_ENV_CATEGORY});
    data.fuelTankCapacity = field({TAG_OPTIONAL_CONTAINER, TAG_FUEL_TANK_CAPACITY});

    // Owner2 (C.2)
    data.owner2Name = field({TAG_MANDATORY_CONTAINER, TAG_PERSONAL_DATA, TAG_VEHICLE_OWNER, TAG_NAME});

    // User (C.3) — try 71 first, fallback to 72
    for (const auto container : {TAG_MANDATORY_CONTAINER, TAG_OPTIONAL_CONTAINER}) {
        data.userName = field({container, TAG_PERSONAL_DATA, TAG_USER, TAG_NAME});
        data.userOtherNames = field({container, TAG_PERSONAL_DATA, TAG_USER, TAG_OTHER_NAMES});
        data.userAddress = field({container, TAG_PERSONAL_DATA, TAG_USER, TAG_ADDRESS});
        if (!data.userName.empty() || !data.userOtherNames.empty() || !data.userAddress.empty())
            break;
    }

    // National extensions — tags >= 0xC0, search recursively in both 71 and 72 containers
    for (const auto& child : root.children) {
        if (child.tag == TAG_MANDATORY_CONTAINER || child.tag == TAG_OPTIONAL_CONTAINER) {
            collectNationalTags(child, data);
        }
    }

    return data;
}

} // namespace euvrc

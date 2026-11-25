// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace LibreSCRS::RsEId::Core {

/// @brief How one field's bytes encode text. Measured per field: no rule
///        independent of the field tells UTF-8 "М" (D0 9C) from a UTF-16LE
///        character, or ASCII "A-" (41 2D) from U+2D41.
enum class TextEncoding : std::uint8_t { Utf8, Utf16Le };

/// @brief How a value is shown. Date: the CardEdge surface inserts dots into
///        DDMMYYYY, the annex surface passes the digits through as it always has.
enum class FieldFormat : std::uint8_t { Text, Date };

/// @brief Where a field row is shown. Bit flags, combined in @ref FieldSpec::surfaces.
enum class Surface : std::uint8_t { CardEdge = 1, Annex = 2 };

/// @brief How a file is read and, when a signed object covers it, hashed.
enum class ReadMode : std::uint8_t {
    Header,     ///< container header plus its declared length
    Allocation, ///< the whole allocation, padding included
};

/// @brief Which of the verdicts a signed object feeds.
enum class SodRole : std::uint8_t { Fixed, Variable };

/// @brief Place of a slot in @ref SodSpec::slots that no file readable without
///        authentication corresponds to. It is counted, never checked.
inline constexpr std::uint16_t kProtectedSlot = 0xFFFF;

struct FileSpec
{
    std::uint16_t fid;
    ReadMode mode;
};

struct GroupSpec
{
    std::string_view key;
    std::string_view label;
};

/// @brief One shown field. The same tag may have a row per surface, each with
///        its own key and label, because the surfaces never agreed on them.
struct FieldSpec
{
    std::uint16_t fid;
    std::uint16_t tag;
    std::string_view key;
    std::string_view label;
    std::string_view group;
    TextEncoding encoding;
    FieldFormat format;
    std::uint8_t surfaces; ///< @ref Surface bits
};

/// @brief One signed object and the files it covers, in the order it covers them.
struct SodSpec
{
    std::uint16_t fid;
    SodRole role;
    std::span<const std::uint16_t> slots;
};

/// @brief Everything the readers know about one document type, as data.
struct DocumentProfile
{
    std::string_view code; ///< ID, IF, RP, EL
    std::span<const std::uint8_t> aid;
    std::span<const FileSpec> files;
    std::span<const GroupSpec> groups; ///< emission order
    std::span<const FieldSpec> fields;
    /// Tags that are known to exist but have no confirmed meaning; never shown.
    std::span<const std::uint16_t> unnamedTags;
    std::span<const SodSpec> sods;
    std::uint16_t photoFid;
    std::uint16_t cardCertSodFid;
};

struct ProfileField
{
    std::string key;
    std::string label;
    std::string value;
};

struct ProfileGroup
{
    std::string key;
    std::string label;
    std::vector<ProfileField> fields;
};

/// @brief Files as they stand on the card, container header and padding included.
using RawFiles = std::map<std::uint16_t, std::vector<std::uint8_t>>;

/// @brief ID, IF, RP, EL.
[[nodiscard]] std::span<const DocumentProfile> documentProfiles();

/// @return The profile whose application id is @p aid, or null.
[[nodiscard]] const DocumentProfile* profileForAid(std::span<const std::uint8_t> aid) noexcept;

/// @brief The profile whose annex rows the current generation shows.
[[nodiscard]] const DocumentProfile& annexProfile() noexcept;

/// @brief Files @p groupKey draws its fields from, ascending, for @p surface.
[[nodiscard]] std::vector<std::uint16_t> groupFiles(const DocumentProfile& profile, std::string_view groupKey,
                                                    Surface surface);

/// @brief One group from the files read so far.
///
/// Fields come in file-id order, then in the order the profile lists them. A
/// field is left out when its tag is absent, its value empty, or its row is not
/// for @p surface; a duplicated tag yields its first occurrence. A group with no
/// field left, or one the profile does not list, yields nothing: an absent tag
/// must never make a read fail.
[[nodiscard]] std::optional<ProfileGroup> buildGroup(const DocumentProfile& profile, std::string_view groupKey,
                                                     const RawFiles& files, Surface surface);

/// @brief Every non-empty group, in the profile's order.
[[nodiscard]] std::vector<ProfileGroup> buildGroups(const DocumentProfile& profile, const RawFiles& files,
                                                    Surface surface);

/// @brief The picture in a photo file: the 8 bytes of container and inner header
///        removed. Empty unless what follows is a JPEG, so a host never feeds
///        arbitrary card bytes to an image decoder.
[[nodiscard]] std::vector<std::uint8_t> extractPhoto(std::span<const std::uint8_t> photoFile);

/// @brief The bytes of @p file a signed object's digest was taken over.
///
/// Empty when a Header file has no complete header: that is no block at all,
/// and an empty block never matches.
[[nodiscard]] std::vector<std::uint8_t> sodBlock(const FileSpec& spec, std::span<const std::uint8_t> file);

/// @brief Distinct slot counts of every signed object of every profile, ascending.
///
/// Computed from the profiles; a count outside this set is a layout nobody has measured.
[[nodiscard]] std::vector<std::size_t> measuredSlotCounts();

} // namespace LibreSCRS::RsEId::Core

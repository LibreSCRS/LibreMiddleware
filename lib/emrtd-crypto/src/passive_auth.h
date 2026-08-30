// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace emrtd::crypto {

struct PAResult
{
    enum Status { PASSED, FAILED, NOT_PERFORMED };
    Status sodSignature = NOT_PERFORMED;
    Status cscaChain = NOT_PERFORMED;
    std::map<int, Status> dgHashes;
    std::string hashAlgorithm;
    /// The document signer, as named by the SIGNATURE rather than by the
    /// unauthenticated certificate bag the object travels with. Both are empty
    /// when that signature does not verify, since there is then no signer to
    /// describe -- and a name taken from the bag would be the attacker's, not
    /// the signing authority's.
    std::string dscSubject;
    std::string dscExpiry;
    std::string errorDetail;
};

struct SODContent
{
    std::string hashAlgorithm;
    std::map<int, std::vector<uint8_t>> dgHashes;
    std::string ldsVersion;
    std::string unicodeVersion;
};

std::optional<SODContent> parseSOD(const std::vector<uint8_t>& sodRaw);
PAResult::Status verifyDGHash(const std::vector<uint8_t>& dgRaw, const std::vector<uint8_t>& expectedHash,
                              const std::string& hashAlgorithm);
PAResult::Status verifySODSignature(const std::vector<uint8_t>& sodRaw);

/// @brief Judges a security object's signer against a trust store on disk.
///
/// @note Its successor is `evaluateCscaChain()` in `csca_master_list.h`, which
///       answers the same question over anchors the caller has already read,
///       separates "we hold no anchor for this issuer" from "this does not
///       chain to what we hold", and pins the verification defaults ICAO
///       documents need. Anything learned about one of these two belongs in
///       both until this one is retired.
///
///       Two things this one does that the successor does not, both reasons to
///       prefer it: it reads its anchors with `X509_STORE_load_path`, which
///       needs a `c_rehash`ed directory and answers 1 for a path that does not
///       exist -- it only records the string -- so a mistyped store is
///       indistinguishable here from an empty one; and it returns a single
///       status, so "no anchors configured", "no anchor for this issuer" and
///       "does not chain to what we hold" arrive as one answer. The last of
///       those is an accusation and the first two are not.
PAResult::Status verifyCSCAChain(const std::vector<uint8_t>& sodRaw, const std::string& trustStorePath);
PAResult performPassiveAuth(const std::vector<uint8_t>& sodRaw, const std::map<int, std::vector<uint8_t>>& dgRawData,
                            const std::string& trustStorePath = "");

} // namespace emrtd::crypto

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
    /// Why @ref cscaChain came out as it did, as a key to be translated where
    /// it is shown and never as a sentence: `"csca.not-configured"`,
    /// `"csca.anchors-unreadable"`, `"csca.anchors-undecodable"`,
    /// `"csca.no-anchor-for-issuer"` or `"csca.chain-failed"`.
    ///
    /// Empty exactly when @ref cscaChain is `PASSED` -- the one outcome with
    /// nothing to explain. Three of the five share the `NOT_PERFORMED` status,
    /// and telling those three apart is what this exists for.
    std::string cscaChainReason;
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

/// @brief Judges a security object's signer against a directory of trust
///        anchors.
///
/// A directory read by `loadAnchorDerFromDirectory()`, a verdict reached by
/// `evaluateCscaChain()`, both declared in `csca_master_list.h`. This function
/// is the seam between them and the live passive-authentication path; the
/// judgement itself is documented there and not repeated here.
///
/// @param trustStorePath a directory of certificate files, in any file naming
///        and with no `c_rehash` run needed. Empty means no anchor source was
///        configured, which is answered `NOT_PERFORMED` without the document
///        being read at all.
/// @return the status a badge is painted from, paired with the key that says
///         which of the six situations produced it. `PASSED` only when every
///         signer of @p sodRaw chains to an anchor held. `FAILED` only when a
///         chain was attempted against anchors and did not hold -- it is the
///         accusation, and no statement about the caller's own configuration
///         may ever be reported as one.
/// @brief What a CSCA chain check came to, and why.
///
/// Two members rather than one because the situations that call for different
/// things to be done about them do not map onto the statuses. `NOT_PERFORMED`
/// is reached three ways -- no anchor source configured, a source that yielded
/// no usable anchor, and anchors that name a different authority than this
/// document's signer does -- and a person is owed a different sentence for
/// each.
struct CscaChainOutcome
{
    PAResult::Status status = PAResult::NOT_PERFORMED;
    /// A key to be translated where it is shown, never a sentence: an English
    /// literal chosen here is a literal every host has to show in English.
    /// Empty exactly when @ref status is `PASSED`. See PAResult::cscaChainReason
    /// for the keys.
    std::string reasonKey;
};

CscaChainOutcome verifyCSCAChain(const std::vector<uint8_t>& sodRaw, const std::string& trustStorePath);
PAResult performPassiveAuth(const std::vector<uint8_t>& sodRaw, const std::map<int, std::vector<uint8_t>>& dgRawData,
                            const std::string& trustStorePath = "");

} // namespace emrtd::crypto

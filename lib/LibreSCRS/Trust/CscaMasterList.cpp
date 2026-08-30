// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Trust/CscaMasterList.h>

#include "emrtd-crypto/src/csca_master_list.h"

#include <algorithm>
#include <cstdint>
#include <optional>
#include <type_traits>
#include <utility>
#include <vector>

// The two switches below are the cardinality half of the enum gate, and this
// pragma is what turns them from a warning into a gate. -Wswitch is only a
// warning in a default build and LIBREMIDDLEWARE_WERROR is off by default, so
// without this a value added to either enum would compile with a diagnostic
// nobody has to read. Promoted to an error in this translation unit alone, so
// the gate does not depend on how the tree was configured.
#if defined(__GNUC__) || defined(__clang__)
#pragma GCC diagnostic error "-Wswitch"
#endif

namespace LibreSCRS::Trust {
namespace {

using Internal = emrtd::crypto::MasterListError;

// ---------------------------------------------------------------------------
// The gate between the public error enum and the internal one it mirrors
// ---------------------------------------------------------------------------
//
// LibreSCRS::Trust::MasterListError exists because the public header may not
// name an internal type, so it is a copy -- and a copy without a gate is the
// defect where one side grows a value, the other does not, and a caller is
// handed the wrong refusal for a year. Three mechanisms hold it, and they fail
// in different directions on purpose:
//
//   1. toPublic() is a switch over the INTERNAL enum with no `default:`. A
//      value added internally has no case here, and -Wswitch -- an error in
//      this file, see above -- stops the build.
//   2. toInternal() is the same switch pointed the other way, so a value added
//      to the PUBLIC enum, which no switch over the internal one could see,
//      stops the build too.
//   3. The static_asserts below bind each pair by NUMERIC value in both
//      directions. Those catch what a switch cannot: a reordering, where every
//      case still exists and every name still maps, but the wire value of a
//      refusal has silently changed under a consumer that stored one.
//
// The numeric identity in (3) is not something the mapping needs -- the
// switches map by name and would be correct without it. It is pinned so that
// the two enums cannot drift apart quietly, and so that anyone who deliberately
// reorders one has to come here and say so.

/// The internal refusal as the public one. See the gate note above.
constexpr MasterListError toPublic(Internal internalError)
{
    switch (internalError) {
    case Internal::NotAMasterList:
        return MasterListError::NotAMasterList;
    case Internal::Empty:
        return MasterListError::Empty;
    case Internal::Malformed:
        return MasterListError::Malformed;
    case Internal::BadSignature:
        return MasterListError::BadSignature;
    case Internal::SignerMismatch:
        return MasterListError::SignerMismatch;
    }
    // No `default:` above, deliberately: it would swallow exactly the addition
    // this function exists to refuse. Unreachable for every value the enum has,
    // so getting here at run time is undefined -- and in a constant expression
    // it is a compile error, which is what the round-trip asserts below rest on.
    std::unreachable();
}

/// The public refusal as the internal one. Exists only for the gate: nothing
/// converts in this direction at run time, and the compiler needs the switch in
/// order to notice a value added on the public side.
constexpr Internal toInternal(MasterListError publicError)
{
    switch (publicError) {
    case MasterListError::NotAMasterList:
        return Internal::NotAMasterList;
    case MasterListError::Empty:
        return Internal::Empty;
    case MasterListError::Malformed:
        return Internal::Malformed;
    case MasterListError::BadSignature:
        return Internal::BadSignature;
    case MasterListError::SignerMismatch:
        return Internal::SignerMismatch;
    }
    std::unreachable();
}

/// Both switches, over one pair, plus the numeric identity between them.
constexpr bool mirrors(MasterListError publicError, Internal internalError)
{
    return toPublic(internalError) == publicError && toInternal(publicError) == internalError &&
           static_cast<int>(publicError) == static_cast<int>(internalError);
}

static_assert(mirrors(MasterListError::NotAMasterList, Internal::NotAMasterList),
              "the public MasterListError mirror drifted from emrtd::crypto::MasterListError");
static_assert(mirrors(MasterListError::Empty, Internal::Empty),
              "the public MasterListError mirror drifted from emrtd::crypto::MasterListError");
static_assert(mirrors(MasterListError::Malformed, Internal::Malformed),
              "the public MasterListError mirror drifted from emrtd::crypto::MasterListError");
static_assert(mirrors(MasterListError::BadSignature, Internal::BadSignature),
              "the public MasterListError mirror drifted from emrtd::crypto::MasterListError");
static_assert(mirrors(MasterListError::SignerMismatch, Internal::SignerMismatch),
              "the public MasterListError mirror drifted from emrtd::crypto::MasterListError");

// ---------------------------------------------------------------------------
// The gate between the public result structure and the internal one it mirrors
// ---------------------------------------------------------------------------
//
// The enum is not the only thing copied across this boundary. The public header
// may not name an internal type, so what a caller receives is a hand-written
// mirror of the internal structure -- and a mirror without a gate is the defect
// where one side grows a field, the other does not, and the field quietly stops
// being carried. Neither switch above can see that: a structure has no cases to
// be exhaustive over.
//
// A structured binding does see it. A binding list has to name EVERY member of
// its type, no more and no fewer, so a field added on either side stops this
// function compiling and whoever added it has to come here and say where it
// goes. The static_asserts under it pin what the counts alone would not: each
// binding against the type parseAndVerifyMasterList() below actually reads or
// writes, so a field whose type drifts on one side is caught as well.
//
// What it does NOT catch, said here rather than left to be found out: two
// fields of the SAME type exchanged for one another. Both sides would still
// typecheck, and only the tests over the mapping stand in the way of that.
//
// Nothing calls this. It is a compile-time statement, and it costs nothing at
// run time.
[[maybe_unused]] void verifiedMasterListMirrors(const emrtd::crypto::VerifiedMasterList& internalSide,
                                                const VerifiedMasterList& publicSide)
{
    [[maybe_unused]] const auto& [internalAnchors, internalFingerprint, internalChecked, internalSignerCert,
                                  internalSigningTime] = internalSide;
    [[maybe_unused]] const auto& [publicAnchors, publicFingerprint, publicChecked, publicSignerCert,
                                  publicSigningTime] = publicSide;

    // The one pair whose two types differ by design: the internal side carries
    // the whole parse result, the public side the anchors taken out of it.
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(internalAnchors)>, emrtd::crypto::MasterList>,
                  "the internal VerifiedMasterList no longer opens with the parsed list");
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(publicAnchors)>, std::vector<std::vector<std::uint8_t>>>,
                  "the public VerifiedMasterList no longer opens with the anchors");

    // A fingerprint is a fixed 32 bytes on the way out and a vector on the way
    // in, which is why parseAndVerifyMasterList() checks the length before it
    // copies. Both halves of that are pinned here.
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(internalFingerprint)>, std::vector<std::uint8_t>>,
                  "the internal signer fingerprint changed shape");
    static_assert(
        std::is_same_v<std::remove_cvref_t<decltype(publicFingerprint)>, std::array<std::uint8_t, kSpkiSha256Size>>,
        "the public signer fingerprint changed shape");

    static_assert(std::is_same_v<std::remove_cvref_t<decltype(internalChecked)>, bool>);
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(publicChecked)>, bool>);

    // These two are carried across unchanged, so here the two types must be the
    // SAME type and not merely each what it was.
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(internalSignerCert)>,
                                 std::remove_cvref_t<decltype(publicSignerCert)>>,
                  "the signer certificate is carried across unchanged and its two spellings drifted");
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(internalSigningTime)>,
                                 std::remove_cvref_t<decltype(publicSigningTime)>>,
                  "the signing time is carried across unchanged and its two spellings drifted");
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(publicSignerCert)>, std::vector<std::uint8_t>>);
    static_assert(std::is_same_v<std::remove_cvref_t<decltype(publicSigningTime)>, std::optional<std::int64_t>>);
}

} // namespace

std::expected<VerifiedMasterList, MasterListError>
parseAndVerifyMasterList(const std::vector<std::uint8_t>& der,
                         const std::array<std::uint8_t, kSpkiSha256Size>* expectedSpkiSha256)
{
    // A null pointer becomes the empty vector the internal call reads as "do
    // not compare", which is the whole of the translation between the two
    // spellings of "no pin". A caller cannot express "compare against nothing"
    // any other way, and identityChecked below is what records which of the two
    // happened.
    const std::vector<std::uint8_t> pin =
        expectedSpkiSha256 == nullptr
            ? std::vector<std::uint8_t>{}
            : std::vector<std::uint8_t>(expectedSpkiSha256->begin(), expectedSpkiSha256->end());

    const auto verified = emrtd::crypto::parseAndVerifyMasterList(der, pin);
    if (!verified) {
        return std::unexpected(toPublic(verified.error()));
    }

    // SHA-256, so 32 bytes, and the internal contract says always -- there is
    // no path that fills the field otherwise. Guarded because a short copy into
    // a fixed array is the kind of thing that stops being true quietly, and
    // because there is no honest way to report a partial fingerprint: an array
    // has no length to shorten, so the alternative is padding it with bytes
    // nothing computed. BadSignature is the refusal that covers "nothing here
    // vouches for these anchors", which is what a signer we cannot name means.
    if (verified->signerSpkiSha256.size() != kSpkiSha256Size) {
        return std::unexpected(MasterListError::BadSignature);
    }

    VerifiedMasterList out;
    out.anchors = verified->list.cscaDer;
    std::copy(verified->signerSpkiSha256.begin(), verified->signerSpkiSha256.end(), out.signerSpkiSha256.begin());
    out.identityChecked = verified->identityChecked;
    out.signerCertDer = verified->signerCertDer;
    out.signingTimeEpochSeconds = verified->signingTimeEpochSeconds;
    return out;
}

std::optional<std::array<std::uint8_t, kSpkiSha256Size>>
spkiSha256FromCertificateDer(const std::vector<std::uint8_t>& certDer)
{
    const auto fingerprint = emrtd::crypto::spkiSha256FromCertificateDer(certDer);
    // Same unreachable guard as above, and here the answer is the natural one:
    // a value means a fingerprint, so anything that is not 32 bytes is nothing.
    if (!fingerprint || fingerprint->size() != kSpkiSha256Size) {
        return std::nullopt;
    }

    std::array<std::uint8_t, kSpkiSha256Size> out{};
    std::copy(fingerprint->begin(), fingerprint->end(), out.begin());
    return out;
}

bool signerChainsToAnyAnchor(const std::vector<std::uint8_t>& signerCertDer,
                             const std::vector<std::vector<std::uint8_t>>& anchorsDer)
{
    return emrtd::crypto::signerChainsToAnyAnchor(signerCertDer, anchorsDer);
}

} // namespace LibreSCRS::Trust

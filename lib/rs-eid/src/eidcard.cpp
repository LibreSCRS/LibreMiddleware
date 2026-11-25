// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "eidcard.h"
#include "card_reader_gemalto.h"
#include "card_verifier.h"
#include <apdu.h>
#include <smartcard/card_connection.h>
#include <smartcard/or_throw.h>

#include <LibreSCRS/Logging.h>

#include <algorithm>
#include <stdexcept>

namespace eidcard {

namespace Core = LibreSCRS::RsEId::Core;

EIdCard::EIdCard(LibreSCRS::SmartCard::CardConnection& externalConn) : conn(&externalConn)
{
    selected = CardReaderGemalto::selectApplication(*conn);
    if (!selected)
        throw std::runtime_error("Unknown card type: no Serbian eID application selected");
}

EIdCard::~EIdCard() = default;

const Core::DocumentProfile& EIdCard::profile() const
{
    return *selected;
}

const Core::RawFiles& EIdCard::load(std::span<const std::uint16_t> fids)
{
    std::vector<std::uint16_t> todo;
    for (const auto fid : fids) {
        if (!tried.contains(fid))
            todo.push_back(fid);
    }
    if (todo.empty())
        return files;

    auto tx = LibreSCRS::SmartCard::Internal::orThrow(LibreSCRS::SmartCard::Internal::CardTransaction::begin(*conn));
    for (const auto fid : todo) {
        const auto spec = std::ranges::find(selected->files, fid, &Core::FileSpec::fid);
        if (spec == selected->files.end()) {
            tried.insert(fid); // a file the profile does not know cannot be read as one
            continue;
        }
        // Remembered only once the card has answered: a read that throws leaves
        // the file untried, so a flaky link cannot pass for "the card refused".
        auto bytes = CardReaderGemalto::readFile(*conn, *selected, *spec);
        tried.insert(fid);
        if (bytes)
            files[fid] = std::move(*bytes);
    }
    return files;
}

PhotoData EIdCard::readPortrait()
{
    const std::uint16_t fid = selected->photoFid;
    const auto& read = load(std::span<const std::uint16_t>(&fid, 1));
    const auto file = read.find(fid);
    return file == read.end() ? PhotoData{} : Core::extractPhoto(file->second);
}

void EIdCard::addTrustedCertificate(const std::vector<uint8_t>& derCert)
{
    if (!verifier)
        verifier = std::make_unique<CardVerifier>(""); // empty path = cert-by-cert mode
    verifier->addCertificate(derCert);
}

// Read what a verdict needs, then judge it. A read that fails for good leaves
// the verdict unknown rather than the whole card unreadable.
template <typename Verdict>
VerificationResult EIdCard::verdict(std::vector<std::uint16_t> fids, Verdict&& judge)
{
    if (!verifier)
        return VerificationResult::Unknown;
    try {
        return judge(load(fids));
    } catch (const std::exception& e) {
        LibreSCRS::log::tracef(LibreSCRS::log::TraceChannel::Sign, "[EIdCard] verification read failed: {}", e.what());
        return VerificationResult::Unknown;
    }
}

VerificationResult EIdCard::verifyCard()
{
    return verdict({selected->cardCertSodFid},
                   [&](const Core::RawFiles& f) { return verifier->verifyCard(*selected, f); });
}

VerificationResult EIdCard::verifyFixedData()
{
    return verdict(CardVerifier::filesFor(*selected, Core::SodRole::Fixed),
                   [&](const Core::RawFiles& f) { return verifier->verifyFixedData(*selected, f); });
}

VerificationResult EIdCard::verifyVariableData()
{
    return verdict(CardVerifier::filesFor(*selected, Core::SodRole::Variable),
                   [&](const Core::RawFiles& f) { return verifier->verifyVariableData(*selected, f); });
}

} // namespace eidcard

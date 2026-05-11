// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief @ref LibreSCRS::OpenSc::Pkcs11::OpenScPKCS11Provider — broadest
///        PKCS#11 fallback. Constructs an @ref OpenScCard and returns it
///        on a successful @c sc_pkcs15_bind.

#include <internal/OpenScPKCS11Provider.h>

#include "opensc_card.h"

#include <internal/Crv.h>

namespace LibreSCRS::OpenSc::Pkcs11 {

std::shared_ptr<LibreSCRS::Pkcs11::Internal::PKCS11Card> OpenScPKCS11Provider::probe(const std::string& readerName)
{
    auto card = std::make_shared<OpenScCard>();
    if (auto rc = card->bind(readerName); rc != LibreSCRS::Pkcs11::Internal::Crv::Ok)
        return nullptr;
    return card;
}

} // namespace LibreSCRS::OpenSc::Pkcs11

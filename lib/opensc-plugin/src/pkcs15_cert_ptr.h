// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

/// @file
/// @brief RAII smart-pointer alias for @c sc_pkcs15_cert_t returned by
///        @c sc_pkcs15_read_certificate.
///
/// libopensc allocates a fresh @c sc_pkcs15_cert_t on each successful
/// @c sc_pkcs15_read_certificate call; the caller owns it and must
/// release with @c sc_pkcs15_free_certificate. Wrapping in
/// @c std::unique_ptr closes throw paths between the read and the
/// free (e.g. @c std::vector::assign and @c std::vector::push_back
/// inside the per-cert loop), which previously leaked the cert on
/// @c std::bad_alloc.

#include <libopensc/opensc.h>
#include <libopensc/pkcs15.h>

#include <memory>

namespace LibreSCRS::OpenSc::Plugin {

struct Pkcs15CertDeleter
{
    void operator()(sc_pkcs15_cert_t* p) const noexcept
    {
        if (p)
            sc_pkcs15_free_certificate(p);
    }
};

using Pkcs15CertPtr = std::unique_ptr<sc_pkcs15_cert_t, Pkcs15CertDeleter>;

} // namespace LibreSCRS::OpenSc::Plugin

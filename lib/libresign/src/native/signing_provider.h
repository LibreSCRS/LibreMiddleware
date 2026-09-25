// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#error "This header is internal to LibreMiddleware. Public API: <LibreSCRS/...>"
#endif

#pragma once

#include <memory>

typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;

namespace libresign {

class Pkcs11Token;

// RAII wrapper for EVP_PKEY — declared here rather than taken from the shared
// internal set, because this header must not include an OpenSSL header at all:
// the deleter body lives in the .cpp, so <openssl/evp.h> stays out of every
// consumer of this file. The shared set's EvpPkeyPtr is the same shape and the
// two are ABI-compatible; this one exists for the include boundary, which is a
// reason the registry carries rather than a duplicate it tolerates.
struct EvpPkeyPublicDeleter
{
    void operator()(EVP_PKEY* p) const;
};
using EvpPkeyPublicPtr = std::unique_ptr<EVP_PKEY, EvpPkeyPublicDeleter>;

/// Keeps the librescrs OpenSSL provider loaded into the default library
/// context for as long as it lives. The first lease loads it, the last one to
/// go unloads it: a provider loaded and never unloaded is still referenced when
/// OpenSSL tears the context down at exit, so its allocations are never freed.
///
/// Only what a lease loaded is unloaded. The default provider is left to
/// OpenSSL's own fallback, which it activates on first use and frees at exit,
/// so unloading this one never takes the standard algorithms away from other
/// OpenSSL users in the process; only when something else has already turned
/// the fallback off does the lease load the default provider itself, and then
/// it unloads that too.
///
/// Thread-safe: leases may be taken and dropped concurrently.
class SigningProviderLease
{
public:
    SigningProviderLease();
    ~SigningProviderLease();
    SigningProviderLease(const SigningProviderLease&) = delete;
    SigningProviderLease& operator=(const SigningProviderLease&) = delete;
};

/// @p lease is the proof that the provider stays loaded while the key is used;
/// it must outlive the returned key.
EvpPkeyPublicPtr createPkcs11EvpKey(const SigningProviderLease& lease, Pkcs11Token& token, X509* cert);

} // namespace libresign

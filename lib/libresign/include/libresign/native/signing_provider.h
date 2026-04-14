// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

typedef struct evp_pkey_st EVP_PKEY;
typedef struct x509_st X509;

namespace libresign {

class Pkcs11Token;

void initSigningProvider();

EVP_PKEY* createPkcs11EvpKey(Pkcs11Token& token, X509* cert);

} // namespace libresign

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <openssl/x509.h>

#include <algorithm>
#include <cctype>
#include <string>

namespace LibreSCRS::RsEId::Core::detail {

/// Lower-cased Common Name (CN) of an X509_NAME, or "" if it has none.
/// MUP certificate CNs are ASCII; used only for trust-branch classification.
inline std::string lowerCommonName(X509_NAME* name)
{
    if (!name)
        return {};
    const int idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
    if (idx < 0)
        return {};
    X509_NAME_ENTRY* entry = X509_NAME_get_entry(name, idx);
    if (!entry)
        return {};
    ASN1_STRING* data = X509_NAME_ENTRY_get_data(entry);
    if (!data)
        return {};
    unsigned char* utf8 = nullptr;
    const int len = ASN1_STRING_to_UTF8(&utf8, data);
    if (len < 0 || !utf8)
        return {};
    std::string cn(reinterpret_cast<const char*>(utf8), static_cast<std::size_t>(len));
    OPENSSL_free(utf8);
    std::transform(cn.begin(), cn.end(), cn.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return cn;
}

/// True iff `signer` was issued by a MUP "Resursi" (resources / personalization)
/// certification authority — the only branch of the MUP PKI authorised to sign a
/// card Security Object (SOD).
///
/// The MUP PKI issues citizen ("Gradjani") and officials ("Sluzbenici") certificates
/// from CAs that are SIBLINGS of the resources CA under the SAME roots, in every
/// root generation. A cryptographically valid chain to a trusted MUP root therefore
/// does NOT by itself establish a legitimate card-data signer: a citizen's own eID
/// certificate chains to the same root. This predicate enforces the resources-branch
/// domain, keyed on the issuer CN — which names the branch consistently ("...Resursi...")
/// across every generation, so it holds without a per-generation, per-certificate
/// allow-list (and without needing the legacy issuer CA certs to be loadable, which on
/// modern OpenSSL some are not).
///
/// Fail-closed: a null certificate or a missing/unreadable issuer CN is rejected.
inline bool signerIsMupDocumentSigner(X509* signer)
{
    if (!signer)
        return false;
    const std::string issuerCn = lowerCommonName(X509_get_issuer_name(signer));
    if (issuerCn.empty())
        return false;
    // Explicitly exclude the sibling citizen / officials branches.
    if (issuerCn.find("gradjani") != std::string::npos || issuerCn.find("sluzbenici") != std::string::npos)
        return false;
    // Accept only the resources branch.
    return issuerCn.find("resursi") != std::string::npos;
}

} // namespace LibreSCRS::RsEId::Core::detail

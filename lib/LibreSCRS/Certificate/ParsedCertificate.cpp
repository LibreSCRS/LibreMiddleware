// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#ifndef LIBRESCRS_INTERNAL_BUILD
#define LIBRESCRS_INTERNAL_BUILD
#endif
#include <LibreSCRS/Certificate/ParsedCertificate.h>

#include <LibreSCRS/Auth/ErrorKeys.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <utility>

namespace LibreSCRS::Certificate {

namespace {

using X509Ptr = std::unique_ptr<X509, decltype(&X509_free)>;

std::string asn1StringToUtf8(const ASN1_STRING* s)
{
    if (!s)
        return {};
    unsigned char* utf8 = nullptr;
    int len = ASN1_STRING_to_UTF8(&utf8, s);
    if (len < 0 || !utf8)
        return {};
    std::string out(reinterpret_cast<char*>(utf8), static_cast<std::size_t>(len));
    OPENSSL_free(utf8);
    return out;
}

ObjectIdentifier asn1ObjectToOid(const ASN1_OBJECT* obj)
{
    if (!obj)
        return ObjectIdentifier{};
    char buf[128] = {};
    OBJ_obj2txt(buf, sizeof(buf), obj, 1);
    return ObjectIdentifier(std::string(buf));
}

DistinguishedName parseDn(const X509_NAME* name)
{
    DistinguishedName dn;
    if (!name)
        return dn;
    int count = X509_NAME_entry_count(name);
    for (int i = 0; i < count; ++i) {
        X509_NAME_ENTRY* entry = X509_NAME_get_entry(const_cast<X509_NAME*>(name), i);
        if (!entry)
            continue;
        ASN1_OBJECT* obj = X509_NAME_ENTRY_get_object(entry);
        ASN1_STRING* val = X509_NAME_ENTRY_get_data(entry);
        DistinguishedNameComponent c;
        c.oid = asn1ObjectToOid(obj);
        c.value = asn1StringToUtf8(val);
        dn.components.push_back(std::move(c));
    }
    return dn;
}

std::chrono::system_clock::time_point asn1TimeToTimePoint(const ASN1_TIME* t)
{
    if (!t)
        return {};
    std::tm tm{};
    if (ASN1_TIME_to_tm(t, &tm) != 1)
        return {};
    auto epoch = timegm(&tm);
    return std::chrono::system_clock::from_time_t(epoch);
}

std::string ia5ToString(const ASN1_IA5STRING* s)
{
    if (!s)
        return {};
    const unsigned char* data = ASN1_STRING_get0_data(s);
    int len = ASN1_STRING_length(s);
    if (!data || len <= 0)
        return {};
    return std::string(reinterpret_cast<const char*>(data), static_cast<std::size_t>(len));
}

std::string ipBytesToString(const ASN1_OCTET_STRING* s)
{
    if (!s)
        return {};
    const unsigned char* data = ASN1_STRING_get0_data(s);
    int len = ASN1_STRING_length(s);
    if (!data || len <= 0)
        return {};
    char buf[64] = {};
    if (len == 4) {
        std::snprintf(buf, sizeof(buf), "%u.%u.%u.%u", data[0], data[1], data[2], data[3]);
        return buf;
    }
    if (len == 16) {
        std::snprintf(buf, sizeof(buf),
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
                      "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                      data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7], data[8], data[9],
                      data[10], data[11], data[12], data[13], data[14], data[15]);
        return buf;
    }
    return {};
}

GeneralName convertGeneralName(const GENERAL_NAME* gn)
{
    GeneralName out;
    if (!gn)
        return out;
    switch (gn->type) {
    case GEN_OTHERNAME:
        out.type = GeneralNameType::OtherName;
        // Composite — leave string value empty, raw DER captured below.
        break;
    case GEN_EMAIL:
        out.type = GeneralNameType::Rfc822Name;
        out.value = ia5ToString(gn->d.rfc822Name);
        break;
    case GEN_DNS:
        out.type = GeneralNameType::DnsName;
        out.value = ia5ToString(gn->d.dNSName);
        break;
    case GEN_X400:
        out.type = GeneralNameType::X400Address;
        break;
    case GEN_DIRNAME:
        out.type = GeneralNameType::DirectoryName;
        if (gn->d.directoryName) {
            char* dn = X509_NAME_oneline(gn->d.directoryName, nullptr, 0);
            if (dn) {
                out.value = dn;
                OPENSSL_free(dn);
            }
        }
        break;
    case GEN_EDIPARTY:
        out.type = GeneralNameType::EdiPartyName;
        break;
    case GEN_URI:
        out.type = GeneralNameType::UniformResourceIdentifier;
        out.value = ia5ToString(gn->d.uniformResourceIdentifier);
        break;
    case GEN_IPADD:
        out.type = GeneralNameType::IpAddress;
        out.value = ipBytesToString(gn->d.iPAddress);
        break;
    case GEN_RID:
        out.type = GeneralNameType::RegisteredId;
        out.value = asn1ObjectToOid(gn->d.registeredID).dottedDecimal;
        break;
    default:
        out.type = GeneralNameType::OtherName;
        break;
    }

    // Always capture the raw DER for callers that need the full structure.
    int len = i2d_GENERAL_NAME(const_cast<GENERAL_NAME*>(gn), nullptr);
    if (len > 0) {
        out.rawValue.resize(static_cast<std::size_t>(len));
        unsigned char* p = out.rawValue.data();
        i2d_GENERAL_NAME(const_cast<GENERAL_NAME*>(gn), &p);
    }
    return out;
}

std::optional<std::vector<GeneralName>> readGeneralNamesExt(const X509* x509, int nid)
{
    int crit = -1;
    auto* gns = static_cast<GENERAL_NAMES*>(X509_get_ext_d2i(x509, nid, &crit, nullptr));
    if (!gns) {
        // crit == -1 means "extension not present"; -2 means "present but
        // multiple times / decode error". For both cases we return nullopt.
        return std::nullopt;
    }
    std::unique_ptr<GENERAL_NAMES, decltype(&GENERAL_NAMES_free)> guard(gns, GENERAL_NAMES_free);
    std::vector<GeneralName> out;
    int n = sk_GENERAL_NAME_num(gns);
    out.reserve(static_cast<std::size_t>(std::max(0, n)));
    for (int i = 0; i < n; ++i) {
        out.push_back(convertGeneralName(sk_GENERAL_NAME_value(gns, i)));
    }
    return out;
}

} // namespace

struct LIBRESCRS_INTERNAL ParsedCertificate::Impl
{
    X509Ptr x509{nullptr, X509_free};
    std::vector<std::uint8_t> originalDer;
};

ParsedCertificate::ParsedCertificate() = default;
ParsedCertificate::~ParsedCertificate() = default;
ParsedCertificate::ParsedCertificate(ParsedCertificate&&) noexcept = default;
ParsedCertificate& ParsedCertificate::operator=(ParsedCertificate&&) noexcept = default;
ParsedCertificate::operator bool() const noexcept
{
    return d != nullptr;
}

std::expected<ParsedCertificate, ParsedCertificate::ParseError>
ParsedCertificate::fromDer(std::span<const std::uint8_t> der) noexcept
{
    using Auth::ErrorKeys::derInvalid;

    if (der.empty()) {
        return std::unexpected{ParseError{ParseError::Kind::Invalid, derInvalid(), std::string{"DER input is empty"}}};
    }
    const std::uint8_t* p = der.data();
    X509Ptr x509(d2i_X509(nullptr, &p, static_cast<long>(der.size())), X509_free);
    if (!x509) {
        return std::unexpected{
            ParseError{ParseError::Kind::Invalid, derInvalid(), std::string{"d2i_X509 rejected DER input"}}};
    }

    // The Impl construction + originalDer copy below can throw bad_alloc.
    // The noexcept contract on this factory requires translating any such
    // throw into a structured ParseError::Kind::AllocationFailed rather
    // than propagating across the public ABI boundary.
    try {
        ParsedCertificate cert;
        cert.d = std::make_unique<Impl>();
        cert.d->x509 = std::move(x509);
        cert.d->originalDer.assign(der.begin(), der.end());
        return cert;
    } catch (const std::bad_alloc&) {
        return std::unexpected{ParseError{ParseError::Kind::AllocationFailed, derInvalid(),
                                          std::string{"std::bad_alloc during ParsedCertificate construction"}}};
    } catch (const std::exception& e) {
        // Defensive: any other exception from STL allocations / move /
        // assign — same AllocationFailed bucket since the failure mode
        // is init-time resource shortfall, not parse-content failure.
        return std::unexpected{
            ParseError{ParseError::Kind::AllocationFailed, derInvalid(),
                       std::string{"std::exception during ParsedCertificate construction: "} + e.what()}};
    }
}

DistinguishedName ParsedCertificate::subject() const
{
    if (!d)
        return {};
    return parseDn(X509_get_subject_name(d->x509.get()));
}

DistinguishedName ParsedCertificate::issuer() const
{
    if (!d)
        return {};
    return parseDn(X509_get_issuer_name(d->x509.get()));
}

std::vector<std::uint8_t> ParsedCertificate::serialNumber() const
{
    if (!d)
        return {};
    const ASN1_INTEGER* sn = X509_get0_serialNumber(d->x509.get());
    if (!sn)
        return {};
    std::unique_ptr<BIGNUM, decltype(&BN_free)> bn(ASN1_INTEGER_to_BN(sn, nullptr), BN_free);
    if (!bn)
        return {};
    int len = BN_num_bytes(bn.get());
    if (len <= 0)
        return {};
    std::vector<std::uint8_t> out(static_cast<std::size_t>(len));
    BN_bn2bin(bn.get(), out.data());
    return out;
}

int ParsedCertificate::version() const
{
    if (!d)
        return 0;
    // RFC 5280: stored zero-based (v1=0, v2=1, v3=2). Return the human
    // version number (1, 2, 3) for caller convenience.
    return static_cast<int>(X509_get_version(d->x509.get())) + 1;
}

std::chrono::system_clock::time_point ParsedCertificate::notBefore() const
{
    if (!d)
        return {};
    return asn1TimeToTimePoint(X509_get0_notBefore(d->x509.get()));
}

std::chrono::system_clock::time_point ParsedCertificate::notAfter() const
{
    if (!d)
        return {};
    return asn1TimeToTimePoint(X509_get0_notAfter(d->x509.get()));
}

ObjectIdentifier ParsedCertificate::signatureAlgorithmOid() const
{
    if (!d)
        return {};
    const X509_ALGOR* alg = nullptr;
    const ASN1_BIT_STRING* sig = nullptr;
    X509_get0_signature(&sig, &alg, d->x509.get());
    if (!alg)
        return {};
    const ASN1_OBJECT* obj = nullptr;
    X509_ALGOR_get0(&obj, nullptr, nullptr, alg);
    return asn1ObjectToOid(obj);
}

std::string ParsedCertificate::signatureAlgorithmDescription() const
{
    auto oid = signatureAlgorithmOid();
    auto fn = oid.friendlyName();
    return fn.empty() ? oid.dottedDecimal : fn;
}

std::vector<std::uint8_t> ParsedCertificate::signatureValue() const
{
    if (!d)
        return {};
    const ASN1_BIT_STRING* sig = nullptr;
    X509_get0_signature(&sig, nullptr, d->x509.get());
    if (!sig)
        return {};
    const unsigned char* sigData = ASN1_STRING_get0_data(sig);
    int sigLen = ASN1_STRING_length(sig);
    if (!sigData || sigLen <= 0)
        return {};
    return {sigData, sigData + sigLen};
}

std::span<const std::uint8_t> ParsedCertificate::derBytes() const noexcept
{
    if (!d)
        return {};
    return {d->originalDer.data(), d->originalDer.size()};
}

PublicKeyInfo ParsedCertificate::publicKey() const
{
    PublicKeyInfo info;
    if (!d)
        return info;

    EVP_PKEY* pkey = X509_get0_pubkey(d->x509.get());
    if (!pkey)
        return info;

    int nid = EVP_PKEY_get_base_id(pkey);
    info.bitLength = EVP_PKEY_get_bits(pkey);

    char oidBuf[128] = {};
    OBJ_obj2txt(oidBuf, sizeof(oidBuf), OBJ_nid2obj(nid), 1);
    info.algorithmOid = ObjectIdentifier(std::string(oidBuf));

    switch (nid) {
    case EVP_PKEY_RSA:
    case EVP_PKEY_RSA_PSS:
        info.algorithm = PublicKeyAlgorithm::RSA;
        info.algorithmDescription = "RSA " + std::to_string(info.bitLength);
        break;
    case EVP_PKEY_EC: {
        info.algorithm = PublicKeyAlgorithm::ECDSA;
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        char curveName[80] = {};
        std::size_t curveLen = 0;
        if (EVP_PKEY_get_utf8_string_param(pkey, "group", curveName, sizeof(curveName), &curveLen) == 1) {
            // OpenSSL returns the curve's short or long friendly name here
            // (e.g. "prime256v1" or "secp384r1"). Acceptable for display
            // and consistent with `openssl ec -text` output.
            info.curveOid = curveName;
        }
#endif
        info.algorithmDescription = "ECDSA " + std::to_string(info.bitLength) + "-bit";
        break;
    }
    case EVP_PKEY_ED25519:
    case EVP_PKEY_ED448:
        info.algorithm = PublicKeyAlgorithm::EdDSA;
        info.algorithmDescription = (nid == EVP_PKEY_ED25519) ? "Ed25519" : "Ed448";
        break;
    default:
        info.algorithm = PublicKeyAlgorithm::Other;
        info.algorithmDescription = info.algorithmOid.friendlyName();
        if (info.algorithmDescription.empty()) {
            info.algorithmDescription = info.algorithmOid.dottedDecimal;
        }
        break;
    }
    return info;
}

std::optional<std::vector<KeyUsageBit>> ParsedCertificate::keyUsage() const
{
    if (!d)
        return std::nullopt;
    int loc = X509_get_ext_by_NID(d->x509.get(), NID_key_usage, -1);
    if (loc < 0)
        return std::nullopt;

    static constexpr std::pair<int, KeyUsageBit> kBits[] = {
        {KU_DIGITAL_SIGNATURE, KeyUsageBit::DigitalSignature},
        {KU_NON_REPUDIATION, KeyUsageBit::NonRepudiation},
        {KU_KEY_ENCIPHERMENT, KeyUsageBit::KeyEncipherment},
        {KU_DATA_ENCIPHERMENT, KeyUsageBit::DataEncipherment},
        {KU_KEY_AGREEMENT, KeyUsageBit::KeyAgreement},
        {KU_KEY_CERT_SIGN, KeyUsageBit::KeyCertSign},
        {KU_CRL_SIGN, KeyUsageBit::CRLSign},
        {KU_ENCIPHER_ONLY, KeyUsageBit::EncipherOnly},
        {KU_DECIPHER_ONLY, KeyUsageBit::DecipherOnly},
    };
    std::vector<KeyUsageBit> out;
    std::uint32_t bits = X509_get_key_usage(d->x509.get());
    for (auto [bit, kub] : kBits) {
        if (bits & bit)
            out.push_back(kub);
    }
    return out;
}

std::optional<std::vector<ObjectIdentifier>> ParsedCertificate::extendedKeyUsage() const
{
    if (!d)
        return std::nullopt;
    auto* eku = static_cast<EXTENDED_KEY_USAGE*>(X509_get_ext_d2i(d->x509.get(), NID_ext_key_usage, nullptr, nullptr));
    if (!eku)
        return std::nullopt;
    std::unique_ptr<EXTENDED_KEY_USAGE, decltype(&EXTENDED_KEY_USAGE_free)> guard(eku, EXTENDED_KEY_USAGE_free);
    std::vector<ObjectIdentifier> out;
    int n = sk_ASN1_OBJECT_num(eku);
    out.reserve(static_cast<std::size_t>(std::max(0, n)));
    for (int i = 0; i < n; ++i) {
        out.push_back(asn1ObjectToOid(sk_ASN1_OBJECT_value(eku, i)));
    }
    return out;
}

std::optional<std::vector<GeneralName>> ParsedCertificate::subjectAlternativeNames() const
{
    if (!d)
        return std::nullopt;
    return readGeneralNamesExt(d->x509.get(), NID_subject_alt_name);
}

std::optional<std::vector<GeneralName>> ParsedCertificate::issuerAlternativeNames() const
{
    if (!d)
        return std::nullopt;
    return readGeneralNamesExt(d->x509.get(), NID_issuer_alt_name);
}

std::optional<ParsedCertificate::BasicConstraints> ParsedCertificate::basicConstraints() const
{
    if (!d)
        return std::nullopt;
    auto* bc =
        static_cast<BASIC_CONSTRAINTS*>(X509_get_ext_d2i(d->x509.get(), NID_basic_constraints, nullptr, nullptr));
    if (!bc)
        return std::nullopt;
    std::unique_ptr<BASIC_CONSTRAINTS, decltype(&BASIC_CONSTRAINTS_free)> guard(bc, BASIC_CONSTRAINTS_free);
    BasicConstraints out;
    out.isCa = (bc->ca != 0);
    if (bc->pathlen) {
        out.pathLenConstraint = static_cast<int>(ASN1_INTEGER_get(bc->pathlen));
    }
    return out;
}

std::optional<std::vector<std::uint8_t>> ParsedCertificate::authorityKeyIdentifier() const
{
    if (!d)
        return std::nullopt;
    auto* aki =
        static_cast<AUTHORITY_KEYID*>(X509_get_ext_d2i(d->x509.get(), NID_authority_key_identifier, nullptr, nullptr));
    if (!aki)
        return std::nullopt;
    std::unique_ptr<AUTHORITY_KEYID, decltype(&AUTHORITY_KEYID_free)> guard(aki, AUTHORITY_KEYID_free);
    if (!aki->keyid)
        return std::nullopt;
    const unsigned char* data = ASN1_STRING_get0_data(aki->keyid);
    int len = ASN1_STRING_length(aki->keyid);
    if (!data || len <= 0)
        return std::nullopt;
    return std::vector<std::uint8_t>(data, data + len);
}

std::optional<std::vector<std::uint8_t>> ParsedCertificate::subjectKeyIdentifier() const
{
    if (!d)
        return std::nullopt;
    auto* ski =
        static_cast<ASN1_OCTET_STRING*>(X509_get_ext_d2i(d->x509.get(), NID_subject_key_identifier, nullptr, nullptr));
    if (!ski)
        return std::nullopt;
    std::unique_ptr<ASN1_OCTET_STRING, decltype(&ASN1_OCTET_STRING_free)> guard(ski, ASN1_OCTET_STRING_free);
    const unsigned char* data = ASN1_STRING_get0_data(ski);
    int len = ASN1_STRING_length(ski);
    if (!data || len <= 0)
        return std::nullopt;
    return std::vector<std::uint8_t>(data, data + len);
}

std::optional<std::vector<std::string>> ParsedCertificate::crlDistributionPoints() const
{
    if (!d)
        return std::nullopt;
    auto* crldp =
        static_cast<CRL_DIST_POINTS*>(X509_get_ext_d2i(d->x509.get(), NID_crl_distribution_points, nullptr, nullptr));
    if (!crldp)
        return std::nullopt;
    std::unique_ptr<CRL_DIST_POINTS, decltype(&CRL_DIST_POINTS_free)> guard(crldp, CRL_DIST_POINTS_free);
    std::vector<std::string> out;
    int n = sk_DIST_POINT_num(crldp);
    for (int i = 0; i < n; ++i) {
        DIST_POINT* dp = sk_DIST_POINT_value(crldp, i);
        if (!dp || !dp->distpoint || dp->distpoint->type != 0)
            continue;
        GENERAL_NAMES* names = dp->distpoint->name.fullname;
        int m = sk_GENERAL_NAME_num(names);
        for (int j = 0; j < m; ++j) {
            GENERAL_NAME* gn = sk_GENERAL_NAME_value(names, j);
            if (gn && gn->type == GEN_URI) {
                std::string uri = ia5ToString(gn->d.uniformResourceIdentifier);
                if (!uri.empty())
                    out.push_back(std::move(uri));
            }
        }
    }
    return out;
}

namespace {

std::vector<std::string> readAuthorityInfoAccessUrls(const X509* x509, int methodNid)
{
    std::vector<std::string> out;
    auto* aia = static_cast<AUTHORITY_INFO_ACCESS*>(
        X509_get_ext_d2i(const_cast<X509*>(x509), NID_info_access, nullptr, nullptr));
    if (!aia)
        return out;
    std::unique_ptr<AUTHORITY_INFO_ACCESS, decltype(&AUTHORITY_INFO_ACCESS_free)> guard(aia,
                                                                                        AUTHORITY_INFO_ACCESS_free);
    int n = sk_ACCESS_DESCRIPTION_num(aia);
    for (int i = 0; i < n; ++i) {
        ACCESS_DESCRIPTION* ad = sk_ACCESS_DESCRIPTION_value(aia, i);
        if (!ad || !ad->method)
            continue;
        if (OBJ_obj2nid(ad->method) != methodNid)
            continue;
        if (!ad->location || ad->location->type != GEN_URI)
            continue;
        std::string uri = ia5ToString(ad->location->d.uniformResourceIdentifier);
        if (!uri.empty())
            out.push_back(std::move(uri));
    }
    return out;
}

} // namespace

std::optional<std::vector<std::string>> ParsedCertificate::ocspResponderUrls() const
{
    if (!d)
        return std::nullopt;
    if (X509_get_ext_by_NID(d->x509.get(), NID_info_access, -1) < 0)
        return std::nullopt;
    return readAuthorityInfoAccessUrls(d->x509.get(), NID_ad_OCSP);
}

std::optional<std::vector<std::string>> ParsedCertificate::caIssuersUrls() const
{
    if (!d)
        return std::nullopt;
    if (X509_get_ext_by_NID(d->x509.get(), NID_info_access, -1) < 0)
        return std::nullopt;
    return readAuthorityInfoAccessUrls(d->x509.get(), NID_ad_ca_issuers);
}

std::optional<std::vector<ObjectIdentifier>> ParsedCertificate::certificatePolicies() const
{
    if (!d)
        return std::nullopt;
    auto* polStack =
        static_cast<CERTIFICATEPOLICIES*>(X509_get_ext_d2i(d->x509.get(), NID_certificate_policies, nullptr, nullptr));
    if (!polStack)
        return std::nullopt;
    std::unique_ptr<CERTIFICATEPOLICIES, decltype(&CERTIFICATEPOLICIES_free)> guard(polStack, CERTIFICATEPOLICIES_free);
    std::vector<ObjectIdentifier> out;
    int n = sk_POLICYINFO_num(polStack);
    out.reserve(static_cast<std::size_t>(std::max(0, n)));
    for (int i = 0; i < n; ++i) {
        POLICYINFO* pi = sk_POLICYINFO_value(polStack, i);
        if (!pi)
            continue;
        out.push_back(asn1ObjectToOid(pi->policyid));
    }
    return out;
}

std::vector<Extension> ParsedCertificate::extensions() const
{
    std::vector<Extension> out;
    if (!d)
        return out;
    int count = X509_get_ext_count(d->x509.get());
    out.reserve(static_cast<std::size_t>(std::max(0, count)));
    for (int i = 0; i < count; ++i) {
        X509_EXTENSION* ext = X509_get_ext(d->x509.get(), i);
        if (!ext)
            continue;
        Extension e;
        e.oid = asn1ObjectToOid(X509_EXTENSION_get_object(ext));
        e.critical = X509_EXTENSION_get_critical(ext) != 0;
        ASN1_OCTET_STRING* val = X509_EXTENSION_get_data(ext);
        if (val) {
            const unsigned char* data = ASN1_STRING_get0_data(val);
            int len = ASN1_STRING_length(val);
            if (data && len > 0) {
                e.value.assign(data, data + len);
            }
        }
        out.push_back(std::move(e));
    }
    return out;
}

std::optional<Extension> ParsedCertificate::findExtension(const ObjectIdentifier& oid) const
{
    auto exts = extensions();
    for (auto& e : exts) {
        if (e.oid.dottedDecimal == oid.dottedDecimal)
            return std::move(e);
    }
    return std::nullopt;
}

} // namespace LibreSCRS::Certificate

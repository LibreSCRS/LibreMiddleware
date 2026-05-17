// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/xades_module.h"
#include "native/pkcs11_token.h"
#include "native/revocation_client.h"
#include "native/tsa_client.h"
#include "native_utils.h"

#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>

#include <charconv>
#include <climits>
#include <cstring>
#include <functional>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>

#include "xml_raii.h"

namespace libresign {

namespace {

using namespace libresign::native_utils;
using ::libresign::XmlDocPtr;

// ---- XML namespace URIs ----

constexpr const char* kNsDs = "http://www.w3.org/2000/09/xmldsig#";
constexpr const char* kNsXades = "http://uri.etsi.org/01903/v1.3.2#";

// Percent-encode a filename for use as a ds:Reference URI attribute.
// RFC 3986 §2.3 unreserved + "." "-" "_" "~" pass through; everything
// else (spaces, "&", "#", "?", UTF-8 bytes, etc.) becomes %HH. Without
// this, filenames with special chars produce a URI that validators
// dereference incorrectly — and xmlSetProp only escapes for XML, not
// URI.
std::string percentEncodeUriFilename(const std::string& in)
{
    std::string out;
    out.reserve(in.size());
    for (unsigned char c : in) {
        const bool unreserved = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                                c == '-' || c == '_' || c == '.' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            // Shared nibble-to-ASCII table from native_utils.h — same source
            // of truth as pades_module.cpp::hexEncode (DRY: one literal, one
            // place to fix).
            out.push_back('%');
            out.push_back(kHexChars[c >> 4]);
            out.push_back(kHexChars[c & 0x0F]);
        }
    }
    return out;
}

// ---- Extract issuer DN as RFC 2253 string ----

std::string issuerDN(X509* cert)
{
    X509_NAME* name = X509_get_issuer_name(cert);
    if (!name)
        throw std::runtime_error("X509_get_issuer_name() returned null");

    ::libresign::BioPtr bio(BIO_new(BIO_s_mem()));
    if (!bio)
        throw std::runtime_error("BIO_new() failed");

    // RFC 2253 format (the format expected by XML-DSIG)
    if (X509_NAME_print_ex(bio.get(), name, 0, XN_FLAG_RFC2253) < 0)
        throw std::runtime_error("X509_NAME_print_ex() failed");

    BUF_MEM* bufMem = nullptr;
    BIO_get_mem_ptr(bio.get(), &bufMem);
    return {bufMem->data, bufMem->length};
}

// ---- Extract serial number as decimal string ----

std::string serialNumber(X509* cert)
{
    const ASN1_INTEGER* serial = X509_get0_serialNumber(cert);
    if (!serial)
        throw std::runtime_error("X509_get0_serialNumber() returned null");

    ::libresign::BNPtr bn(ASN1_INTEGER_to_BN(serial, nullptr));
    if (!bn)
        throw std::runtime_error("ASN1_INTEGER_to_BN() failed");

    char* dec = BN_bn2dec(bn.get());
    if (!dec)
        throw std::runtime_error("BN_bn2dec() failed");

    std::string result(dec);
    OPENSSL_free(dec);
    return result;
}

// ---- Canonicalize an XML node subtree using Exclusive C14N ----
// Returns the canonical form as a byte vector.

std::vector<uint8_t> canonicalizeNode(xmlDocPtr doc, xmlNodePtr node)
{
    // Use XPath to select the subtree rooted at `node`. This lets libxml2's
    // C14N implementation handle namespace visibility correctly, including
    // namespaces declared on ancestor elements.
    XPathCtxPtr xpathCtx(xmlXPathNewContext(doc));
    if (!xpathCtx)
        throw std::runtime_error("xmlXPathNewContext() failed");

    // Register the node in the XPath context and evaluate a self-or-descendant expression
    // Use "(//. | //@* | //namespace::*)" scoped to the subtree via node as context
    xpathCtx->node = node;
    XPathObjPtr xpathObj(
        xmlXPathEvalExpression(BAD_CAST "(. | ./descendant::* | ./descendant::text() | ./@* | ./descendant::*/@* "
                                        "| ./namespace::* | ./descendant::*/namespace::*)",
                               xpathCtx.get()));

    if (!xpathObj || !xpathObj->nodesetval)
        throw std::runtime_error("XPath evaluation failed for C14N node selection");

    xmlChar* buf = nullptr;
    int size = xmlC14NDocDumpMemory(doc, xpathObj->nodesetval, XML_C14N_EXCLUSIVE_1_0, nullptr, 0, &buf);

    if (size < 0 || !buf) {
        if (buf)
            xmlFree(buf);
        throw std::runtime_error("xmlC14NDocDumpMemory() failed");
    }

    std::vector<uint8_t> result(buf, buf + size);
    xmlFree(buf);
    return result;
}

// ---- Helper: add a child element with text content ----

xmlNodePtr addChildWithText(xmlNodePtr parent, xmlNsPtr ns, const char* name, const std::string& text)
{
    xmlNodePtr node = xmlNewChild(parent, ns, BAD_CAST name, nullptr);
    if (!text.empty())
        xmlNodeSetContent(node, BAD_CAST text.c_str());
    return node;
}

// ---- Build the XAdES Signature XML document ----
//
// Returns the xmlDoc and sets signedInfoNode/signedPropsNode for
// later canonicalization and signing.

// W3C XML 1.0 §3.3.1 requires xml:id attribute values to be unique within a
// document. XAdES parallel sequential re-signing appends a new <ds:Signature>
// alongside the existing one, so every ID we mint must be disambiguated from
// the prior signature. Each call carries its own suffix and substitutes it
// into every Id/URI/Target attribute that previously used "-1".
struct SignatureIds
{
    std::string signature;        // "Signature-{suffix}"
    std::string signedProperties; // "SignedProperties-{suffix}"
    std::string signatureValue;   // "SignatureValue-{suffix}"
    std::string reference;        // "Reference-{suffix}"
};

SignatureIds makeSignatureIds(std::string_view suffix)
{
    return {
        std::string("Signature-") + std::string(suffix),
        std::string("SignedProperties-") + std::string(suffix),
        std::string("SignatureValue-") + std::string(suffix),
        std::string("Reference-") + std::string(suffix),
    };
}

struct XmlSignatureContext
{
    XmlDocPtr doc;
    xmlNodePtr signatureNode = nullptr;
    xmlNodePtr signedInfoNode = nullptr;
    xmlNodePtr signedPropsNode = nullptr;
    xmlNodePtr signatureValueNode = nullptr;
    xmlNodePtr dataRefDigestValueNode = nullptr;
    xmlNodePtr propsRefDigestValueNode = nullptr;
    SignatureIds ids;
};

XmlSignatureContext buildSignatureXml(const std::vector<uint8_t>& certDer, X509* cert,
                                      const std::vector<std::vector<uint8_t>>& chainDer, const std::string& fileName,
                                      SignaturePackaging packaging, const SignatureIds& ids)
{
    XmlSignatureContext ctx;
    ctx.ids = ids;

    // Create document
    xmlDocPtr rawDoc = xmlNewDoc(BAD_CAST "1.0");
    if (!rawDoc)
        throw std::runtime_error("xmlNewDoc() failed");
    ctx.doc.reset(rawDoc);

    // Create root <ds:Signature> element
    xmlNodePtr sigNode = xmlNewNode(nullptr, BAD_CAST "Signature");
    xmlDocSetRootElement(rawDoc, sigNode);

    xmlNsPtr nsDs = xmlNewNs(sigNode, BAD_CAST kNsDs, BAD_CAST "ds");
    xmlNsPtr nsXades = xmlNewNs(sigNode, BAD_CAST kNsXades, BAD_CAST "xades");
    xmlSetNs(sigNode, nsDs);
    xmlSetProp(sigNode, BAD_CAST "Id", BAD_CAST ids.signature.c_str());
    ctx.signatureNode = sigNode;

    // ---- <ds:SignedInfo> ----
    xmlNodePtr signedInfo = xmlNewChild(sigNode, nsDs, BAD_CAST "SignedInfo", nullptr);
    ctx.signedInfoNode = signedInfo;

    // <ds:CanonicalizationMethod>
    xmlNodePtr c14nMethod = xmlNewChild(signedInfo, nsDs, BAD_CAST "CanonicalizationMethod", nullptr);
    xmlSetProp(c14nMethod, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#");

    // <ds:SignatureMethod>
    xmlNodePtr sigMethod = xmlNewChild(signedInfo, nsDs, BAD_CAST "SignatureMethod", nullptr);
    // Detect key type from certificate
    EVP_PKEY* pubKey = X509_get0_pubkey(cert);
    int keyType = pubKey ? EVP_PKEY_base_id(pubKey) : EVP_PKEY_RSA;
    if (keyType == EVP_PKEY_EC) {
        xmlSetProp(sigMethod, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
    } else {
        xmlSetProp(sigMethod, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
    }

    // <ds:Reference URI="" or URI="filename"> (data reference)
    xmlNodePtr dataRef = xmlNewChild(signedInfo, nsDs, BAD_CAST "Reference", nullptr);
    xmlSetProp(dataRef, BAD_CAST "Id", BAD_CAST ids.reference.c_str());
    if (packaging == SignaturePackaging::ENVELOPED) {
        xmlSetProp(dataRef, BAD_CAST "URI", BAD_CAST "");
        // Enveloped signature transform
        xmlNodePtr transforms = xmlNewChild(dataRef, nsDs, BAD_CAST "Transforms", nullptr);
        xmlNodePtr envTransform = xmlNewChild(transforms, nsDs, BAD_CAST "Transform", nullptr);
        xmlSetProp(envTransform, BAD_CAST "Algorithm",
                   BAD_CAST "http://www.w3.org/2000/09/xmldsig#enveloped-signature");
        // Exclusive C14N transform — applied after removing the Signature element
        xmlNodePtr c14nTransform = xmlNewChild(transforms, nsDs, BAD_CAST "Transform", nullptr);
        xmlSetProp(c14nTransform, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#");
    } else {
        // Detached: reference is the file name, percent-encoded per RFC 3986
        const std::string encoded = percentEncodeUriFilename(fileName);
        xmlSetProp(dataRef, BAD_CAST "URI", BAD_CAST encoded.c_str());
    }

    xmlNodePtr dataDigestMethod = xmlNewChild(dataRef, nsDs, BAD_CAST "DigestMethod", nullptr);
    xmlSetProp(dataDigestMethod, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/04/xmlenc#sha256");
    xmlNodePtr dataDigestValue = xmlNewChild(dataRef, nsDs, BAD_CAST "DigestValue", nullptr);
    ctx.dataRefDigestValueNode = dataDigestValue;

    // <ds:Reference URI="#SignedProperties-{suffix}"> (signed properties reference)
    xmlNodePtr propsRef = xmlNewChild(signedInfo, nsDs, BAD_CAST "Reference", nullptr);
    std::string propsRefUri = "#" + ids.signedProperties;
    xmlSetProp(propsRef, BAD_CAST "URI", BAD_CAST propsRefUri.c_str());
    xmlSetProp(propsRef, BAD_CAST "Type", BAD_CAST "http://uri.etsi.org/01903#SignedProperties");

    // Exclusive C14N transform — must match the canonicalization used for digest computation
    xmlNodePtr propsTransforms = xmlNewChild(propsRef, nsDs, BAD_CAST "Transforms", nullptr);
    xmlNodePtr propsC14nTransform = xmlNewChild(propsTransforms, nsDs, BAD_CAST "Transform", nullptr);
    xmlSetProp(propsC14nTransform, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#");

    xmlNodePtr propsDigestMethod = xmlNewChild(propsRef, nsDs, BAD_CAST "DigestMethod", nullptr);
    xmlSetProp(propsDigestMethod, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/04/xmlenc#sha256");
    xmlNodePtr propsDigestValue = xmlNewChild(propsRef, nsDs, BAD_CAST "DigestValue", nullptr);
    ctx.propsRefDigestValueNode = propsDigestValue;

    // ---- <ds:SignatureValue> ----
    xmlNodePtr sigValue = xmlNewChild(sigNode, nsDs, BAD_CAST "SignatureValue", nullptr);
    xmlSetProp(sigValue, BAD_CAST "Id", BAD_CAST ids.signatureValue.c_str());
    ctx.signatureValueNode = sigValue;

    // ---- <ds:KeyInfo> ----
    xmlNodePtr keyInfo = xmlNewChild(sigNode, nsDs, BAD_CAST "KeyInfo", nullptr);
    xmlNodePtr x509Data = xmlNewChild(keyInfo, nsDs, BAD_CAST "X509Data", nullptr);

    // Add all certificates in chain
    for (const auto& der : chainDer) {
        addChildWithText(x509Data, nsDs, "X509Certificate", base64Encode(der));
    }

    // ---- <ds:Object> with <xades:QualifyingProperties> ----
    xmlNodePtr object = xmlNewChild(sigNode, nsDs, BAD_CAST "Object", nullptr);

    xmlNodePtr qualProps = xmlNewChild(object, nsXades, BAD_CAST "QualifyingProperties", nullptr);
    std::string qualPropsTarget = "#" + ids.signature;
    xmlSetProp(qualProps, BAD_CAST "Target", BAD_CAST qualPropsTarget.c_str());

    // ---- <xades:SignedProperties> ----
    xmlNodePtr signedProps = xmlNewChild(qualProps, nsXades, BAD_CAST "SignedProperties", nullptr);
    xmlSetProp(signedProps, BAD_CAST "Id", BAD_CAST ids.signedProperties.c_str());
    ctx.signedPropsNode = signedProps;

    // <xades:SignedSignatureProperties>
    xmlNodePtr signedSigProps = xmlNewChild(signedProps, nsXades, BAD_CAST "SignedSignatureProperties", nullptr);

    // <xades:SigningTime>
    addChildWithText(signedSigProps, nsXades, "SigningTime", iso8601Now());

    // <xades:SigningCertificateV2>
    xmlNodePtr sigCertV2 = xmlNewChild(signedSigProps, nsXades, BAD_CAST "SigningCertificateV2", nullptr);
    xmlNodePtr certElem = xmlNewChild(sigCertV2, nsXades, BAD_CAST "Cert", nullptr);

    // <xades:CertDigest>
    xmlNodePtr certDigest = xmlNewChild(certElem, nsXades, BAD_CAST "CertDigest", nullptr);
    xmlNodePtr certDigestMethod = xmlNewChild(certDigest, nsDs, BAD_CAST "DigestMethod", nullptr);
    xmlSetProp(certDigestMethod, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/04/xmlenc#sha256");
    addChildWithText(certDigest, nsDs, "DigestValue", base64Encode(sha256(certDer)));

    // <xades:IssuerSerial>
    xmlNodePtr issuerSerial = xmlNewChild(certElem, nsXades, BAD_CAST "IssuerSerial", nullptr);
    addChildWithText(issuerSerial, nsDs, "X509IssuerName", issuerDN(cert));
    addChildWithText(issuerSerial, nsDs, "X509SerialNumber", serialNumber(cert));

    // <xades:SignedDataObjectProperties>
    xmlNodePtr signedDataObjProps = xmlNewChild(signedProps, nsXades, BAD_CAST "SignedDataObjectProperties", nullptr);
    xmlNodePtr dataObjFormat = xmlNewChild(signedDataObjProps, nsXades, BAD_CAST "DataObjectFormat", nullptr);
    std::string dataObjRef = "#" + ids.reference;
    xmlSetProp(dataObjFormat, BAD_CAST "ObjectReference", BAD_CAST dataObjRef.c_str());
    addChildWithText(dataObjFormat, nsXades, "MimeType", mimeTypeFromFileName(fileName));

    return ctx;
}

// ---- Add UnsignedProperties for B-T/B-LT/B-LTA ----

xmlNodePtr ensureUnsignedProperties(xmlNodePtr signatureNode, xmlNsPtr nsXades)
{
    // Find QualifyingProperties
    xmlNodePtr qualProps = nullptr;
    for (xmlNodePtr child = signatureNode->children; child; child = child->next) {
        if (child->type == XML_ELEMENT_NODE && xmlStrcmp(child->name, BAD_CAST "Object") == 0) {
            for (xmlNodePtr grandChild = child->children; grandChild; grandChild = grandChild->next) {
                if (grandChild->type == XML_ELEMENT_NODE &&
                    xmlStrcmp(grandChild->name, BAD_CAST "QualifyingProperties") == 0) {
                    qualProps = grandChild;
                    break;
                }
            }
            if (qualProps)
                break;
        }
    }

    if (!qualProps)
        throw std::runtime_error("QualifyingProperties not found in Signature");

    // Check if UnsignedProperties already exists
    for (xmlNodePtr child = qualProps->children; child; child = child->next) {
        if (child->type == XML_ELEMENT_NODE && xmlStrcmp(child->name, BAD_CAST "UnsignedProperties") == 0)
            return child;
    }

    // Create it
    return xmlNewChild(qualProps, nsXades, BAD_CAST "UnsignedProperties", nullptr);
}

xmlNodePtr ensureUnsignedSignatureProperties(xmlNodePtr unsignedProps, xmlNsPtr nsXades)
{
    for (xmlNodePtr child = unsignedProps->children; child; child = child->next) {
        if (child->type == XML_ELEMENT_NODE && xmlStrcmp(child->name, BAD_CAST "UnsignedSignatureProperties") == 0)
            return child;
    }
    return xmlNewChild(unsignedProps, nsXades, BAD_CAST "UnsignedSignatureProperties", nullptr);
}

// ---- Serialize xmlDoc to UTF-8 bytes ----

std::vector<uint8_t> serializeDoc(xmlDocPtr doc)
{
    xmlChar* buf = nullptr;
    int size = 0;
    xmlDocDumpFormatMemoryEnc(doc, &buf, &size, "UTF-8", 0);
    if (!buf || size <= 0)
        throw std::runtime_error("xmlDocDumpFormatMemoryEnc() failed");

    std::vector<uint8_t> result(buf, buf + size);
    xmlFree(buf);
    return result;
}

} // namespace

// ---- XAdESModule::sign ----

SigningResult XAdESModule::sign(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                                SignatureLevel level, SignaturePackaging packaging, const TSAConfig& tsa)
{
    if (data.empty())
        return {false, {}, "Input data is empty"};

    try {
        native_utils::ensureXmlInitialized();

        // 1. Get certificate and chain from token
        auto certDer = token.certificate();
        if (certDer.empty())
            return {false, {}, "No certificate found on token"};

        X509Ptr cert = parseCert(certDer);
        auto chainDer = token.certificateChain();
        if (chainDer.empty())
            chainDer.push_back(certDer); // at minimum include signer cert

        // For ENVELOPED re-sign, the input XML may already contain a previous
        // <ds:Signature> with Id="Signature-1" etc. Pick the smallest positive
        // integer suffix not yet present so every Id attribute remains unique
        // (W3C XML 1.0 §3.3.1). DETACHED never has an input XML, so "1" is
        // always safe.
        std::string idSuffix = "1";
        std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> origDocPtr(nullptr, &xmlFreeDoc);
        constexpr int kSafeXmlOptions = XML_PARSE_NONET | XML_PARSE_NOCDATA;
        if (packaging == SignaturePackaging::ENVELOPED) {
            if (data.size() > static_cast<size_t>(INT_MAX))
                return {false, {}, "XAdES enveloped: input XML exceeds INT_MAX"};
            xmlDocPtr origDoc = xmlReadMemory(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()),
                                              nullptr, nullptr, kSafeXmlOptions);
            if (!origDoc)
                return {false, {}, "XAdES enveloped: failed to parse input XML"};
            origDocPtr.reset(origDoc);

            // Scan existing Id attributes for "Signature-N" / "SignedProperties-N"
            // / "SignatureValue-N" / "Reference-N" and bump past the highest N.
            int maxN = 0;
            std::function<void(xmlNodePtr)> scan = [&](xmlNodePtr node) {
                if (!node)
                    return;
                if (node->type == XML_ELEMENT_NODE) {
                    xmlChar* idAttr = xmlGetProp(node, BAD_CAST "Id");
                    if (idAttr) {
                        std::string s(reinterpret_cast<const char*>(idAttr));
                        xmlFree(idAttr);
                        for (std::string_view prefix :
                             {"Signature-", "SignedProperties-", "SignatureValue-", "Reference-"}) {
                            if (s.starts_with(prefix)) {
                                std::string_view suffix(s);
                                suffix.remove_prefix(prefix.size());
                                int n = 0;
                                auto [p, ec] = std::from_chars(suffix.data(), suffix.data() + suffix.size(), n);
                                if (ec == std::errc{} && p == suffix.data() + suffix.size() && n > maxN)
                                    maxN = n;
                                break;
                            }
                        }
                    }
                }
                for (xmlNodePtr c = node->children; c; c = c->next)
                    scan(c);
            };
            scan(xmlDocGetRootElement(origDoc));
            idSuffix = std::to_string(maxN + 1);
        }
        SignatureIds ids = makeSignatureIds(idSuffix);

        // 2. Build the XML Signature structure with the chosen IDs
        auto ctx = buildSignatureXml(certDer, cert.get(), chainDer, fileName, packaging, ids);

        // 3. For enveloped: embed Signature into original XML.
        //    For detached: set data digest from raw bytes.
        if (packaging == SignaturePackaging::ENVELOPED) {
            xmlNodePtr sigNode = xmlDocGetRootElement(ctx.doc.get());
            xmlUnlinkNode(sigNode);
            xmlNodePtr origRoot = xmlDocGetRootElement(origDocPtr.get());
            if (!xmlAddChild(origRoot, sigNode))
                return {false, {}, "XAdES enveloped: failed to add Signature to document"};
            ctx.doc.reset(origDocPtr.release());

            // Set placeholder digests so serialization has correct structure
            xmlNodeSetContent(ctx.dataRefDigestValueNode, BAD_CAST "PLACEHOLDER");
            xmlNodeSetContent(ctx.propsRefDigestValueNode, BAD_CAST "PLACEHOLDER");
        } else {
            auto dataHash = sha256(data);
            xmlNodeSetContent(ctx.dataRefDigestValueNode, BAD_CAST base64Encode(dataHash).c_str());
            xmlNodeSetContent(ctx.propsRefDigestValueNode, BAD_CAST "PLACEHOLDER");
        }

        // 4. Serialize-then-hash: serialize to compact XML, parse back, and
        //    compute all digests from the parsed form. This ensures the C14N
        //    output matches what validators will compute on the serialized XML.
        auto tempXml = serializeDoc(ctx.doc.get());
        if (tempXml.size() > static_cast<size_t>(INT_MAX))
            return {false, {}, "XAdES: serialized XML exceeds INT_MAX"};
        xmlDocPtr parsedDoc = xmlReadMemory(reinterpret_cast<const char*>(tempXml.data()),
                                            static_cast<int>(tempXml.size()), nullptr, nullptr, kSafeXmlOptions);
        if (!parsedDoc)
            return {false, {}, "XAdES: failed to re-parse serialized XML"};
        ctx.doc.reset(parsedDoc);

        // Find key nodes in the re-parsed document by Id attributes
        xmlNodePtr parsedRoot = xmlDocGetRootElement(parsedDoc);
        auto findById = [&](const char* id) -> xmlNodePtr {
            // Walk the tree to find element with matching Id attribute.
            // Check node itself first, then recurse into children.
            std::function<xmlNodePtr(xmlNodePtr)> walk = [&](xmlNodePtr node) -> xmlNodePtr {
                if (!node || node->type != XML_ELEMENT_NODE)
                    return nullptr;
                xmlChar* attr = xmlGetProp(node, BAD_CAST "Id");
                if (attr) {
                    bool match = xmlStrcmp(attr, BAD_CAST id) == 0;
                    xmlFree(attr);
                    if (match)
                        return node;
                }
                for (xmlNodePtr child = node->children; child; child = child->next) {
                    auto found = walk(child);
                    if (found)
                        return found;
                }
                return nullptr;
            };
            return walk(parsedRoot);
        };

        ctx.signatureNode = findById(ctx.ids.signature.c_str());
        ctx.signedInfoNode = nullptr;
        ctx.signedPropsNode = findById(ctx.ids.signedProperties.c_str());
        ctx.signatureValueNode = findById(ctx.ids.signatureValue.c_str());

        // Find SignedInfo (first child of Signature named SignedInfo)
        if (ctx.signatureNode) {
            for (xmlNodePtr c = ctx.signatureNode->children; c; c = c->next) {
                if (c->type == XML_ELEMENT_NODE && xmlStrcmp(c->name, BAD_CAST "SignedInfo") == 0) {
                    ctx.signedInfoNode = c;
                    break;
                }
            }
        }

        if (!ctx.signatureNode || !ctx.signedInfoNode || !ctx.signedPropsNode || !ctx.signatureValueNode)
            return {false, {}, "XAdES: failed to find key elements in re-parsed XML"};

        // Find DigestValue nodes in SignedInfo references
        ctx.dataRefDigestValueNode = nullptr;
        ctx.propsRefDigestValueNode = nullptr;
        for (xmlNodePtr ref = ctx.signedInfoNode->children; ref; ref = ref->next) {
            if (ref->type != XML_ELEMENT_NODE || xmlStrcmp(ref->name, BAD_CAST "Reference") != 0)
                continue;
            xmlChar* uri = xmlGetProp(ref, BAD_CAST "URI");
            if (!uri)
                continue;
            std::string thisPropsRefUri = "#" + ctx.ids.signedProperties;
            bool isProps = xmlStrcmp(uri, BAD_CAST thisPropsRefUri.c_str()) == 0;
            bool isData = xmlStrcmp(uri, BAD_CAST "") == 0 || (uri[0] != '#' && xmlStrlen(uri) > 0);
            xmlFree(uri);

            // Find DigestValue child
            for (xmlNodePtr c = ref->children; c; c = c->next) {
                if (c->type == XML_ELEMENT_NODE && xmlStrcmp(c->name, BAD_CAST "DigestValue") == 0) {
                    if (isProps)
                        ctx.propsRefDigestValueNode = c;
                    else if (isData)
                        ctx.dataRefDigestValueNode = c;
                    break;
                }
            }
        }

        if (!ctx.dataRefDigestValueNode || !ctx.propsRefDigestValueNode)
            return {false, {}, "XAdES: failed to find DigestValue nodes in re-parsed XML"};

        // 5. Compute data reference hash from re-parsed document
        if (packaging == SignaturePackaging::ENVELOPED) {
            xmlUnlinkNode(ctx.signatureNode);
            // Ensure Signature is re-linked even if canonicalization throws
            struct RelinkGuard
            {
                xmlNodePtr sig;
                xmlNodePtr parent;
                bool done = false;
                ~RelinkGuard()
                {
                    if (!done)
                        xmlAddChild(parent, sig);
                }
            } relink{ctx.signatureNode, xmlDocGetRootElement(parsedDoc)};
            auto docC14n = canonicalizeNode(parsedDoc, xmlDocGetRootElement(parsedDoc));
            xmlAddChild(xmlDocGetRootElement(parsedDoc), ctx.signatureNode);
            relink.done = true;
            auto dataHash = sha256(docC14n);
            xmlNodeSetContent(ctx.dataRefDigestValueNode, BAD_CAST base64Encode(dataHash).c_str());
        }
        // (detached: data digest already set from raw bytes, but update in re-parsed doc)
        // For detached, re-set the already-computed value
        if (packaging == SignaturePackaging::DETACHED) {
            auto dataHash = sha256(data);
            xmlNodeSetContent(ctx.dataRefDigestValueNode, BAD_CAST base64Encode(dataHash).c_str());
        }

        // 6. Compute SignedProperties and SignedInfo hashes using canonicalizeNode
        //    on the re-parsed document (Exclusive C14N within full document context)
        auto signedPropsC14n = canonicalizeNode(parsedDoc, ctx.signedPropsNode);
        auto propsHash = sha256(signedPropsC14n);
        xmlNodeSetContent(ctx.propsRefDigestValueNode, BAD_CAST base64Encode(propsHash).c_str());

        // 7. Canonicalize SignedInfo
        auto signedInfoC14n = canonicalizeNode(parsedDoc, ctx.signedInfoNode);
        auto signedInfoHash = sha256(signedInfoC14n);

        // 8. Sign with PKCS#11 token. Pass canonicalised SignedInfo as the
        //    raw "to-be-signed" bytes so hash-on-card SSCDs can use the
        //    combined CKM_SHA256_RSA_PKCS mechanism; legacy cards fall
        //    through to the pre-built DigestInfo path inside Pkcs11Token.
        auto signatureBytes =
            signHashWithToken(token, cert.get(), signedInfoHash, "SHA256", std::span<const uint8_t>{signedInfoC14n});

        if (signatureBytes.empty())
            return {false, {}, "PKCS#11 token signing returned empty signature"};

        // 9. Set SignatureValue
        std::string sigValueB64 = base64Encode(signatureBytes);
        xmlNodeSetContent(ctx.signatureValueNode, BAD_CAST sigValueB64.c_str());

        // 10. B-T: add SignatureTimeStamp
        if (level >= SignatureLevel::B_T) {
            if (tsa.url.empty())
                return {false, {}, "TSA URL is required for B-T level or above"};

            // Per ETSI EN 319 132-1 clause 6.3, the SignatureTimeStamp is
            // computed over the canonicalized <ds:SignatureValue> element.
            // Use canonicalizeNode() for correctness (includes Id attribute, proper namespace handling).
            auto c14nSigValueBytes = canonicalizeNode(ctx.doc.get(), ctx.signatureValueNode);
            std::string c14nSigValue(c14nSigValueBytes.begin(), c14nSigValueBytes.end());
            auto sigHash = sha256(reinterpret_cast<const uint8_t*>(c14nSigValue.data()), c14nSigValue.size());

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(sigHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return {false, {}, "TSA timestamp failed: " + tsaResult.errorMessage};

            // Find the xades namespace on the Signature node
            xmlNsPtr nsXades = xmlSearchNsByHref(ctx.doc.get(), ctx.signatureNode, BAD_CAST kNsXades);
            xmlNsPtr nsDs = xmlSearchNsByHref(ctx.doc.get(), ctx.signatureNode, BAD_CAST kNsDs);

            xmlNodePtr unsignedProps = ensureUnsignedProperties(ctx.signatureNode, nsXades);
            xmlNodePtr unsignedSigProps = ensureUnsignedSignatureProperties(unsignedProps, nsXades);

            // <xades:SignatureTimeStamp>
            xmlNodePtr sigTimeStamp = xmlNewChild(unsignedSigProps, nsXades, BAD_CAST "SignatureTimeStamp", nullptr);
            // <ds:CanonicalizationMethod>
            xmlNodePtr tstC14n = xmlNewChild(sigTimeStamp, nsDs, BAD_CAST "CanonicalizationMethod", nullptr);
            xmlSetProp(tstC14n, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#");
            // <xades:EncapsulatedTimeStamp>
            addChildWithText(sigTimeStamp, nsXades, "EncapsulatedTimeStamp", base64Encode(tsaResult.token));
        }

        // 11. B-LT: add revocation data
        if (level >= SignatureLevel::B_LT) {
            auto revData = collectRevocationData(token, tsa);

            if (!revData.crls.empty() || !revData.ocspResponses.empty()) {
                xmlNsPtr nsXades = xmlSearchNsByHref(ctx.doc.get(), ctx.signatureNode, BAD_CAST kNsXades);
                xmlNodePtr unsignedProps = ensureUnsignedProperties(ctx.signatureNode, nsXades);
                xmlNodePtr unsignedSigProps = ensureUnsignedSignatureProperties(unsignedProps, nsXades);

                // <xades:RevocationValues>
                xmlNodePtr revValues = xmlNewChild(unsignedSigProps, nsXades, BAD_CAST "RevocationValues", nullptr);

                if (!revData.crls.empty()) {
                    xmlNodePtr crlValues = xmlNewChild(revValues, nsXades, BAD_CAST "CRLValues", nullptr);
                    for (const auto& crl : revData.crls) {
                        addChildWithText(crlValues, nsXades, "EncapsulatedCRLValue", base64Encode(crl));
                    }
                }

                if (!revData.ocspResponses.empty()) {
                    xmlNodePtr ocspValues = xmlNewChild(revValues, nsXades, BAD_CAST "OCSPValues", nullptr);
                    for (const auto& ocsp : revData.ocspResponses) {
                        addChildWithText(ocspValues, nsXades, "EncapsulatedOCSPValue", base64Encode(ocsp));
                    }
                }
            }
        }

        // 12. B-LTA: add archive timestamp per ETSI EN 319 132-1 clause 6.4.3
        if (level >= SignatureLevel::B_LTA) {
            // Build archive timestamp input: canonicalized concatenation of
            // SignedInfo, SignatureValue, KeyInfo, unsigned properties, and
            // referenced data objects.
            std::vector<uint8_t> archiveInput;

            // 1. Canonicalized SignedInfo
            auto c14nSignedInfo = canonicalizeNode(ctx.doc.get(), ctx.signedInfoNode);
            archiveInput.insert(archiveInput.end(), c14nSignedInfo.begin(), c14nSignedInfo.end());

            // 2. Canonicalized SignatureValue
            auto c14nSigValue = canonicalizeNode(ctx.doc.get(), ctx.signatureValueNode);
            archiveInput.insert(archiveInput.end(), c14nSigValue.begin(), c14nSigValue.end());

            // 3. Canonicalized KeyInfo (if present)
            for (xmlNodePtr child = ctx.signatureNode->children; child; child = child->next) {
                if (child->type == XML_ELEMENT_NODE && xmlStrcmp(child->name, BAD_CAST "KeyInfo") == 0) {
                    auto c14nKeyInfo = canonicalizeNode(ctx.doc.get(), child);
                    archiveInput.insert(archiveInput.end(), c14nKeyInfo.begin(), c14nKeyInfo.end());
                    break;
                }
            }

            // 4. Canonicalized SignedProperties (ETSI EN 319 132-1 §5.5.2.2)
            if (ctx.signedPropsNode) {
                auto c14nSignedProps = canonicalizeNode(ctx.doc.get(), ctx.signedPropsNode);
                archiveInput.insert(archiveInput.end(), c14nSignedProps.begin(), c14nSignedProps.end());
            }

            // 5. Canonicalized unsigned properties (excluding ArchiveTimeStamp)
            xmlNsPtr nsXades = xmlSearchNsByHref(ctx.doc.get(), ctx.signatureNode, BAD_CAST kNsXades);
            xmlNsPtr nsDs = xmlSearchNsByHref(ctx.doc.get(), ctx.signatureNode, BAD_CAST kNsDs);
            xmlNodePtr unsignedProps = ensureUnsignedProperties(ctx.signatureNode, nsXades);
            xmlNodePtr unsignedSigProps = ensureUnsignedSignatureProperties(unsignedProps, nsXades);

            for (xmlNodePtr child = unsignedSigProps->children; child; child = child->next) {
                if (child->type != XML_ELEMENT_NODE)
                    continue;
                // Skip existing ArchiveTimeStamp elements
                if (xmlStrcmp(child->name, BAD_CAST "ArchiveTimeStamp") == 0)
                    continue;
                auto c14nProp = canonicalizeNode(ctx.doc.get(), child);
                archiveInput.insert(archiveInput.end(), c14nProp.begin(), c14nProp.end());
            }

            // 6. Referenced data objects
            if (packaging == SignaturePackaging::DETACHED) {
                // Detached: include raw document bytes
                archiveInput.insert(archiveInput.end(), data.begin(), data.end());
            } else {
                // Enveloped: canonicalize root with signature temporarily removed
                xmlUnlinkNode(ctx.signatureNode);
                // Ensure Signature is re-linked even if canonicalization throws
                struct RelinkGuard
                {
                    xmlNodePtr sig;
                    xmlNodePtr parent;
                    bool done = false;
                    ~RelinkGuard()
                    {
                        if (!done)
                            xmlAddChild(parent, sig);
                    }
                } relink{ctx.signatureNode, xmlDocGetRootElement(ctx.doc.get())};
                auto c14nDoc = canonicalizeNode(ctx.doc.get(), xmlDocGetRootElement(ctx.doc.get()));
                xmlAddChild(xmlDocGetRootElement(ctx.doc.get()), ctx.signatureNode);
                relink.done = true;
                archiveInput.insert(archiveInput.end(), c14nDoc.begin(), c14nDoc.end());
            }

            auto archiveHash = sha256(archiveInput);

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(archiveHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return {false, {}, "Archive TSA timestamp failed: " + tsaResult.errorMessage};

            // <xades:ArchiveTimeStamp>
            xmlNodePtr archTst = xmlNewChild(unsignedSigProps, nsXades, BAD_CAST "ArchiveTimeStamp", nullptr);
            xmlNodePtr archC14n = xmlNewChild(archTst, nsDs, BAD_CAST "CanonicalizationMethod", nullptr);
            xmlSetProp(archC14n, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#");
            addChildWithText(archTst, nsXades, "EncapsulatedTimeStamp", base64Encode(tsaResult.token));
        }

        // 13. Serialize final XML
        auto result = serializeDoc(ctx.doc.get());
        return {true, std::move(result), {}};

    } catch (const std::exception& e) {
        return {false, {}, std::string("XAdES error: ") + e.what()};
    }
}

} // namespace libresign

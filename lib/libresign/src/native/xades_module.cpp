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
#include <unordered_set>

#include "xml_raii.h"

namespace libresign {

namespace {

using namespace libresign::native_utils;
using ::libresign::XmlDocPtr;

// ---- XML namespace URIs ----

constexpr const char* kNsDs = "http://www.w3.org/2000/09/xmldsig#";
constexpr const char* kNsXades = "http://uri.etsi.org/01903/v1.3.2#";
// ETSI EN 319 162-1 (ASiC) namespace used by EN 319 132-1 §A.5 as the
// multi-signature container wrapping ds:Signature siblings when the prior
// signed payload is detached (i.e. there is no host XML document to anchor
// the new signature into).
constexpr const char* kNsAsic = "http://uri.etsi.org/02918/v1.2.1#";
// W3C XML-Signature XPath Filter 2.0 (https://www.w3.org/TR/xmldsig-filter2/).
// Used by every ENVELOPED ds:Reference produced here so the dereferenced data
// object excludes ALL ds:Signature descendants of the host document, not just
// the Signature carrying the transform (which is what the basic enveloped-
// signature transform per XMLDSig §6.6.4 does). Without this, parallel multi-
// sign ENVELOPED breaks: appending a sibling ds:Signature invalidates every
// prior signature because their canonicalised input now includes the new
// sibling. ETSI EN 319 132-1 §A.5 mandates this transform for multi-signature-
// capable ENVELOPED XAdES, and on a single-signature document the subtraction
// of /descendant::ds:Signature also excludes the self Signature, so the
// transform degrades gracefully to single-sign behaviour.
constexpr const char* kNsXpathFilter2 = "http://www.w3.org/2002/06/xmldsig-filter2";

// Percent-encode a filename for use as a ds:Reference URI attribute.
// RFC 3986 §2.3 unreserved + "." "-" "_" "~" pass through; everything
// else (spaces, "&", "#", "?", UTF-8 bytes, etc.) becomes %HH. Without
// this, filenames with special chars produce a URI that validators
// dereference incorrectly — and xmlSetProp only escapes for XML, not
// URI.
// XAdES URI filename references are single-segment URIs; every byte outside
// the RFC 3986 §2.3 unreserved set (including `/`) must be percent-encoded.
// Delegates to the shared native_utils::percentEncode with preserveSlash=false.

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
    if (packaging == SignaturePackaging::Enveloped) {
        xmlSetProp(dataRef, BAD_CAST "URI", BAD_CAST "");
        // ENVELOPED transform pipeline:
        //   1. XPath Filter 2.0 "subtract" /descendant::ds:Signature — removes
        //      EVERY ds:Signature descendant of the document root, not just
        //      this one. Multi-sign safety per ETSI EN 319 132-1 §A.5 +
        //      XMLDSig 1.1; degrades to a no-op-equivalent on single-sign
        //      documents because the only ds:Signature present IS self.
        //   2. Exclusive C14N — canonicalise the result for digesting.
        xmlNodePtr transforms = xmlNewChild(dataRef, nsDs, BAD_CAST "Transforms", nullptr);
        xmlNodePtr xpathFilterTransform = xmlNewChild(transforms, nsDs, BAD_CAST "Transform", nullptr);
        xmlSetProp(xpathFilterTransform, BAD_CAST "Algorithm", BAD_CAST kNsXpathFilter2);
        xmlNsPtr nsXpathFilter = xmlNewNs(xpathFilterTransform, BAD_CAST kNsXpathFilter2, BAD_CAST "dsf");
        xmlNodePtr xpathNode =
            xmlNewChild(xpathFilterTransform, nsXpathFilter, BAD_CAST "XPath", BAD_CAST "/descendant::ds:Signature");
        xmlSetProp(xpathNode, BAD_CAST "Filter", BAD_CAST "subtract");
        // The XPath expression body references the ds prefix, which is in
        // scope from the ancestor ds:Signature element's xmlns:ds declaration.
        // No additional xmlns:ds declaration on the XPath element is required.
        xmlNodePtr c14nTransform = xmlNewChild(transforms, nsDs, BAD_CAST "Transform", nullptr);
        xmlSetProp(c14nTransform, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#");
    } else {
        // Detached: reference is the file name, percent-encoded per RFC 3986
        const std::string encoded = percentEncode(fileName);
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

// Forward declaration — definition follows after serializeDoc() since
// the merge implementation calls serializeDoc() on its assembled document.
std::vector<uint8_t> serializeDoc(xmlDocPtr doc);

// ---- Merge two detached XAdES signature documents into an asic:Signatures wrapper ----
//
// DOM-level (not string-concatenation) merge: parse both inputs, build a
// fresh document rooted at <asic:Signatures>, and xmlCopyNode the prior
// ds:Signature children + the new ds:Signature into it. Going through the
// DOM lets libxml2 propagate namespace declarations correctly onto the
// copied subtrees (otherwise xmlns:ds vanishes when the elements lose
// their original parent context) and avoids brittle text-level splicing
// of XML declarations / whitespace.
//
// Accepts a prior that is either a single <ds:Signature> document or an
// already-wrapped <asic:Signatures> container per ETSI EN 319 162-1.
std::vector<uint8_t> mergeDetachedSignatures(std::span<const uint8_t> prior, std::span<const uint8_t> newSignature)
{
    constexpr int kSafeXmlOptions = XML_PARSE_NONET | XML_PARSE_NOCDATA;

    if (prior.size() > static_cast<size_t>(INT_MAX) || newSignature.size() > static_cast<size_t>(INT_MAX))
        throw std::runtime_error("XAdES mergeDetachedSignatures: input exceeds INT_MAX");

    XmlDocPtr priorDoc(xmlReadMemory(reinterpret_cast<const char*>(prior.data()), static_cast<int>(prior.size()),
                                     "prior.xml", nullptr, kSafeXmlOptions));
    if (!priorDoc)
        throw std::runtime_error("XAdES mergeDetachedSignatures: failed to parse prior XML");

    XmlDocPtr newDoc(xmlReadMemory(reinterpret_cast<const char*>(newSignature.data()),
                                   static_cast<int>(newSignature.size()), "new.xml", nullptr, kSafeXmlOptions));
    if (!newDoc)
        throw std::runtime_error("XAdES mergeDetachedSignatures: failed to parse new signature XML");

    xmlNodePtr priorRoot = xmlDocGetRootElement(priorDoc.get());
    xmlNodePtr newRoot = xmlDocGetRootElement(newDoc.get());
    if (!priorRoot || !newRoot)
        throw std::runtime_error("XAdES mergeDetachedSignatures: empty document");

    const bool priorIsWrapper = (xmlStrcmp(priorRoot->name, BAD_CAST "Signatures") == 0);
    const bool priorIsSignature = (xmlStrcmp(priorRoot->name, BAD_CAST "Signature") == 0);
    const bool newIsSignature = (xmlStrcmp(newRoot->name, BAD_CAST "Signature") == 0);
    if (!newIsSignature)
        throw std::runtime_error("XAdES mergeDetachedSignatures: new signature root is not ds:Signature");
    if (!priorIsWrapper && !priorIsSignature)
        throw std::runtime_error(
            "XAdES mergeDetachedSignatures: prior root is neither asic:Signatures nor ds:Signature");

    // Build the merged document fresh: a new <asic:Signatures> root with
    // asic + ds namespace declarations, then copy each signature child in.
    XmlDocPtr mergedDoc(xmlNewDoc(BAD_CAST "1.0"));
    if (!mergedDoc)
        throw std::runtime_error("XAdES mergeDetachedSignatures: xmlNewDoc() failed");

    xmlNodePtr wrapper = xmlNewNode(nullptr, BAD_CAST "Signatures");
    if (!wrapper)
        throw std::runtime_error("XAdES mergeDetachedSignatures: xmlNewNode(Signatures) failed");
    xmlDocSetRootElement(mergedDoc.get(), wrapper);

    xmlNsPtr nsAsic = xmlNewNs(wrapper, BAD_CAST kNsAsic, BAD_CAST "asic");
    if (!nsAsic)
        throw std::runtime_error("XAdES mergeDetachedSignatures: xmlNewNs(asic) failed");
    xmlSetNs(wrapper, nsAsic);
    // Declare the ds namespace on the wrapper too — every copied ds:Signature
    // child re-declares it locally (libxml2 propagates the prefix bound to
    // the original href), so this top-level declaration is mainly for
    // human-readable serialisations and validator-friendliness.
    xmlNewNs(wrapper, BAD_CAST kNsDs, BAD_CAST "ds");

    auto adoptSignature = [&](xmlNodePtr sig) {
        // xmlDocCopyNode(recursive=1) reconciles namespaces against the
        // destination document, ensuring xmlns:ds (and any xades / xadesv141
        // declarations the signature carries) survive the copy.
        xmlNodePtr copy = xmlDocCopyNode(sig, mergedDoc.get(), 1);
        if (!copy)
            throw std::runtime_error("XAdES mergeDetachedSignatures: xmlDocCopyNode() failed");
        if (!xmlAddChild(wrapper, copy)) {
            xmlFreeNode(copy);
            throw std::runtime_error("XAdES mergeDetachedSignatures: xmlAddChild() failed");
        }
    };

    if (priorIsWrapper) {
        // Re-host every existing ds:Signature child of the prior asic:Signatures.
        for (xmlNodePtr child = priorRoot->children; child; child = child->next) {
            if (child->type != XML_ELEMENT_NODE)
                continue;
            if (xmlStrcmp(child->name, BAD_CAST "Signature") != 0)
                continue;
            adoptSignature(child);
        }
    } else {
        adoptSignature(priorRoot);
    }
    adoptSignature(newRoot);

    return serializeDoc(mergedDoc.get());
}

// ---- Scan ds:Signature documents for templated Id occupancy ----
//
// DETACHED appendSigner must choose an Id suffix for the new signature
// BEFORE signing, because every templated Id (Signature-N, SignedProperties-N,
// SignatureValue-N, Reference-N) is digested as part of the signature
// itself: SignedProperties@Id is c14n'd into the SignedProperties digest;
// the URI="#SignedProperties-N" reference in SignedInfo is c14n'd into
// SignedInfo's digest; SignedInfo is what SignatureValue covers. Renaming
// these after signing invalidates the signature.
//
// Returns a set populated with every Id attribute value present on every
// element in @p priorRoot. Used by appendSigner DETACHED to compute the
// smallest free positive-integer suffix M such that all four
// "<template>-M" Ids miss the set.
std::unordered_set<std::string> collectAllIds(xmlNodePtr priorRoot)
{
    std::unordered_set<std::string> ids;
    if (!priorRoot)
        return ids;
    constexpr size_t kMaxScanDepth = 512;
    std::vector<std::pair<xmlNodePtr, size_t>> stack;
    stack.emplace_back(priorRoot, 0);
    while (!stack.empty()) {
        auto [node, depth] = stack.back();
        stack.pop_back();
        if (!node || depth > kMaxScanDepth)
            continue;
        if (node->type == XML_ELEMENT_NODE) {
            std::string idStr = native_utils::xmlAttrToString(node, "Id");
            if (!idStr.empty())
                ids.emplace(std::move(idStr));
        }
        for (xmlNodePtr c = node->children; c; c = c->next)
            stack.emplace_back(c, depth + 1);
    }
    return ids;
}

// ---- Collect every ds:Signature descendant for XPath-Filter-2.0 subtraction ----
//
// The ENVELOPED transform pipeline emits XPath-Filter-2.0 with
// `subtract /descendant::ds:Signature`. To compute the digest we must mirror
// what a validator computes: canonicalise the document with every
// ds:Signature descendant removed (not just the one being signed). The
// caller unlinks the returned nodes, canonicalises the host document, then
// re-attaches them in their original positions. Original sibling order is
// preserved by re-using xmlAddPrevSibling against the next-sibling cached
// at unlink time, falling back to xmlAddChild when the signature was the
// last child of its parent.
struct XmlNodeAnchor
{
    xmlNodePtr node = nullptr;
    xmlNodePtr parent = nullptr;
    xmlNodePtr nextSibling = nullptr; // may be nullptr if node was the last child
};

std::vector<XmlNodeAnchor> collectDsSignatureDescendants(xmlNodePtr root)
{
    std::vector<XmlNodeAnchor> hits;
    if (!root)
        return hits;

    // Iterative DFS — recursive lambdas blow stack on legal-but-deep XML.
    constexpr size_t kMaxScanDepth = 512;
    std::vector<std::pair<xmlNodePtr, size_t>> stack;
    stack.emplace_back(root, 0);
    while (!stack.empty()) {
        auto [node, depth] = stack.back();
        stack.pop_back();
        if (!node || node->type != XML_ELEMENT_NODE || depth > kMaxScanDepth)
            continue;
        if (xmlStrcmp(node->name, BAD_CAST "Signature") == 0 && node->ns && node->ns->href &&
            xmlStrcmp(node->ns->href, BAD_CAST kNsDs) == 0) {
            hits.push_back({node, node->parent, node->next});
            // Do not descend into a ds:Signature subtree — nested ds:Signature
            // inside ds:Object is legal XAdES (countersignatures) but for the
            // XPath-Filter-2.0 subtract step the outer match already removes
            // the whole subtree.
            continue;
        }
        for (xmlNodePtr c = node->children; c; c = c->next)
            stack.emplace_back(c, depth + 1);
    }
    return hits;
}

// RAII guard: unlink every ds:Signature descendant on construction, re-link
// them on destruction in their original document order. Used to bracket
// canonicalisation steps that compute the data hash / archive input under
// the XPath-Filter-2.0 "subtract /descendant::ds:Signature" view.
class DsSignatureUnlinkGuard
{
public:
    explicit DsSignatureUnlinkGuard(xmlNodePtr root) : anchors_(collectDsSignatureDescendants(root))
    {
        for (const auto& a : anchors_)
            xmlUnlinkNode(a.node);
    }
    ~DsSignatureUnlinkGuard()
    {
        // Re-link in original order; walk forward so each insertion lands at
        // its original sibling position.
        for (const auto& a : anchors_) {
            if (a.nextSibling)
                xmlAddPrevSibling(a.nextSibling, a.node);
            else if (a.parent)
                xmlAddChild(a.parent, a.node);
        }
    }

    DsSignatureUnlinkGuard(const DsSignatureUnlinkGuard&) = delete;
    DsSignatureUnlinkGuard& operator=(const DsSignatureUnlinkGuard&) = delete;
    DsSignatureUnlinkGuard(DsSignatureUnlinkGuard&&) = delete;
    DsSignatureUnlinkGuard& operator=(DsSignatureUnlinkGuard&&) = delete;

private:
    std::vector<XmlNodeAnchor> anchors_;
};

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
//
// @par DETACHED packaging Reference URI constraint
// For SignaturePackaging::DETACHED the emitted XML carries a
// `ds:Reference URI="<percent-encoded basename>"` pointing at @p fileName.
// Conformant XAdES validators (EU DSS, ETSI test bench, Adobe) resolve
// that URI relative to the on-disk location of the `.xml` signature
// file. The original payload bytes MUST therefore be co-located with
// the produced signature under the exact filename supplied here; if
// the recipient receives only the `.xml`, validation aborts at the
// reference-resolution step before any cryptographic check runs.
SigningResult XAdESModule::sign(const std::vector<uint8_t>& data, const std::string& fileName, Pkcs11Token& token,
                                SignatureLevel level, SignaturePackaging packaging, const TSAConfig& tsa)
{
    return signWithSuffix(data, fileName, token, level, packaging, tsa, std::string_view{});
}

SigningResult XAdESModule::signWithSuffix(const std::vector<uint8_t>& data, const std::string& fileName,
                                          Pkcs11Token& token, SignatureLevel level, SignaturePackaging packaging,
                                          const TSAConfig& tsa, std::string_view forcedIdSuffix)
{
    if (data.empty())
        return makeFailure(SignFailureKind::InvalidDocument, "Input data is empty");

    try {
        native_utils::ensureXmlInitialized();

        // 1. Get certificate and chain from token
        auto certDer = token.certificate();
        if (certDer.empty())
            return makeFailure(SignFailureKind::CardError, "No certificate found on token");

        X509Ptr cert = parseCert(certDer);
        auto chainDer = token.certificateChain();
        if (chainDer.empty())
            chainDer.push_back(certDer); // at minimum include signer cert

        // For ENVELOPED re-sign, the input XML may already contain a previous
        // <ds:Signature> with Id="Signature-1" etc. Pick the smallest positive
        // integer suffix not yet present so every Id attribute remains unique
        // (W3C XML 1.0 §3.3.1). DETACHED never has an input XML, so "1" is
        // the natural default — except when the caller (appendSigner DETACHED)
        // has already computed a non-colliding suffix against the prior
        // wrapper, in which case @p forcedIdSuffix overrides the default and
        // also short-circuits the ENVELOPED scan below.
        std::string idSuffix = forcedIdSuffix.empty() ? std::string("1") : std::string(forcedIdSuffix);
        std::unique_ptr<xmlDoc, decltype(&xmlFreeDoc)> origDocPtr(nullptr, &xmlFreeDoc);
        constexpr int kSafeXmlOptions = XML_PARSE_NONET | XML_PARSE_NOCDATA;
        if (packaging == SignaturePackaging::Enveloped) {
            if (data.size() > static_cast<size_t>(INT_MAX))
                return makeFailure(SignFailureKind::InvalidDocument, "XAdES enveloped: input XML exceeds INT_MAX");
            xmlDocPtr origDoc = xmlReadMemory(reinterpret_cast<const char*>(data.data()), static_cast<int>(data.size()),
                                              nullptr, nullptr, kSafeXmlOptions);
            if (!origDoc)
                return makeFailure(SignFailureKind::InvalidDocument, "XAdES enveloped: failed to parse input XML");
            origDocPtr.reset(origDoc);
        }
        if (packaging == SignaturePackaging::Enveloped && forcedIdSuffix.empty()) {
            xmlDocPtr origDoc = origDocPtr.get();

            // Collect every Id attribute value on every element into a hash
            // set, then mint suffix N such that all four templated Ids
            // (Signature-N / SignedProperties-N / SignatureValue-N /
            // Reference-N) miss the set. XML allows ANY element to carry an
            // Id attribute (W3C XML 1.0 §3.3.1), not just ds:Signature
            // descendants, so a prefix-only scan could collide with a
            // generic Id (e.g. <ds:Object Id="Signature-1"> on an unrelated
            // path) on hostile input.
            //
            // Iterative walk via an explicit work stack — the previous
            // recursive lambda would stack-overflow on pathologically nested
            // XML (libxml2 caps depth at ~256 in the default parser, but
            // every additional std::function frame here is ~200 bytes, so
            // 256 levels × N nested Ids each comfortably exceeds a default
            // 8 MiB stack on Linux). The cap below is a second line of
            // defense even though the libxml2 parser already enforces one.
            constexpr size_t kMaxXmlScanDepth = 512;
            std::unordered_set<std::string> existingIds;
            std::vector<std::pair<xmlNodePtr, size_t>> stack;
            stack.reserve(kMaxXmlScanDepth);
            stack.emplace_back(xmlDocGetRootElement(origDoc), 0);
            while (!stack.empty()) {
                auto [node, depth] = stack.back();
                stack.pop_back();
                if (!node || depth > kMaxXmlScanDepth)
                    continue;
                if (node->type == XML_ELEMENT_NODE) {
                    // Centralised NUL-rejecting attr reader — see
                    // native_utils::xmlAttrToString for why we never use the
                    // raw std::string(const char*) constructor on libxml2
                    // output.
                    std::string idStr = native_utils::xmlAttrToString(node, "Id");
                    if (!idStr.empty())
                        existingIds.emplace(std::move(idStr));
                }
                for (xmlNodePtr c = node->children; c; c = c->next)
                    stack.emplace_back(c, depth + 1);
            }

            // Mint smallest positive N such that all four templated Ids
            // miss the collected set. The 10000 cap rejects pathological
            // input — a XAdES document with that many prior signatures is
            // not realistic.
            constexpr int kMaxIdSuffixScan = 10000;
            int n = 1;
            for (; n <= kMaxIdSuffixScan; ++n) {
                const std::string sn = std::to_string(n);
                if (!existingIds.contains("Signature-" + sn) && !existingIds.contains("SignedProperties-" + sn) &&
                    !existingIds.contains("SignatureValue-" + sn) && !existingIds.contains("Reference-" + sn))
                    break;
            }
            if (n > kMaxIdSuffixScan)
                return makeFailure(SignFailureKind::InvalidInput,
                                   "XAdES enveloped: Id collision-avoidance exceeded 10000 iterations");
            idSuffix = std::to_string(n);
        }
        SignatureIds ids = makeSignatureIds(idSuffix);

        // 2. Build the XML Signature structure with the chosen IDs
        auto ctx = buildSignatureXml(certDer, cert.get(), chainDer, fileName, packaging, ids);

        // 3. For enveloped: embed Signature into original XML.
        //    For detached: set data digest from raw bytes.
        if (packaging == SignaturePackaging::Enveloped) {
            xmlNodePtr sigNode = xmlDocGetRootElement(ctx.doc.get());
            xmlUnlinkNode(sigNode);
            xmlNodePtr origRoot = xmlDocGetRootElement(origDocPtr.get());
            if (!xmlAddChild(origRoot, sigNode))
                return makeFailure(SignFailureKind::XmlSerializationError,
                                   "XAdES enveloped: failed to add Signature to document");
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
            return makeFailure(SignFailureKind::XmlSerializationError, "XAdES: serialized XML exceeds INT_MAX");
        xmlDocPtr parsedDoc = xmlReadMemory(reinterpret_cast<const char*>(tempXml.data()),
                                            static_cast<int>(tempXml.size()), nullptr, nullptr, kSafeXmlOptions);
        if (!parsedDoc)
            return makeFailure(SignFailureKind::XmlSerializationError, "XAdES: failed to re-parse serialized XML");
        ctx.doc.reset(parsedDoc);

        // Find key nodes in the re-parsed document by Id attributes.
        //
        // Iterative DFS with an explicit work stack — see the matching cap
        // and rationale on the multi-sign Id scan above (kMaxXmlScanDepth).
        // Re-stating: even though libxml2 enforces XML_MAX_DEPTH (~256) at
        // parse time, each std::function-bound recursive lambda frame here
        // costs enough stack that a deep-but-legal document could still blow
        // an 8 MiB stack. The cap is defence-in-depth.
        xmlNodePtr parsedRoot = xmlDocGetRootElement(parsedDoc);
        constexpr size_t kMaxXmlScanDepthFindById = 512;
        auto findById = [&](const char* id) -> xmlNodePtr {
            std::vector<std::pair<xmlNodePtr, size_t>> stack;
            stack.reserve(kMaxXmlScanDepthFindById);
            stack.emplace_back(parsedRoot, 0);
            while (!stack.empty()) {
                auto [node, depth] = stack.back();
                stack.pop_back();
                if (!node || node->type != XML_ELEMENT_NODE || depth > kMaxXmlScanDepthFindById)
                    continue;
                xmlChar* attr = xmlGetProp(node, BAD_CAST "Id");
                if (attr) {
                    bool match = xmlStrcmp(attr, BAD_CAST id) == 0;
                    xmlFree(attr);
                    if (match)
                        return node;
                }
                for (xmlNodePtr child = node->children; child; child = child->next)
                    stack.emplace_back(child, depth + 1);
            }
            return nullptr;
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
            return makeFailure(SignFailureKind::XmlSerializationError,
                               "XAdES: failed to find key elements in re-parsed XML");

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
            return makeFailure(SignFailureKind::XmlSerializationError,
                               "XAdES: failed to find DigestValue nodes in re-parsed XML");

        // 5. Compute data reference hash from re-parsed document. The
        // XPath-Filter-2.0 transform subtracts EVERY ds:Signature descendant
        // (including any prior signatures from a multi-sign chain plus the
        // one being currently built), so the digest input is the host
        // document with every ds:Signature stripped. DsSignatureUnlinkGuard
        // unlinks them all, c14n runs, and the guard re-attaches them in
        // their original positions on scope exit (including on throw).
        if (packaging == SignaturePackaging::Enveloped) {
            xmlNodePtr docRoot = xmlDocGetRootElement(parsedDoc);
            std::vector<uint8_t> docC14n;
            {
                DsSignatureUnlinkGuard guard(docRoot);
                docC14n = canonicalizeNode(parsedDoc, docRoot);
            }
            auto dataHash = sha256(docC14n);
            xmlNodeSetContent(ctx.dataRefDigestValueNode, BAD_CAST base64Encode(dataHash).c_str());
        }
        // (detached: data digest already set from raw bytes, but update in re-parsed doc)
        // For detached, re-set the already-computed value
        if (packaging == SignaturePackaging::Detached) {
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
            return makeFailure(SignFailureKind::CardError, "PKCS#11 token signing returned empty signature");

        // 9. Set SignatureValue
        std::string sigValueB64 = base64Encode(signatureBytes);
        xmlNodeSetContent(ctx.signatureValueNode, BAD_CAST sigValueB64.c_str());

        // 10. B-T: add SignatureTimeStamp
        if (level >= SignatureLevel::B_T) {
            if (tsa.url.empty())
                return makeFailure(SignFailureKind::InvalidInput, "TSA URL is required for B-T level or above");

            // Per ETSI EN 319 132-1 clause 6.3, the SignatureTimeStamp is
            // computed over the canonicalized <ds:SignatureValue> element.
            // Use canonicalizeNode() for correctness (includes Id attribute, proper namespace handling).
            auto c14nSigValueBytes = canonicalizeNode(ctx.doc.get(), ctx.signatureValueNode);
            std::string c14nSigValue(c14nSigValueBytes.begin(), c14nSigValueBytes.end());
            auto sigHash = sha256(reinterpret_cast<const uint8_t*>(c14nSigValue.data()), c14nSigValue.size());

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(sigHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return makeFailure(SignFailureKind::TsaUnreachable, "TSA timestamp failed: " + tsaResult.errorMessage);

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
            if (auto failure = revocationFailClosed(revData))
                return *failure;

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

        // 12. B-LTA: add archive timestamp per ETSI EN 319 132-1 §5.5.2.2
        //
        // The message imprint input is the concatenation, in this order, of
        // the canonicalized forms of:
        //   1. The referenced data objects obtained by dereferencing each
        //      ds:Reference in ds:SignedInfo (and applying its transforms),
        //      in document order.
        //   2. ds:SignedInfo.
        //   3. ds:SignatureValue.
        //   4. ds:KeyInfo, if present.
        //   5. The children of xades:UnsignedSignatureProperties other than
        //      the xadesv141:ArchiveTimeStamp being computed, in document
        //      order.
        //   6. Any ds:Object element other than the one carrying
        //      xades:QualifyingProperties, in document order (none in our
        //      output — the only ds:Object we emit carries QualifyingProperties,
        //      so this step is empty).
        //
        // Note: xades:SignedProperties is NOT concatenated separately —
        // it is covered transitively via the ds:Reference to
        // "#SignedProperties-N" processed in step 1.
        if (level >= SignatureLevel::B_LTA) {
            std::vector<uint8_t> archiveInput;

            xmlNsPtr nsXades = xmlSearchNsByHref(ctx.doc.get(), ctx.signatureNode, BAD_CAST kNsXades);
            xmlNsPtr nsDs = xmlSearchNsByHref(ctx.doc.get(), ctx.signatureNode, BAD_CAST kNsDs);

            // Step 1: ds:Reference referenced data objects in document order.
            // Our SignedInfo emits the data reference first (URI="" or URI=filename)
            // then the SignedProperties reference (URI="#SignedProperties-N",
            // Type="...#SignedProperties"). We must walk SignedInfo in document
            // order and, for each ds:Reference, materialise the referenced data
            // object after transforms.
            const std::string propsRefUri = "#" + ctx.ids.signedProperties;
            for (xmlNodePtr ref = ctx.signedInfoNode->children; ref; ref = ref->next) {
                if (ref->type != XML_ELEMENT_NODE || xmlStrcmp(ref->name, BAD_CAST "Reference") != 0)
                    continue;

                xmlChar* uriAttr = xmlGetProp(ref, BAD_CAST "URI");
                const std::string uri = uriAttr ? std::string(reinterpret_cast<const char*>(uriAttr)) : std::string();
                if (uriAttr)
                    xmlFree(uriAttr);

                if (uri == propsRefUri) {
                    // SignedProperties reference: dereference returns the
                    // xades:SignedProperties element; the only transform applied
                    // is exclusive c14n, so output is the canonicalised element.
                    if (ctx.signedPropsNode) {
                        auto c14nSignedProps = canonicalizeNode(ctx.doc.get(), ctx.signedPropsNode);
                        archiveInput.insert(archiveInput.end(), c14nSignedProps.begin(), c14nSignedProps.end());
                    }
                } else {
                    // Data reference: in ENVELOPED mode the XPath-Filter-2.0
                    // transform strips every ds:Signature subtree before
                    // c14n; in DETACHED mode the dereferenced object is the
                    // raw document bytes (no transform alters them in our
                    // pipeline). DsSignatureUnlinkGuard mirrors the validator
                    // view across the canonicalisation call and re-attaches
                    // on scope exit (RAII, exception-safe).
                    if (packaging == SignaturePackaging::Detached) {
                        archiveInput.insert(archiveInput.end(), data.begin(), data.end());
                    } else {
                        xmlNodePtr docRoot = xmlDocGetRootElement(ctx.doc.get());
                        std::vector<uint8_t> c14nDoc;
                        {
                            DsSignatureUnlinkGuard guard(docRoot);
                            c14nDoc = canonicalizeNode(ctx.doc.get(), docRoot);
                        }
                        archiveInput.insert(archiveInput.end(), c14nDoc.begin(), c14nDoc.end());
                    }
                }
            }

            // Step 2: ds:SignedInfo.
            auto c14nSignedInfo = canonicalizeNode(ctx.doc.get(), ctx.signedInfoNode);
            archiveInput.insert(archiveInput.end(), c14nSignedInfo.begin(), c14nSignedInfo.end());

            // Step 3: ds:SignatureValue.
            auto c14nSigValue = canonicalizeNode(ctx.doc.get(), ctx.signatureValueNode);
            archiveInput.insert(archiveInput.end(), c14nSigValue.begin(), c14nSigValue.end());

            // Step 4: ds:KeyInfo (if present).
            for (xmlNodePtr child = ctx.signatureNode->children; child; child = child->next) {
                if (child->type == XML_ELEMENT_NODE && xmlStrcmp(child->name, BAD_CAST "KeyInfo") == 0) {
                    auto c14nKeyInfo = canonicalizeNode(ctx.doc.get(), child);
                    archiveInput.insert(archiveInput.end(), c14nKeyInfo.begin(), c14nKeyInfo.end());
                    break;
                }
            }

            // Step 5: UnsignedSignatureProperties children excluding the
            // ArchiveTimeStamp being computed, in document order.
            xmlNodePtr unsignedProps = ensureUnsignedProperties(ctx.signatureNode, nsXades);
            xmlNodePtr unsignedSigProps = ensureUnsignedSignatureProperties(unsignedProps, nsXades);

            for (xmlNodePtr child = unsignedSigProps->children; child; child = child->next) {
                if (child->type != XML_ELEMENT_NODE)
                    continue;
                if (xmlStrcmp(child->name, BAD_CAST "ArchiveTimeStamp") == 0)
                    continue;
                auto c14nProp = canonicalizeNode(ctx.doc.get(), child);
                archiveInput.insert(archiveInput.end(), c14nProp.begin(), c14nProp.end());
            }

            // Step 6: ds:Object elements other than the one containing
            // QualifyingProperties — none in our output.

            auto archiveHash = sha256(archiveInput);

            TSAClient tsaClient;
            auto tsaResult = tsaClient.timestamp(archiveHash, toTsaRequest(tsa));
            if (!tsaResult.success)
                return makeFailure(SignFailureKind::TsaUnreachable,
                                   "Archive TSA timestamp failed: " + tsaResult.errorMessage);

            // <xades:ArchiveTimeStamp>
            xmlNodePtr archTst = xmlNewChild(unsignedSigProps, nsXades, BAD_CAST "ArchiveTimeStamp", nullptr);
            xmlNodePtr archC14n = xmlNewChild(archTst, nsDs, BAD_CAST "CanonicalizationMethod", nullptr);
            xmlSetProp(archC14n, BAD_CAST "Algorithm", BAD_CAST "http://www.w3.org/2001/10/xml-exc-c14n#");
            addChildWithText(archTst, nsXades, "EncapsulatedTimeStamp", base64Encode(tsaResult.token));
        }

        // 13. Serialize final XML
        auto result = serializeDoc(ctx.doc.get());
        return makeSuccess(std::move(result));

    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("XAdES error: ") + e.what());
    }
}

// ---- XAdESModule::appendSigner ----

SigningResult XAdESModule::appendSigner(std::span<const uint8_t> prior, std::span<const uint8_t> originalDoc,
                                        const std::string& fileName, Pkcs11Token& token, SignatureLevel level,
                                        const TSAConfig& tsa)
{
    if (prior.empty())
        return makeFailure(SignFailureKind::InvalidDocument, "XAdES appendSigner: empty prior");

    try {
        native_utils::ensureXmlInitialized();

        // Detect prior shape from the XML root element.
        //
        // - root == ds:Signature   -> DETACHED single-signature input
        // - root == asic:Signatures -> DETACHED multi-sig container
        //                              (already wrapped per EN 319 162-1)
        // - anything else           -> ENVELOPED (host XML carries the
        //                              ds:Signature subtree(s) as descendants)
        if (prior.size() > static_cast<size_t>(INT_MAX))
            return makeFailure(SignFailureKind::InvalidDocument, "XAdES appendSigner: prior exceeds INT_MAX");

        constexpr int kSafeXmlOptions = XML_PARSE_NONET | XML_PARSE_NOCDATA;
        XmlDocPtr probeDoc(xmlReadMemory(reinterpret_cast<const char*>(prior.data()), static_cast<int>(prior.size()),
                                         "prior.xml", nullptr, kSafeXmlOptions));
        if (!probeDoc)
            return makeFailure(SignFailureKind::InvalidDocument, "XAdES appendSigner: prior XML parse failed");

        xmlNodePtr root = xmlDocGetRootElement(probeDoc.get());
        if (!root)
            return makeFailure(SignFailureKind::InvalidDocument, "XAdES appendSigner: prior has no root element");

        const bool isDsSignatureRoot = (xmlStrcmp(root->name, BAD_CAST "Signature") == 0);
        const bool isAsicSignaturesRoot = (xmlStrcmp(root->name, BAD_CAST "Signatures") == 0);
        const bool detachedShape = isDsSignatureRoot || isAsicSignaturesRoot;

        // Probe document done — release before delegating to sign(), which
        // performs its own parsing pass. Keeps the libxml2 allocator
        // footprint bounded for the multi-MB document case.
        probeDoc.reset();

        if (detachedShape) {
            if (originalDoc.empty())
                return makeFailure(SignFailureKind::InvalidInput,
                                   "XAdES detached appendSigner requires originalDocument");

            // 1. Scan the prior wrapper for occupied Id attribute values and
            //    pick the smallest positive integer suffix M such that none
            //    of Signature-M / SignedProperties-M / SignatureValue-M /
            //    Reference-M collide. This MUST happen before signing because
            //    every templated Id contributes to the digested
            //    SignedProperties + SignedInfo bytes — renaming Ids after
            //    signing invalidates the SignatureValue.
            //
            //    Re-parse the prior here (the probeDoc was already released)
            //    so we walk the actual DOM rather than relying on textual
            //    pattern matching that could miss Ids carried on unrelated
            //    elements (W3C XML 1.0 §3.3.1 lets any element carry an
            //    Id attribute).
            XmlDocPtr priorIdScanDoc(xmlReadMemory(reinterpret_cast<const char*>(prior.data()),
                                                   static_cast<int>(prior.size()), "prior.xml", nullptr,
                                                   kSafeXmlOptions));
            if (!priorIdScanDoc)
                return makeFailure(SignFailureKind::InvalidDocument,
                                   "XAdES detached appendSigner: prior re-parse for Id scan failed");
            auto occupiedIds = collectAllIds(xmlDocGetRootElement(priorIdScanDoc.get()));
            priorIdScanDoc.reset();

            std::string newSuffix;
            constexpr int kMaxIdSuffixScan = 10000;
            for (int n = 1; n <= kMaxIdSuffixScan; ++n) {
                const std::string sn = std::to_string(n);
                if (!occupiedIds.contains("Signature-" + sn) && !occupiedIds.contains("SignedProperties-" + sn) &&
                    !occupiedIds.contains("SignatureValue-" + sn) && !occupiedIds.contains("Reference-" + sn)) {
                    newSuffix = sn;
                    break;
                }
            }
            if (newSuffix.empty())
                return makeFailure(SignFailureKind::InvalidInput,
                                   "XAdES detached appendSigner: Id collision-avoidance exceeded 10000 iterations");

            // 2. Build a fresh standalone DETACHED XAdES signature over the
            //    original payload with the chosen Id suffix. The signWithSuffix
            //    path already handles certificate retrieval, hashing, TSA, LT
            //    and LTA promotion. The returned blob is a single
            //    <ds:Signature> XML document with non-colliding Ids.
            std::vector<uint8_t> originalCopy(originalDoc.begin(), originalDoc.end());
            auto newSigResult = this->signWithSuffix(originalCopy, fileName, token, level, SignaturePackaging::Detached,
                                                     tsa, newSuffix);
            if (!newSigResult.success)
                return newSigResult;

            // 3. Merge: build (or extend) the <asic:Signatures> wrapper
            //    holding the prior signature(s) + the new one.
            auto merged = mergeDetachedSignatures(prior, std::span<const uint8_t>{newSigResult.signedDocument});
            return makeSuccess(std::move(merged));
        }

        // ENVELOPED prior: delegate to the existing auto-detect multi-sign
        // path inside sign(). It scans the host document for existing
        // Signature-N / SignedProperties-N / ... Id attributes and picks the
        // next free integer suffix, so the new ds:Signature lands as a
        // sibling at the document root without colliding with any prior IDs.
        std::vector<uint8_t> priorCopy(prior.begin(), prior.end());
        return this->sign(priorCopy, fileName, token, level, SignaturePackaging::Enveloped, tsa);

    } catch (const std::exception& e) {
        return makeFailure(SignFailureKind::EngineError, std::string("XAdES appendSigner error: ") + e.what());
    }
}

} // namespace libresign

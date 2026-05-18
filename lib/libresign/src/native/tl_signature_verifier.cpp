// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "tl_signature_verifier.h"
#include "native_utils.h"
#include "xml_raii.h"

#include <libxml/c14n.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <openssl/evp.h>
#include <openssl/x509.h>

#include <cstring>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace libresign {

namespace {

using native_utils::base64Decode;

constexpr const char* kNsDs = "http://www.w3.org/2000/09/xmldsig#";

// ---- RAII helper for xmlChar* allocated by xmlGetProp / xmlNodeGetContent ----

struct XmlCharDeleter
{
    void operator()(xmlChar* p) const
    {
        if (p)
            xmlFree(p);
    }
};
using XmlCharPtr = std::unique_ptr<xmlChar, XmlCharDeleter>;

} // namespace

// ---- Public URI tables (declared in the header) ----
//
// Two intentionally-disjoint tables. The XMLDSig spec puts digest method
// URIs and signature method URIs in different element @Algorithm slots
// (ds:DigestMethod vs ds:SignatureMethod) — letting either lookup
// accept the other's URIs is a category error that previously could
// have admitted, e.g. `rsa-sha256` as a digest URI or `xmlenc#sha256`
// as a signature URI. Substring matching is also avoided — every URI
// must match a literal entry. SHA-1 is rejected outright because the
// ETSI TL profile mandates SHA-256+ and SHA-1 is exploitable via
// chosen-prefix collisions in the c14n'd SignedInfo surface.

const EVP_MD* digestFromDigestMethodUri(const std::string& uri)
{
    if (uri == "http://www.w3.org/2001/04/xmlenc#sha256")
        return EVP_sha256();
    if (uri == "http://www.w3.org/2001/04/xmldsig-more#sha384")
        return EVP_sha384();
    if (uri == "http://www.w3.org/2001/04/xmlenc#sha512")
        return EVP_sha512();
    return nullptr;
}

std::pair<const EVP_MD*, int> digestFromSignatureMethodUri(const std::string& uri)
{
    if (uri == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256")
        return {EVP_sha256(), EVP_PKEY_RSA};
    if (uri == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384")
        return {EVP_sha384(), EVP_PKEY_RSA};
    if (uri == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")
        return {EVP_sha512(), EVP_PKEY_RSA};
    if (uri == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")
        return {EVP_sha256(), EVP_PKEY_EC};
    if (uri == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384")
        return {EVP_sha384(), EVP_PKEY_EC};
    if (uri == "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512")
        return {EVP_sha512(), EVP_PKEY_EC};
    return {nullptr, 0};
}

namespace {

// ---- Safe Id-attribute lookup ----
//
// Walks the document looking for the first element whose `Id` attribute
// (literal name `Id`, as used in xmldsig) equals the supplied id string.
// Used as a fallback when `xmlGetID` (which respects DTD-declared ID
// attributes and `xml:id`) returns nothing. Treats `id` as an opaque
// literal — never builds an XPath expression — so it cannot be tricked
// by metacharacters in the URI fragment (the prior `//*[@Id='" + id + "']`
// expression was an XPath-injection sink).
xmlNodePtr findElementByIdAttr(xmlNodePtr root, const xmlChar* id)
{
    if (!root || !id)
        return nullptr;
    for (xmlNodePtr cur = root; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE) {
            for (xmlAttrPtr attr = cur->properties; attr; attr = attr->next) {
                if (xmlStrcmp(attr->name, BAD_CAST "Id") == 0) {
                    XmlCharPtr val(xmlNodeListGetString(cur->doc, attr->children, 1));
                    if (val && xmlStrcmp(val.get(), id) == 0)
                        return cur;
                }
            }
            if (xmlNodePtr hit = findElementByIdAttr(cur->children, id))
                return hit;
        }
    }
    return nullptr;
}

// ---- XPath helper: find nodes with ds: namespace ----

xmlNodePtr findDsChild(xmlNodePtr parent, const char* localName)
{
    for (xmlNodePtr cur = parent->children; cur; cur = cur->next) {
        if (cur->type == XML_ELEMENT_NODE && cur->ns && cur->ns->href &&
            std::strcmp(reinterpret_cast<const char*>(cur->ns->href), kNsDs) == 0 &&
            xmlStrcmp(cur->name, BAD_CAST localName) == 0) {
            return cur;
        }
    }
    return nullptr;
}

// ---- Node text / attribute extraction (NUL-rejecting) ----
//
// Delegate to the shared helpers in native_utils. The previous local
// `nodeText` / `nodeAttr` used the convenience `std::string(const
// char*)` constructor, which silently truncates at the first embedded
// NUL — so any post-extraction digest would have run over a different
// payload than the one the upstream XML carried. The shared helpers
// reject embedded NULs with std::runtime_error.

std::string nodeText(xmlNodePtr node)
{
    return native_utils::xmlContentToString(node);
}

std::string nodeAttr(xmlNodePtr node, const char* attrName)
{
    return native_utils::xmlAttrToString(node, attrName);
}

// ---- Find the document-root-level ds:Signature element ----
//
// XPath is anchored at /*/ds:Signature — direct-child-of-root only —
// to defeat the signature-wrapping attack class where a hostile XML
// embeds an additional ds:Signature deep inside the body that the
// verifier accidentally picks up as authoritative while the genuine
// root-level signature actually covers different content. We also
// refuse documents that carry multiple root-level signatures: a
// well-formed ETSI TL has exactly one. Empty `errorOut` on success.
xmlNodePtr findSignatureNode(xmlDocPtr doc, std::string& errorOut)
{
    XPathCtxPtr ctx(xmlXPathNewContext(doc));
    if (!ctx) {
        errorOut = "xmlXPathNewContext failed";
        return nullptr;
    }
    xmlXPathRegisterNs(ctx.get(), BAD_CAST "ds", BAD_CAST kNsDs);

    XPathObjPtr obj(xmlXPathEvalExpression(BAD_CAST "/*/ds:Signature", ctx.get()));
    if (!obj || !obj->nodesetval || obj->nodesetval->nodeNr == 0) {
        errorOut = "no ds:Signature element found at document root";
        return nullptr;
    }
    if (obj->nodesetval->nodeNr > 1) {
        errorOut = "trust list carries " + std::to_string(obj->nodesetval->nodeNr) +
                   " ds:Signature elements at document root; expected exactly one";
        return nullptr;
    }
    return obj->nodesetval->nodeTab[0];
}

// ---- Canonicalize a subtree using Exclusive C14N ----
// (Same pattern as xades_module.cpp canonicalizeNode)

std::vector<uint8_t> canonicalizeSubtree(xmlDocPtr doc, xmlNodePtr node)
{
    XPathCtxPtr xpathCtx(xmlXPathNewContext(doc));
    if (!xpathCtx)
        return {};

    xpathCtx->node = node;
    XPathObjPtr xpathObj(
        xmlXPathEvalExpression(BAD_CAST "(. | ./descendant::* | ./descendant::text() | ./@* | ./descendant::*/@* "
                                        "| ./namespace::* | ./descendant::*/namespace::*)",
                               xpathCtx.get()));

    if (!xpathObj || !xpathObj->nodesetval)
        return {};

    xmlChar* buf = nullptr;
    int size = xmlC14NDocDumpMemory(doc, xpathObj->nodesetval, XML_C14N_EXCLUSIVE_1_0, nullptr, 0, &buf);

    if (size < 0 || !buf) {
        if (buf)
            xmlFree(buf);
        return {};
    }

    std::vector<uint8_t> result(buf, buf + size);
    xmlFree(buf);
    return result;
}

// ---- Canonicalize entire document using Exclusive C14N ----

std::vector<uint8_t> canonicalizeDoc(xmlDocPtr doc)
{
    xmlChar* buf = nullptr;
    int size = xmlC14NDocDumpMemory(doc, nullptr, XML_C14N_EXCLUSIVE_1_0, nullptr, 0, &buf);
    if (size < 0 || !buf) {
        if (buf)
            xmlFree(buf);
        return {};
    }

    std::vector<uint8_t> result(buf, buf + size);
    xmlFree(buf);
    return result;
}

} // namespace

bool TlSignatureVerifier::verify(std::span<const uint8_t> xmlData, std::span<const uint8_t> signingCertDer)
{
    error.clear();

    if (xmlData.empty()) {
        error = "empty XML data";
        return false;
    }
    if (signingCertDer.empty()) {
        error = "empty signing certificate";
        return false;
    }

    native_utils::ensureXmlInitialized();

    // Parse the XML document
    XmlDocPtr doc(xmlReadMemory(reinterpret_cast<const char*>(xmlData.data()), static_cast<int>(xmlData.size()),
                                nullptr, nullptr, XML_PARSE_NONET | XML_PARSE_NOCDATA));
    if (!doc) {
        error = "failed to parse XML document";
        return false;
    }

    // Find ds:Signature
    xmlNodePtr sigNode = findSignatureNode(doc.get(), error);
    if (!sigNode) {
        // `error` populated by findSignatureNode with the precise reason
        // (none-found / multiple-found / xpath-context-init-failure).
        return false;
    }

    // Navigate: ds:Signature -> ds:SignedInfo
    xmlNodePtr signedInfoNode = findDsChild(sigNode, "SignedInfo");
    if (!signedInfoNode) {
        error = "no ds:SignedInfo element found";
        return false;
    }

    // Get ds:SignatureValue
    xmlNodePtr sigValueNode = findDsChild(sigNode, "SignatureValue");
    if (!sigValueNode) {
        error = "no ds:SignatureValue element found";
        return false;
    }
    std::vector<uint8_t> signatureValue = base64Decode(nodeText(sigValueNode));
    if (signatureValue.empty()) {
        error = "failed to decode ds:SignatureValue";
        return false;
    }

    // CanonicalizationMethod is expected to be Exclusive C14N; we always use it.

    // Get ds:SignatureMethod
    xmlNodePtr sigMethodNode = findDsChild(signedInfoNode, "SignatureMethod");
    if (!sigMethodNode) {
        error = "no ds:SignatureMethod element found";
        return false;
    }
    std::string sigMethodUri = nodeAttr(sigMethodNode, "Algorithm");
    auto [sigMd, expectedKeyTypeNid] = digestFromSignatureMethodUri(sigMethodUri);
    if (!sigMd) {
        error = "unsupported signature algorithm: " + sigMethodUri;
        return false;
    }

    // ---- 1. Reference Validation ----
    // Iterate over ds:Reference elements in ds:SignedInfo
    for (xmlNodePtr refNode = signedInfoNode->children; refNode; refNode = refNode->next) {
        if (refNode->type != XML_ELEMENT_NODE)
            continue;
        if (!refNode->ns || !refNode->ns->href)
            continue;
        if (std::strcmp(reinterpret_cast<const char*>(refNode->ns->href), kNsDs) != 0)
            continue;
        if (xmlStrcmp(refNode->name, BAD_CAST "Reference") != 0)
            continue;

        std::string uri = nodeAttr(refNode, "URI");

        // Get ds:DigestMethod
        xmlNodePtr digestMethodNode = findDsChild(refNode, "DigestMethod");
        if (!digestMethodNode) {
            error = "ds:Reference missing ds:DigestMethod";
            return false;
        }
        std::string digestMethodUri = nodeAttr(digestMethodNode, "Algorithm");
        const EVP_MD* refMd = digestFromDigestMethodUri(digestMethodUri);
        if (!refMd) {
            error = "unsupported digest algorithm: " + digestMethodUri;
            return false;
        }

        // Get expected digest
        xmlNodePtr digestValueNode = findDsChild(refNode, "DigestValue");
        if (!digestValueNode) {
            error = "ds:Reference missing ds:DigestValue";
            return false;
        }
        std::vector<uint8_t> expectedDigest = base64Decode(nodeText(digestValueNode));
        if (expectedDigest.empty()) {
            error = "failed to decode ds:DigestValue";
            return false;
        }

        // Determine transforms
        bool hasEnvelopedSig = false;
        xmlNodePtr transformsNode = findDsChild(refNode, "Transforms");
        if (transformsNode) {
            for (xmlNodePtr t = transformsNode->children; t; t = t->next) {
                if (t->type != XML_ELEMENT_NODE)
                    continue;
                std::string algo = nodeAttr(t, "Algorithm");
                if (algo.find("enveloped-signature") != std::string::npos)
                    hasEnvelopedSig = true;
            }
        }

        // Resolve referenced content and canonicalize
        std::vector<uint8_t> canonicalized;

        if (uri.empty()) {
            // URI="" means whole document with enveloped-signature transform
            // Temporarily remove the Signature element, canonicalize, re-attach
            xmlNodePtr sigParent = sigNode->parent;
            xmlUnlinkNode(sigNode);
            canonicalized = canonicalizeDoc(doc.get());
            // Re-attach signature node
            if (sigParent) {
                xmlAddChild(sigParent, sigNode);
            } else {
                xmlDocSetRootElement(doc.get(), sigNode);
            }
        } else if (uri.size() > 1 && uri[0] == '#') {
            // URI="#id" — find element by Id
            std::string id = uri.substr(1);
            xmlAttrPtr idAttr = xmlGetID(doc.get(), BAD_CAST id.c_str());
            xmlNodePtr targetNode = nullptr;
            if (idAttr) {
                targetNode = idAttr->parent;
            }

            if (!targetNode) {
                // Fallback: literal walk for the first element whose `Id`
                // attribute matches. NEVER build an XPath expression from
                // the user-supplied URI fragment — `id` is attacker-
                // controlled (it arrives from the URI="#…" attribute of a
                // possibly-untrusted XML reference) and the prior
                // "//*[@Id='" + id + "']" expression was an XPath-
                // injection sink (e.g. id="#'or'1'='1" matches every
                // element).
                xmlNodePtr root = xmlDocGetRootElement(doc.get());
                targetNode = findElementByIdAttr(root, BAD_CAST id.c_str());
            }

            if (!targetNode) {
                error = "could not resolve reference URI: " + uri;
                return false;
            }

            if (hasEnvelopedSig) {
                xmlUnlinkNode(sigNode);
                canonicalized = canonicalizeSubtree(doc.get(), targetNode);
                xmlNodePtr sigParent = targetNode; // re-attach to same parent context
                xmlAddChild(sigParent, sigNode);
            } else {
                canonicalized = canonicalizeSubtree(doc.get(), targetNode);
            }
        } else {
            // External references not supported for TL verification
            error = "unsupported reference URI: " + uri;
            return false;
        }

        if (canonicalized.empty()) {
            error = "canonicalization produced empty output for reference: " + uri;
            return false;
        }

        // Compute digest
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int digestLen = 0;
        if (!EVP_Digest(canonicalized.data(), canonicalized.size(), digest, &digestLen, refMd, nullptr)) {
            error = "EVP_Digest failed: " + native_utils::opensslError();
            return false;
        }

        // Compare
        if (digestLen != expectedDigest.size() || std::memcmp(digest, expectedDigest.data(), digestLen) != 0) {
            error = "reference digest mismatch for URI: " + (uri.empty() ? "(whole document)" : uri);
            return false;
        }
    }

    // ---- 2. Signature Validation ----
    // Canonicalize ds:SignedInfo
    std::vector<uint8_t> c14nSignedInfo = canonicalizeSubtree(doc.get(), signedInfoNode);
    if (c14nSignedInfo.empty()) {
        error = "failed to canonicalize ds:SignedInfo";
        return false;
    }

    // Parse the signing certificate
    const unsigned char* certPtr = signingCertDer.data();
    X509Ptr cert(d2i_X509(nullptr, &certPtr, static_cast<long>(signingCertDer.size())));
    if (!cert) {
        error = "failed to parse signing certificate DER: " + native_utils::opensslError();
        return false;
    }

    // Trust-list authenticity is a separate question from "can OpenSSL
    // mathematically verify this signature blob?". An expired signing
    // certificate means the issuer is no longer asserting responsibility
    // for keys issued from this CA, so accepting the trust list would
    // let an attacker replay a stale-but-cryptographically-valid TL even
    // after the issuer has retired the signing key. Hard-fail.
    {
        const ASN1_TIME* notAfter = X509_get0_notAfter(cert.get());
        if (X509_cmp_current_time(notAfter) < 0) {
            error = "TL signing certificate expired: notAfter has passed; "
                    "trust list cannot be authenticated";
            return false;
        }
    }

    // Extract public key
    EVP_PKEY* pubKey = X509_get0_pubkey(cert.get());
    if (!pubKey) {
        error = "failed to extract public key from certificate: " + native_utils::opensslError();
        return false;
    }

    // Belt-and-braces: refuse a signature whose @Algorithm URI claims one
    // key type but whose carrier certificate carries a key of a different
    // family. OpenSSL would reject the math anyway, but failing earlier
    // with a precise diagnostic shrinks the attack surface and makes
    // mis-issued TLs immediately diagnosable.
    int actualKeyTypeNid = EVP_PKEY_base_id(pubKey);
    if (actualKeyTypeNid != expectedKeyTypeNid) {
        error = "signature method " + sigMethodUri + " requires key type " + std::to_string(expectedKeyTypeNid) +
                " but certificate carries key type " + std::to_string(actualKeyTypeNid);
        return false;
    }

    // Verify signature
    EvpMdCtxPtr mdCtx(EVP_MD_CTX_new());
    if (!mdCtx) {
        error = "EVP_MD_CTX_new failed";
        return false;
    }

    if (EVP_DigestVerifyInit(mdCtx.get(), nullptr, sigMd, nullptr, pubKey) != 1) {
        error = "EVP_DigestVerifyInit failed: " + native_utils::opensslError();
        return false;
    }

    if (EVP_DigestVerifyUpdate(mdCtx.get(), c14nSignedInfo.data(), c14nSignedInfo.size()) != 1) {
        error = "EVP_DigestVerifyUpdate failed: " + native_utils::opensslError();
        return false;
    }

    int rc = EVP_DigestVerifyFinal(mdCtx.get(), signatureValue.data(), signatureValue.size());
    if (rc != 1) {
        error = "signature verification failed";
        if (rc < 0)
            error += ": " + native_utils::opensslError();
        return false;
    }

    return true;
}

} // namespace libresign

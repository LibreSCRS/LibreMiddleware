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
#include <iostream>
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

// ---- Algorithm URI to EVP_MD mapping ----

const EVP_MD* digestFromUri(const std::string& uri)
{
    if (uri.find("sha512") != std::string::npos || uri.find("sha-512") != std::string::npos)
        return EVP_sha512();
    if (uri.find("sha384") != std::string::npos || uri.find("sha-384") != std::string::npos)
        return EVP_sha384();
    if (uri.find("sha256") != std::string::npos || uri.find("sha-256") != std::string::npos)
        return EVP_sha256();
    if (uri.find("sha1") != std::string::npos || uri.find("sha-1") != std::string::npos)
        return EVP_sha1();
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

// ---- Get text content of a node as std::string ----

std::string nodeText(xmlNodePtr node)
{
    if (!node)
        return {};
    XmlCharPtr content(xmlNodeGetContent(node));
    if (!content)
        return {};
    return {reinterpret_cast<const char*>(content.get())};
}

// ---- Get attribute value as std::string ----

std::string nodeAttr(xmlNodePtr node, const char* attrName)
{
    if (!node)
        return {};
    XmlCharPtr val(xmlGetProp(node, BAD_CAST attrName));
    if (!val)
        return {};
    return {reinterpret_cast<const char*>(val.get())};
}

// ---- Find the ds:Signature element anywhere in the document ----

xmlNodePtr findSignatureNode(xmlDocPtr doc)
{
    XPathCtxPtr ctx(xmlXPathNewContext(doc));
    if (!ctx)
        return nullptr;
    xmlXPathRegisterNs(ctx.get(), BAD_CAST "ds", BAD_CAST kNsDs);

    XPathObjPtr obj(xmlXPathEvalExpression(BAD_CAST "//ds:Signature", ctx.get()));
    if (!obj || !obj->nodesetval || obj->nodesetval->nodeNr == 0)
        return nullptr;
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
    XPathObjPtr xpathObj(xmlXPathEvalExpression(
        BAD_CAST "(. | ./descendant::* | ./descendant::text() | ./@* | ./descendant::*/@* "
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

bool TlSignatureVerifier::verify(std::span<const uint8_t> xmlData,
                                  std::span<const uint8_t> signingCertDer)
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
    XmlDocPtr doc(xmlReadMemory(reinterpret_cast<const char*>(xmlData.data()),
                                 static_cast<int>(xmlData.size()), nullptr, nullptr,
                                 XML_PARSE_NONET | XML_PARSE_NOCDATA));
    if (!doc) {
        error = "failed to parse XML document";
        return false;
    }

    // Find ds:Signature
    xmlNodePtr sigNode = findSignatureNode(doc.get());
    if (!sigNode) {
        error = "no ds:Signature element found";
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
    const EVP_MD* sigMd = digestFromUri(sigMethodUri);
    if (!sigMd) {
        error = "unsupported signature algorithm: " + sigMethodUri;
        return false;
    }

    // ---- Phase 1: Reference Validation ----
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
        const EVP_MD* refMd = digestFromUri(digestMethodUri);
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
                // Fallback: XPath search for element with matching Id attribute
                XPathCtxPtr xpCtx(xmlXPathNewContext(doc.get()));
                if (xpCtx) {
                    std::string expr = "//*[@Id='" + id + "']";
                    XPathObjPtr xpObj(xmlXPathEvalExpression(BAD_CAST expr.c_str(), xpCtx.get()));
                    if (xpObj && xpObj->nodesetval && xpObj->nodesetval->nodeNr > 0)
                        targetNode = xpObj->nodesetval->nodeTab[0];
                }
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
        if (digestLen != expectedDigest.size() ||
            std::memcmp(digest, expectedDigest.data(), digestLen) != 0) {
            error = "reference digest mismatch for URI: " + (uri.empty() ? "(whole document)" : uri);
            return false;
        }
    }

    // ---- Phase 2: Signature Validation ----
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

    // Check cert validity — warn but don't fail on expired certs.
    // An expired cert can still have mathematically valid signatures.
    {
        const ASN1_TIME* notAfter = X509_get0_notAfter(cert.get());
        if (X509_cmp_current_time(notAfter) < 0) {
            std::cerr << "libresign: WARNING: TL signing certificate has expired" << std::endl;
        }
    }

    // Extract public key
    EVP_PKEY* pubKey = X509_get0_pubkey(cert.get());
    if (!pubKey) {
        error = "failed to extract public key from certificate: " + native_utils::opensslError();
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

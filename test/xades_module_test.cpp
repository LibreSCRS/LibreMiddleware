// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/xades_module.h"
#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "signing_test_support/signing_test_support.h"
#include "signing_service.h"

#include "../lib/libresign/src/native/native_utils.h"

#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>

#include <string>

using namespace libresign;

// ---- Helper: parse XML from SigningResult ----

struct XmlDocDeleter
{
    void operator()(xmlDocPtr p) const
    {
        xmlFreeDoc(p);
    }
};
struct XmlXPathCtxDeleter
{
    void operator()(xmlXPathContextPtr p) const
    {
        xmlXPathFreeContext(p);
    }
};
struct XmlXPathObjDeleter
{
    void operator()(xmlXPathObjectPtr p) const
    {
        xmlXPathFreeObject(p);
    }
};

using XmlDocPtr = std::unique_ptr<xmlDoc, XmlDocDeleter>;
using XPathCtxPtr = std::unique_ptr<xmlXPathContext, XmlXPathCtxDeleter>;
using XPathObjPtr = std::unique_ptr<xmlXPathObject, XmlXPathObjDeleter>;

static XmlDocPtr parseResult(const SigningResult& result)
{
    xmlDocPtr doc = xmlParseMemory(reinterpret_cast<const char*>(result.signedDocument.data()),
                                   static_cast<int>(result.signedDocument.size()));
    return XmlDocPtr(doc);
}

static XPathCtxPtr createXPathCtx(xmlDocPtr doc)
{
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    xmlXPathRegisterNs(ctx, BAD_CAST "ds", BAD_CAST "http://www.w3.org/2000/09/xmldsig#");
    xmlXPathRegisterNs(ctx, BAD_CAST "xades", BAD_CAST "http://uri.etsi.org/01903/v1.3.2#");
    return XPathCtxPtr(ctx);
}

static int xpathCount(xmlXPathContextPtr ctx, const char* expr)
{
    XPathObjPtr obj(xmlXPathEvalExpression(BAD_CAST expr, ctx));
    if (!obj || !obj->nodesetval)
        return 0;
    return obj->nodesetval->nodeNr;
}

static std::string xpathText(xmlXPathContextPtr ctx, const char* expr)
{
    XPathObjPtr obj(xmlXPathEvalExpression(BAD_CAST expr, ctx));
    if (!obj || !obj->nodesetval || obj->nodesetval->nodeNr == 0)
        return {};
    xmlNodePtr node = obj->nodesetval->nodeTab[0];
    xmlChar* content = xmlNodeGetContent(node);
    if (!content)
        return {};
    std::string result(reinterpret_cast<const char*>(content));
    xmlFree(content);
    return result;
}

static std::string xpathAttr(xmlXPathContextPtr ctx, const char* expr)
{
    XPathObjPtr obj(xmlXPathEvalExpression(BAD_CAST expr, ctx));
    if (!obj || !obj->nodesetval || obj->nodesetval->nodeNr == 0)
        return {};
    xmlNodePtr node = obj->nodesetval->nodeTab[0];
    if (node->type == XML_ATTRIBUTE_NODE) {
        xmlChar* content = xmlNodeGetContent(node);
        if (!content)
            return {};
        std::string result(reinterpret_cast<const char*>(content));
        xmlFree(content);
        return result;
    }
    return {};
}

// ---- SoftHSM-dependent tests ----

class XAdESModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        libresign::native_utils::ensureXmlInitialized();
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        auto slot = libresign::test::findSoftHsmTestSlot(manager.acquire(softHsmPath));
        if (!slot)
            GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";
        testSlot = *slot;
    }
    const char* softHsmPath = nullptr;
    libresign::Pkcs11ModuleManager manager;
    unsigned long testSlot = 0;
};

TEST_F(XAdESModuleTest, SignBB_ProducesValidXml)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = xades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_FALSE(result.signedDocument.empty());

    // Must be valid XML
    auto doc = parseResult(result);
    ASSERT_NE(doc.get(), nullptr) << "Failed to parse XML output";

    // Root element should be ds:Signature
    xmlNodePtr root = xmlDocGetRootElement(doc.get());
    ASSERT_NE(root, nullptr);
    EXPECT_STREQ(reinterpret_cast<const char*>(root->name), "Signature");
}

TEST_F(XAdESModuleTest, SignBB_HasRequiredElements)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = xades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    auto doc = parseResult(result);
    ASSERT_NE(doc.get(), nullptr);

    auto ctx = createXPathCtx(doc.get());

    // ds:SignedInfo must exist
    EXPECT_EQ(xpathCount(ctx.get(), "//ds:SignedInfo"), 1);

    // ds:SignatureValue must exist and be non-empty
    EXPECT_EQ(xpathCount(ctx.get(), "//ds:SignatureValue"), 1);
    std::string sigVal = xpathText(ctx.get(), "//ds:SignatureValue");
    EXPECT_FALSE(sigVal.empty()) << "SignatureValue should not be empty";

    // ds:KeyInfo/ds:X509Data/ds:X509Certificate must exist
    EXPECT_GE(xpathCount(ctx.get(), "//ds:KeyInfo/ds:X509Data/ds:X509Certificate"), 1);

    // Two ds:Reference elements in SignedInfo
    EXPECT_EQ(xpathCount(ctx.get(), "//ds:SignedInfo/ds:Reference"), 2);

    // ds:CanonicalizationMethod
    EXPECT_EQ(xpathCount(ctx.get(), "//ds:SignedInfo/ds:CanonicalizationMethod"), 1);

    // ds:SignatureMethod
    EXPECT_EQ(xpathCount(ctx.get(), "//ds:SignedInfo/ds:SignatureMethod"), 1);
}

TEST_F(XAdESModuleTest, SignBB_HasXAdESQualifyingProperties)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'H', 'e', 'l', 'l', 'o'};
    auto result = xades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    auto doc = parseResult(result);
    ASSERT_NE(doc.get(), nullptr);

    auto ctx = createXPathCtx(doc.get());

    // xades:QualifyingProperties must exist with Target="#Signature-1"
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:QualifyingProperties"), 1);
    std::string target = xpathAttr(ctx.get(), "//xades:QualifyingProperties/@Target");
    EXPECT_EQ(target, "#Signature-1");

    // xades:SignedProperties with Id="SignedProperties-1"
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:SignedProperties"), 1);
    std::string propsId = xpathAttr(ctx.get(), "//xades:SignedProperties/@Id");
    EXPECT_EQ(propsId, "SignedProperties-1");

    // xades:SigningTime must be present and non-empty
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:SigningTime"), 1);
    std::string sigTime = xpathText(ctx.get(), "//xades:SigningTime");
    EXPECT_FALSE(sigTime.empty());
    // Should look like ISO 8601: contain 'T' and 'Z'
    EXPECT_NE(sigTime.find('T'), std::string::npos);
    EXPECT_NE(sigTime.find('Z'), std::string::npos);

    // xades:SigningCertificateV2 with Cert/CertDigest
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:SigningCertificateV2"), 1);
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:SigningCertificateV2/xades:Cert"), 1);
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:Cert/xades:CertDigest/ds:DigestValue"), 1);
    std::string certDigest = xpathText(ctx.get(), "//xades:Cert/xades:CertDigest/ds:DigestValue");
    EXPECT_FALSE(certDigest.empty());

    // xades:IssuerSerial
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:IssuerSerial/ds:X509IssuerName"), 1);
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:IssuerSerial/ds:X509SerialNumber"), 1);
}

TEST_F(XAdESModuleTest, SignBB_HasDataObjectFormat)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto result = xades.sign(data, "document.pdf", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    auto doc = parseResult(result);
    ASSERT_NE(doc.get(), nullptr);

    auto ctx = createXPathCtx(doc.get());

    // DataObjectFormat with ObjectReference="#Reference-1"
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:DataObjectFormat"), 1);
    std::string objRef = xpathAttr(ctx.get(), "//xades:DataObjectFormat/@ObjectReference");
    EXPECT_EQ(objRef, "#Reference-1");

    // MimeType should be application/pdf for .pdf files
    std::string mimeType = xpathText(ctx.get(), "//xades:MimeType");
    EXPECT_EQ(mimeType, "application/pdf");
}

TEST_F(XAdESModuleTest, SignBB_DetachedHasFileNameReference)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto result = xades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    auto doc = parseResult(result);
    ASSERT_NE(doc.get(), nullptr);

    auto ctx = createXPathCtx(doc.get());

    // First Reference should have URI="test.txt" for detached
    std::string uri = xpathAttr(ctx.get(), "//ds:SignedInfo/ds:Reference[@Id='Reference-1']/@URI");
    EXPECT_EQ(uri, "test.txt");
}

TEST_F(XAdESModuleTest, SignBB_DigestValuesAreNonEmpty)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto result = xades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    auto doc = parseResult(result);
    ASSERT_NE(doc.get(), nullptr);

    auto ctx = createXPathCtx(doc.get());

    // Both Reference DigestValues should be non-empty base64
    std::string dataDigest = xpathText(ctx.get(), "//ds:SignedInfo/ds:Reference[@Id='Reference-1']/ds:DigestValue");
    EXPECT_FALSE(dataDigest.empty()) << "Data DigestValue should not be empty";

    std::string propsDigest =
        xpathText(ctx.get(), "//ds:SignedInfo/ds:Reference[@URI='#SignedProperties-1']/ds:DigestValue");
    EXPECT_FALSE(propsDigest.empty()) << "SignedProperties DigestValue should not be empty";
}

TEST_F(XAdESModuleTest, SignBB_DifferentDataProducesDifferentSignature)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data1 = {'A', 'B', 'C'};
    std::vector<uint8_t> data2 = {'X', 'Y', 'Z'};

    auto result1 = xades.sign(data1, "a.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});
    auto result2 = xades.sign(data2, "b.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result1.success) << result1.errorMessage;
    ASSERT_TRUE(result2.success) << result2.errorMessage;
    EXPECT_NE(result1.signedDocument, result2.signedDocument);
}

TEST_F(XAdESModuleTest, SignBB_NoUnsignedProperties)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    auto result = xades.sign(data, "test.txt", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    auto doc = parseResult(result);
    ASSERT_NE(doc.get(), nullptr);

    auto ctx = createXPathCtx(doc.get());

    // B-B should NOT have UnsignedProperties
    EXPECT_EQ(xpathCount(ctx.get(), "//xades:UnsignedProperties"), 0);
}

TEST_F(XAdESModuleTest, BTRequiresTSA)
{
    Pkcs11Token token(manager.acquire(softHsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{testSlot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'T', 'e', 's', 't'};
    TSAConfig emptyTsa; // empty URL
    auto result = xades.sign(data, "test.txt", token, SignatureLevel::B_T, SignaturePackaging::Detached, emptyTsa);

    // Should fail because TSA URL is empty
    EXPECT_FALSE(result.success);
    EXPECT_FALSE(result.errorMessage.empty());
}

// ---- Standalone tests (no SoftHSM required) ----

class XAdESModuleStandaloneTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        libresign::native_utils::ensureXmlInitialized();
    }
};

TEST_F(XAdESModuleStandaloneTest, ProducesXmlOutput)
{
    // If SoftHSM is available, verify the output starts with XML declaration
    const char* hsmPath = libresign::test::findSoftHsmPath();
    if (!hsmPath)
        GTEST_SKIP() << "SoftHSM2 not found";

    libresign::Pkcs11ModuleManager manager;
    auto slot = libresign::test::findSoftHsmTestSlot(manager.acquire(hsmPath));
    if (!slot)
        GTEST_SKIP() << "SoftHSM2 token '" << libresign::test::kSoftHsmTokenLabel << "' not initialised";

    Pkcs11Token token(manager.acquire(hsmPath), libresign::as_pin("1234"), "test-key",
                      libresign::Pkcs11Token::TestSlotId{*slot});
    XAdESModule xades;

    std::vector<uint8_t> data = {'X', 'M', 'L'};
    auto result = xades.sign(data, "test.xml", token, SignatureLevel::B_B, SignaturePackaging::Detached, {});

    ASSERT_TRUE(result.success) << result.errorMessage;
    ASSERT_GT(result.signedDocument.size(), 5u);

    // Should start with "<?xml"
    std::string prefix(result.signedDocument.begin(), result.signedDocument.begin() + 5);
    EXPECT_EQ(prefix, "<?xml");
}

// Non-SoftHSM tests

TEST(XAdESModuleStandalone, RejectsEmptyInput)
{
    XAdESModule xades;
    std::vector<uint8_t> empty;
    // Token is never touched — sign() returns early on empty input.
    alignas(Pkcs11Token) char storage[sizeof(Pkcs11Token)]{};
    auto& dummyToken = *reinterpret_cast<Pkcs11Token*>(storage);
    auto result = xades.sign(empty, "test.xml", dummyToken, SignatureLevel::B_B, SignaturePackaging::Enveloped, {});
    ASSERT_FALSE(result.success);
    EXPECT_NE(result.errorMessage.find("empty"), std::string::npos);
}

#else
TEST(XAdESModuleTest, DISABLED_SkippedNativeNotCompiled)
{
    GTEST_SKIP();
}
#endif

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Pkcs11/SessionInjection.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <dlfcn.h>
#include <filesystem>
#include <utility>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11/pkcs11.h"

namespace LibreSCRS::Pkcs11 {

namespace {

std::filesystem::path modulePath()
{
    return std::filesystem::path{LIBRESCRS_PKCS11_MODULE_PATH};
}

std::shared_ptr<LibreSCRS::SmartCard::CardSession> makeFakeSession(const std::string& reader)
{
    return LibreSCRS::SmartCard::detail::makeDetachedCardSession(reader);
}

} // namespace

// Test-suite-level fixture: dlopen the librescrs-pkcs11 module and
// C_Initialize it once so the module-side static state (registry +
// initialised flag) is live for the duration of the suite. The
// SessionAttachment instances under test perform their own RTLD_NOLOAD
// retain on the same module; module state is `static` and shared across
// dlopen handles, so attach()'s probe sees the initialised module.
class SessionAttachmentTest : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        moduleHandle = ::dlopen(LIBRESCRS_PKCS11_MODULE_PATH, RTLD_NOW);
        ASSERT_NE(moduleHandle, nullptr) << "dlopen failed: " << ::dlerror();
        auto getFnList = reinterpret_cast<CK_C_GetFunctionList>(::dlsym(moduleHandle, "C_GetFunctionList"));
        ASSERT_NE(getFnList, nullptr) << "dlsym(C_GetFunctionList) failed: " << ::dlerror();
        CK_FUNCTION_LIST* fnList = nullptr;
        ASSERT_EQ(getFnList(&fnList), CKR_OK);
        ASSERT_NE(fnList, nullptr);
        funcs = fnList;
        ASSERT_EQ(funcs->C_Initialize(nullptr), CKR_OK);
    }

    static void TearDownTestSuite()
    {
        if (funcs) {
            funcs->C_Finalize(nullptr);
        }
        if (moduleHandle) {
            ::dlclose(moduleHandle);
        }
        funcs = nullptr;
        moduleHandle = nullptr;
    }

    static void* moduleHandle;
    static CK_FUNCTION_LIST* funcs;
};

void* SessionAttachmentTest::moduleHandle = nullptr;
CK_FUNCTION_LIST* SessionAttachmentTest::funcs = nullptr;

// Pure validation: empty reader name is rejected before any dlopen.
TEST_F(SessionAttachmentTest, AttachWithEmptyReaderReturnsInvalidArguments)
{
    auto session = makeFakeSession("R0");
    auto result = SessionAttachment::attach(modulePath(), "", session);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), SessionAttachment::Error::InvalidArguments);
}

// Pure validation: null session is rejected before any dlopen.
TEST_F(SessionAttachmentTest, AttachWithNullSessionReturnsInvalidArguments)
{
    auto result = SessionAttachment::attach(modulePath(), "R0", nullptr);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), SessionAttachment::Error::InvalidArguments);
}

// Pure validation: empty modulePath is rejected before any dlopen.
TEST_F(SessionAttachmentTest, AttachWithEmptyModulePathReturnsInvalidArguments)
{
    auto session = makeFakeSession("R0");
    auto result = SessionAttachment::attach(std::filesystem::path{}, "R0", session);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), SessionAttachment::Error::InvalidArguments);
}

// dlopen failure path — non-existent module surfaces as ModuleNotLoaded.
TEST_F(SessionAttachmentTest, AttachToBadPathReturnsModuleNotLoaded)
{
    auto session = makeFakeSession("R0");
    auto result = SessionAttachment::attach("/nonexistent/path/librescrs-pkcs11.so", "R0", session);
    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), SessionAttachment::Error::ModuleNotLoaded);
}

// Happy path: the module is built, present at LIBRESCRS_PKCS11_MODULE_PATH,
// and the suite-level fixture has C_Initialize'd it. attach() must succeed,
// readerName() must echo the bound reader, and the destructor at scope exit
// must detach without crashing.
TEST_F(SessionAttachmentTest, AttachAndDestructorDetachesAutomatically)
{
    auto session = makeFakeSession("R0");

    {
        auto result = SessionAttachment::attach(modulePath(), "R0", session);
        ASSERT_TRUE(result.has_value()) << "attach() failed with error code " << static_cast<int>(result.error());
        EXPECT_EQ(result->readerName(), "R0");
    } // destructor runs here; must not crash.
    SUCCEED();
}

// Move construction transfers state and clears the source so the
// source's destructor is a no-op (no double-detach, no double-dlclose).
TEST_F(SessionAttachmentTest, MoveConstructorTransfersOwnership)
{
    auto session = makeFakeSession("R0");
    auto result = SessionAttachment::attach(modulePath(), "R0", session);
    ASSERT_TRUE(result.has_value()) << "attach() failed with error code " << static_cast<int>(result.error());

    SessionAttachment moved = std::move(*result);
    EXPECT_EQ(moved.readerName(), "R0");
    EXPECT_TRUE(result->readerName().empty()); // moved-from cleared
    // moved.~SessionAttachment() runs at scope exit and must detach the
    // (now solely-owned) registry entry; result.~SessionAttachment() must
    // be a no-op.
}

// detach() is idempotent: calling it twice (or after the destructor
// would) must not double-dlclose or double-detach.
TEST_F(SessionAttachmentTest, DetachIsIdempotent)
{
    auto session = makeFakeSession("R0");
    auto result = SessionAttachment::attach(modulePath(), "R0", session);
    ASSERT_TRUE(result.has_value()) << "attach() failed with error code " << static_cast<int>(result.error());

    result->detach();
    EXPECT_TRUE(result->readerName().empty());
    result->detach(); // second call: must be a no-op, must not crash.
    EXPECT_TRUE(result->readerName().empty());
    SUCCEED();
}

} // namespace LibreSCRS::Pkcs11

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include <gtest/gtest.h>
#include <pkcs11/pkcs11.h>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>

// ---------------------------------------------------------------------------
// C_GetFunctionList
// ---------------------------------------------------------------------------

TEST(PKCS11Test, GetFunctionListReturnsOK)
{
    CK_FUNCTION_LIST_PTR pFunctionList = nullptr;
    CK_RV rv = C_GetFunctionList(&pFunctionList);
    EXPECT_EQ(rv, CKR_OK);
    EXPECT_NE(pFunctionList, nullptr);
}

TEST(PKCS11Test, GetFunctionListNullPtrReturnsBadArgument)
{
    CK_RV rv = C_GetFunctionList(nullptr);
    EXPECT_EQ(rv, CKR_ARGUMENTS_BAD);
}

TEST(PKCS11Test, FunctionListVersion)
{
    CK_FUNCTION_LIST_PTR fl = nullptr;
    C_GetFunctionList(&fl);
    // C_GetFunctionList must advertise PKCS#11 v2.40 for compatibility with
    // SunPKCS11 and other v2.x consumers, even though our header imports
    // the v3.2 specification constants. v3.x clients use C_GetInterface
    // (not implemented here) to negotiate v3 behavior.
    EXPECT_EQ(fl->version.major, 2);
    EXPECT_EQ(fl->version.minor, 40);
}

// ---------------------------------------------------------------------------
// C_Initialize / C_Finalize
// ---------------------------------------------------------------------------

TEST(PKCS11Test, InitializeAndFinalize)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);
    EXPECT_EQ(C_Initialize(nullptr), CKR_CRYPTOKI_ALREADY_INITIALIZED);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
    EXPECT_EQ(C_Finalize(nullptr), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, FinalizeWithReserved)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);
    CK_BYTE dummy = 0;
    EXPECT_EQ(C_Finalize(&dummy), CKR_ARGUMENTS_BAD);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, InitWithOSLocking)
{
    CK_C_INITIALIZE_ARGS args = {};
    args.flags = CKF_OS_LOCKING_OK;
    EXPECT_EQ(C_Initialize(&args), CKR_OK);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, InitWithReservedNonNull)
{
    CK_C_INITIALIZE_ARGS args = {};
    CK_BYTE dummy = 0;
    args.pReserved = &dummy;
    EXPECT_EQ(C_Initialize(&args), CKR_ARGUMENTS_BAD);
}

TEST(PKCS11Test, InitWithCustomMutexNoOSLocking)
{
    CK_C_INITIALIZE_ARGS args = {};
    // Provide a dummy mutex function without CKF_OS_LOCKING_OK
    args.CreateMutex = reinterpret_cast<CK_CREATEMUTEX>(1);
    args.flags = 0;
    EXPECT_EQ(C_Initialize(&args), CKR_CANT_LOCK);
}

// ---------------------------------------------------------------------------
// C_GetInfo
// ---------------------------------------------------------------------------

TEST(PKCS11Test, GetInfoBeforeInit)
{
    CK_INFO info;
    EXPECT_EQ(C_GetInfo(&info), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, GetInfoAfterInit)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);
    CK_INFO info;
    EXPECT_EQ(C_GetInfo(&info), CKR_OK);
    // See FunctionListVersion for the v2.40 rationale.
    EXPECT_EQ(info.cryptokiVersion.major, 2);
    EXPECT_EQ(info.cryptokiVersion.minor, 40);
    EXPECT_EQ(std::string(reinterpret_cast<char*>(info.manufacturerID), 9), "LibreSCRS");
    EXPECT_EQ(std::string(reinterpret_cast<char*>(info.libraryDescription), 17), "LibreSCRS PKCS#11");
    EXPECT_EQ(info.flags, 0u);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, GetInfoNullPtr)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);
    EXPECT_EQ(C_GetInfo(nullptr), CKR_ARGUMENTS_BAD);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

// ---------------------------------------------------------------------------
// C_GetSlotList
// ---------------------------------------------------------------------------

TEST(PKCS11Test, GetSlotListBeforeInit)
{
    CK_ULONG count = 0;
    EXPECT_EQ(C_GetSlotList(CK_FALSE, nullptr, &count), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, GetSlotListNullCount)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);
    EXPECT_EQ(C_GetSlotList(CK_FALSE, nullptr, nullptr), CKR_ARGUMENTS_BAD);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, GetSlotListReturnsSlots)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    // Query count (pSlotList = nullptr)
    CK_ULONG count = 0;
    CK_RV rv = C_GetSlotList(CK_FALSE, nullptr, &count);
    EXPECT_EQ(rv, CKR_OK);
    // count may be 0 on machines without PC/SC readers — that's fine

    if (count > 0) {
        // Fill the list
        std::vector<CK_SLOT_ID> slotList(count);
        CK_ULONG fillCount = count;
        rv = C_GetSlotList(CK_FALSE, slotList.data(), &fillCount);
        EXPECT_EQ(rv, CKR_OK);
        EXPECT_EQ(fillCount, count);
    }

    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, GetSlotListBufferTooSmall)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    CK_ULONG count = 0;
    C_GetSlotList(CK_FALSE, nullptr, &count);

    if (count > 0) {
        // Provide a buffer that's too small
        CK_ULONG smallCount = 0;
        CK_SLOT_ID dummy;
        CK_RV rv = C_GetSlotList(CK_FALSE, &dummy, &smallCount);
        EXPECT_EQ(rv, CKR_BUFFER_TOO_SMALL);
        EXPECT_EQ(smallCount, count);
    }

    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

// ---------------------------------------------------------------------------
// C_GetSlotInfo
// ---------------------------------------------------------------------------

TEST(PKCS11Test, GetSlotInfoWithoutGetSlotList)
{
    // SunPKCS11 calls C_GetSlotInfo immediately after C_Initialize,
    // without calling C_GetSlotList first. Slots must be populated
    // eagerly in C_Initialize so this works.
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    CK_SLOT_INFO info;
    // Slot 0 should work if any readers are connected (eagerly populated).
    // Even if no readers, slot 9999 should return SLOT_ID_INVALID (not crash).
    EXPECT_EQ(C_GetSlotInfo(9999, &info), CKR_SLOT_ID_INVALID);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, GetSlotInfoInvalidSlot)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    CK_SLOT_INFO info;
    EXPECT_EQ(C_GetSlotInfo(9999, &info), CKR_SLOT_ID_INVALID);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, GetSlotInfoNullPtr)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    // Slot 0 exists if any readers are connected
    CK_ULONG count = 0;
    C_GetSlotList(CK_FALSE, nullptr, &count);
    if (count > 0) {
        EXPECT_EQ(C_GetSlotInfo(0, nullptr), CKR_ARGUMENTS_BAD);
    }
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, GetSlotInfoValid)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    CK_ULONG count = 0;
    C_GetSlotList(CK_FALSE, nullptr, &count);

    if (count > 0) {
        std::vector<CK_SLOT_ID> slotList(count);
        CK_ULONG fillCount = count;
        C_GetSlotList(CK_FALSE, slotList.data(), &fillCount);

        CK_SLOT_INFO info;
        CK_RV rv = C_GetSlotInfo(slotList[0], &info);
        EXPECT_EQ(rv, CKR_OK);

        // Must have REMOVABLE_DEVICE and HW_SLOT flags
        EXPECT_TRUE(info.flags & CKF_REMOVABLE_DEVICE);
        EXPECT_TRUE(info.flags & CKF_HW_SLOT);

        // Manufacturer should be LibreSCRS (space-padded)
        EXPECT_EQ(std::string(reinterpret_cast<char*>(info.manufacturerID), 9), "LibreSCRS");
    }

    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

// ---------------------------------------------------------------------------
// C_GetTokenInfo
// ---------------------------------------------------------------------------

TEST(PKCS11Test, GetTokenInfoInvalidSlot)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);
    CK_ULONG count = 0;
    C_GetSlotList(CK_FALSE, nullptr, &count);

    CK_TOKEN_INFO info;
    EXPECT_EQ(C_GetTokenInfo(9999, &info), CKR_SLOT_ID_INVALID);
    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, GetTokenInfoNoToken)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    // Get all slots (including those without tokens)
    CK_ULONG allCount = 0;
    C_GetSlotList(CK_FALSE, nullptr, &allCount);

    // Get only slots with tokens
    CK_ULONG tokenCount = 0;
    C_GetSlotList(CK_TRUE, nullptr, &tokenCount);

    // If there's a slot without a token, test it
    if (allCount > tokenCount) {
        // Find a slot without a token
        std::vector<CK_SLOT_ID> allSlots(allCount);
        CK_ULONG fillAll = allCount;
        C_GetSlotList(CK_FALSE, allSlots.data(), &fillAll);

        std::vector<CK_SLOT_ID> tokenSlots(tokenCount);
        CK_ULONG fillToken = tokenCount;
        if (tokenCount > 0)
            C_GetSlotList(CK_TRUE, tokenSlots.data(), &fillToken);

        for (auto slotID : allSlots) {
            CK_SLOT_INFO slotInfo;
            C_GetSlotInfo(slotID, &slotInfo);
            if (!(slotInfo.flags & CKF_TOKEN_PRESENT)) {
                CK_TOKEN_INFO tokenInfo;
                EXPECT_EQ(C_GetTokenInfo(slotID, &tokenInfo), CKR_TOKEN_NOT_PRESENT);
                break;
            }
        }
    }

    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

// ---------------------------------------------------------------------------
// Remaining stubs still return NOT_SUPPORTED
// ---------------------------------------------------------------------------

TEST(PKCS11Test, StubsReturnNotSupported)
{
    EXPECT_EQ(C_Initialize(nullptr), CKR_OK);

    CK_FUNCTION_LIST_PTR fl = nullptr;
    C_GetFunctionList(&fl);

    // Crypto operations
    EXPECT_EQ(fl->C_EncryptInit(0, nullptr, 0), CKR_FUNCTION_NOT_SUPPORTED);
    EXPECT_EQ(fl->C_DecryptInit(0, nullptr, 0), CKR_FUNCTION_NOT_SUPPORTED);
    EXPECT_EQ(fl->C_DigestInit(0, nullptr), CKR_FUNCTION_NOT_SUPPORTED);
    EXPECT_EQ(fl->C_VerifyInit(0, nullptr, 0), CKR_FUNCTION_NOT_SUPPORTED);

    // Key management
    EXPECT_EQ(fl->C_GenerateKey(0, nullptr, nullptr, 0, nullptr), CKR_FUNCTION_NOT_SUPPORTED);
    EXPECT_EQ(fl->C_GenerateRandom(0, nullptr, 0), CKR_FUNCTION_NOT_SUPPORTED);

    // Legacy parallel functions
    EXPECT_EQ(fl->C_GetFunctionStatus(0), CKR_FUNCTION_NOT_SUPPORTED);
    EXPECT_EQ(fl->C_CancelFunction(0), CKR_FUNCTION_NOT_SUPPORTED);

    // Slot event
    EXPECT_EQ(fl->C_WaitForSlotEvent(0, nullptr, nullptr), CKR_FUNCTION_NOT_SUPPORTED);

    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);
}

TEST(PKCS11Test, FunctionListHasAllEntries)
{
    CK_FUNCTION_LIST_PTR fl = nullptr;
    C_GetFunctionList(&fl);

    // Verify no null function pointers in the table
    EXPECT_NE(fl->C_Initialize, nullptr);
    EXPECT_NE(fl->C_Finalize, nullptr);
    EXPECT_NE(fl->C_GetInfo, nullptr);
    EXPECT_NE(fl->C_GetFunctionList, nullptr);
    EXPECT_NE(fl->C_GetSlotList, nullptr);
    EXPECT_NE(fl->C_GetSlotInfo, nullptr);
    EXPECT_NE(fl->C_GetTokenInfo, nullptr);
    EXPECT_NE(fl->C_GetMechanismList, nullptr);
    EXPECT_NE(fl->C_GetMechanismInfo, nullptr);
    EXPECT_NE(fl->C_InitToken, nullptr);
    EXPECT_NE(fl->C_InitPIN, nullptr);
    EXPECT_NE(fl->C_SetPIN, nullptr);
    EXPECT_NE(fl->C_OpenSession, nullptr);
    EXPECT_NE(fl->C_CloseSession, nullptr);
    EXPECT_NE(fl->C_CloseAllSessions, nullptr);
    EXPECT_NE(fl->C_GetSessionInfo, nullptr);
    EXPECT_NE(fl->C_GetOperationState, nullptr);
    EXPECT_NE(fl->C_SetOperationState, nullptr);
    EXPECT_NE(fl->C_Login, nullptr);
    EXPECT_NE(fl->C_Logout, nullptr);
    EXPECT_NE(fl->C_CreateObject, nullptr);
    EXPECT_NE(fl->C_CopyObject, nullptr);
    EXPECT_NE(fl->C_DestroyObject, nullptr);
    EXPECT_NE(fl->C_GetObjectSize, nullptr);
    EXPECT_NE(fl->C_GetAttributeValue, nullptr);
    EXPECT_NE(fl->C_SetAttributeValue, nullptr);
    EXPECT_NE(fl->C_FindObjectsInit, nullptr);
    EXPECT_NE(fl->C_FindObjects, nullptr);
    EXPECT_NE(fl->C_FindObjectsFinal, nullptr);
    EXPECT_NE(fl->C_EncryptInit, nullptr);
    EXPECT_NE(fl->C_Encrypt, nullptr);
    EXPECT_NE(fl->C_EncryptUpdate, nullptr);
    EXPECT_NE(fl->C_EncryptFinal, nullptr);
    EXPECT_NE(fl->C_DecryptInit, nullptr);
    EXPECT_NE(fl->C_Decrypt, nullptr);
    EXPECT_NE(fl->C_DecryptUpdate, nullptr);
    EXPECT_NE(fl->C_DecryptFinal, nullptr);
    EXPECT_NE(fl->C_DigestInit, nullptr);
    EXPECT_NE(fl->C_Digest, nullptr);
    EXPECT_NE(fl->C_DigestUpdate, nullptr);
    EXPECT_NE(fl->C_DigestKey, nullptr);
    EXPECT_NE(fl->C_DigestFinal, nullptr);
    EXPECT_NE(fl->C_SignInit, nullptr);
    EXPECT_NE(fl->C_Sign, nullptr);
    EXPECT_NE(fl->C_SignUpdate, nullptr);
    EXPECT_NE(fl->C_SignFinal, nullptr);
    EXPECT_NE(fl->C_SignRecoverInit, nullptr);
    EXPECT_NE(fl->C_SignRecover, nullptr);
    EXPECT_NE(fl->C_VerifyInit, nullptr);
    EXPECT_NE(fl->C_Verify, nullptr);
    EXPECT_NE(fl->C_VerifyUpdate, nullptr);
    EXPECT_NE(fl->C_VerifyFinal, nullptr);
    EXPECT_NE(fl->C_VerifyRecoverInit, nullptr);
    EXPECT_NE(fl->C_VerifyRecover, nullptr);
    EXPECT_NE(fl->C_DigestEncryptUpdate, nullptr);
    EXPECT_NE(fl->C_DecryptDigestUpdate, nullptr);
    EXPECT_NE(fl->C_SignEncryptUpdate, nullptr);
    EXPECT_NE(fl->C_DecryptVerifyUpdate, nullptr);
    EXPECT_NE(fl->C_GenerateKey, nullptr);
    EXPECT_NE(fl->C_GenerateKeyPair, nullptr);
    EXPECT_NE(fl->C_WrapKey, nullptr);
    EXPECT_NE(fl->C_UnwrapKey, nullptr);
    EXPECT_NE(fl->C_DeriveKey, nullptr);
    EXPECT_NE(fl->C_SeedRandom, nullptr);
    EXPECT_NE(fl->C_GenerateRandom, nullptr);
    EXPECT_NE(fl->C_GetFunctionStatus, nullptr);
    EXPECT_NE(fl->C_CancelFunction, nullptr);
    EXPECT_NE(fl->C_WaitForSlotEvent, nullptr);
}

// ---------------------------------------------------------------------------
// Helper: get slot counts after init
// ---------------------------------------------------------------------------

static void getSlotCounts(CK_ULONG& allCount, CK_ULONG& tokenCount)
{
    allCount = 0;
    tokenCount = 0;
    C_GetSlotList(CK_FALSE, nullptr, &allCount);
    C_GetSlotList(CK_TRUE, nullptr, &tokenCount);
}

// Cached usable slot — resolved once, reused by all tests.
// Slot IDs are stable across C_Initialize/C_Finalize cycles (reader index based).
static CK_SLOT_ID g_usableSlot = static_cast<CK_SLOT_ID>(-1);
static bool g_usableSlotResolved = false;

// Requires the library to already be initialized (caller responsibility).
static CK_SLOT_ID findFirstUsableSlot()
{
    if (g_usableSlotResolved)
        return g_usableSlot;
    g_usableSlotResolved = true;

    const char* slotEnv = std::getenv("LIBRESCRS_TEST_SLOT");
    if (slotEnv) {
        g_usableSlot = static_cast<CK_SLOT_ID>(std::stoul(slotEnv));
        return g_usableSlot;
    }

    // Probe once: find first slot where OpenSession + FindObjects work.
    // This is expensive (card I/O) so we cache the result for the entire test run.
    CK_ULONG tokenCount = 0;
    C_GetSlotList(CK_TRUE, nullptr, &tokenCount);
    std::vector<CK_SLOT_ID> slots(tokenCount);
    if (tokenCount > 0)
        C_GetSlotList(CK_TRUE, slots.data(), &tokenCount);

    for (auto slot : slots) {
        CK_SESSION_HANDLE session;
        if (C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &session) != CKR_OK)
            continue;
        CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE tmpl = {CKA_CLASS, &certClass, sizeof(certClass)};
        if (C_FindObjectsInit(session, &tmpl, 1) == CKR_OK) {
            C_FindObjectsFinal(session);
            C_CloseSession(session);
            g_usableSlot = slot;
            break;
        }
        C_CloseSession(session);
    }

    return g_usableSlot;
}

// ---------------------------------------------------------------------------
// Session management tests — pre-init error cases (standalone)
// ---------------------------------------------------------------------------

TEST(PKCS11Test, SessionFunctionsBeforeInit)
{
    CK_SESSION_HANDLE hSession = 0;
    CK_SESSION_INFO sessionInfo;

    EXPECT_EQ(C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_CloseSession(0), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_CloseAllSessions(0), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_GetSessionInfo(0, &sessionInfo), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_Login(0, CKU_USER, nullptr, 0), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_Logout(0), CKR_CRYPTOKI_NOT_INITIALIZED);
}

// ---------------------------------------------------------------------------
// Fixture: C_Initialize once per suite, C_Finalize once at teardown.
// All card-dependent tests use this fixture.
// ---------------------------------------------------------------------------

class PKCS11CardTest : public ::testing::Test
{
protected:
    static void SetUpTestSuite()
    {
        ASSERT_EQ(C_Initialize(nullptr), CKR_OK);
        slot = findFirstUsableSlot();
    }

    static void TearDownTestSuite()
    {
        C_Finalize(nullptr);
    }

    static CK_SLOT_ID slot;
};

CK_SLOT_ID PKCS11CardTest::slot = static_cast<CK_SLOT_ID>(-1);

// ---------------------------------------------------------------------------
// Session management tests — card-dependent (fixture)
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, OpenSessionRequiresSerialFlag)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        // flags=0 means no CKF_SERIAL_SESSION
        EXPECT_EQ(C_OpenSession(slot, 0, nullptr, nullptr, &hSession), CKR_SESSION_PARALLEL_NOT_SUPPORTED);
    }
}

TEST_F(PKCS11CardTest, OpenSessionNullHandle)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, nullptr), CKR_ARGUMENTS_BAD);
    }
}

TEST_F(PKCS11CardTest, OpenSessionInvalidSlot)
{
    CK_SESSION_HANDLE hSession;
    EXPECT_EQ(C_OpenSession(9999, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_SLOT_ID_INVALID);
}

TEST_F(PKCS11CardTest, OpenSessionNoToken)
{
    CK_ULONG allCount, tokenCount;
    getSlotCounts(allCount, tokenCount);

    // Find a slot without a token
    if (allCount > tokenCount) {
        std::vector<CK_SLOT_ID> allSlots(allCount);
        CK_ULONG fillAll = allCount;
        C_GetSlotList(CK_FALSE, allSlots.data(), &fillAll);

        for (auto slotID : allSlots) {
            CK_SLOT_INFO slotInfo;
            C_GetSlotInfo(slotID, &slotInfo);
            if (!(slotInfo.flags & CKF_TOKEN_PRESENT)) {
                CK_SESSION_HANDLE hSession;
                EXPECT_EQ(C_OpenSession(slotID, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession),
                          CKR_TOKEN_NOT_PRESENT);
                break;
            }
        }
    }
}

TEST_F(PKCS11CardTest, OpenAndCloseSession)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);
        EXPECT_EQ(C_CloseSession(hSession), CKR_OK);
        // Double-close should fail
        EXPECT_EQ(C_CloseSession(hSession), CKR_SESSION_HANDLE_INVALID);
    }
}

TEST_F(PKCS11CardTest, SessionInfoReflectsState)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        // RO session
        CK_SESSION_HANDLE hRO;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hRO), CKR_OK);
        CK_SESSION_INFO info;
        EXPECT_EQ(C_GetSessionInfo(hRO, &info), CKR_OK);
        EXPECT_EQ(info.state, CKS_RO_PUBLIC_SESSION);
        EXPECT_EQ(info.slotID, slot);
        EXPECT_TRUE(info.flags & CKF_SERIAL_SESSION);
        EXPECT_FALSE(info.flags & CKF_RW_SESSION);
        C_CloseSession(hRO);

        // RW session
        CK_SESSION_HANDLE hRW;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hRW), CKR_OK);
        EXPECT_EQ(C_GetSessionInfo(hRW, &info), CKR_OK);
        EXPECT_EQ(info.state, CKS_RW_PUBLIC_SESSION);
        EXPECT_TRUE(info.flags & CKF_RW_SESSION);
        C_CloseSession(hRW);
    }
}

TEST_F(PKCS11CardTest, GetSessionInfoInvalidHandle)
{
    CK_SESSION_INFO info;
    EXPECT_EQ(C_GetSessionInfo(9999, &info), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, GetSessionInfoNullPtr)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);
        EXPECT_EQ(C_GetSessionInfo(hSession, nullptr), CKR_ARGUMENTS_BAD);
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, CloseAllSessions)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE h1, h2, h3;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &h1), CKR_OK);
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &h2), CKR_OK);
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &h3), CKR_OK);

        EXPECT_EQ(C_CloseAllSessions(slot), CKR_OK);

        // All handles should now be invalid
        EXPECT_EQ(C_CloseSession(h1), CKR_SESSION_HANDLE_INVALID);
        EXPECT_EQ(C_CloseSession(h2), CKR_SESSION_HANDLE_INVALID);
        EXPECT_EQ(C_CloseSession(h3), CKR_SESSION_HANDLE_INVALID);
    }
}

TEST_F(PKCS11CardTest, CloseAllSessionsInvalidSlot)
{
    EXPECT_EQ(C_CloseAllSessions(9999), CKR_SLOT_ID_INVALID);
}

// ---------------------------------------------------------------------------
// Login / Logout tests
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, LoginWithoutSession)
{
    CK_UTF8CHAR pin[] = "1234";
    EXPECT_EQ(C_Login(9999, CKU_USER, pin, 4), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, LogoutWithoutSession)
{
    EXPECT_EQ(C_Logout(9999), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, LogoutWithoutLogin)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);
        EXPECT_EQ(C_Logout(hSession), CKR_USER_NOT_LOGGED_IN);
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, LoginSONotSupported)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);
        CK_UTF8CHAR pin[] = "1234";
        EXPECT_EQ(C_Login(hSession, CKU_SO, pin, 4), CKR_USER_TYPE_INVALID);
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, FinalizeClosesAllSessions)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);
    }

    EXPECT_EQ(C_Finalize(nullptr), CKR_OK);

    // After finalize, all session ops should return CKR_CRYPTOKI_NOT_INITIALIZED
    CK_SESSION_HANDLE hNew;
    EXPECT_EQ(C_OpenSession(0, CKF_SERIAL_SESSION, nullptr, nullptr, &hNew), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_CloseSession(1), CKR_CRYPTOKI_NOT_INITIALIZED);
    CK_SESSION_INFO info;
    EXPECT_EQ(C_GetSessionInfo(1, &info), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_Login(1, CKU_USER, nullptr, 0), CKR_CRYPTOKI_NOT_INITIALIZED);
    EXPECT_EQ(C_Logout(1), CKR_CRYPTOKI_NOT_INITIALIZED);

    // Re-initialize for remaining tests in the suite
    ASSERT_EQ(C_Initialize(nullptr), CKR_OK);
}

// ---------------------------------------------------------------------------
// Object discovery — error cases (no hardware needed)
// ---------------------------------------------------------------------------

TEST(PKCS11Test, FindObjectsInitBeforeInit)
{
    EXPECT_EQ(C_FindObjectsInit(0, nullptr, 0), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, FindObjectsBeforeInit)
{
    CK_OBJECT_HANDLE obj;
    CK_ULONG count;
    EXPECT_EQ(C_FindObjects(0, &obj, 1, &count), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, FindObjectsFinalBeforeInit)
{
    EXPECT_EQ(C_FindObjectsFinal(0), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, GetAttributeValueBeforeInit)
{
    CK_ATTRIBUTE tmpl = {};
    EXPECT_EQ(C_GetAttributeValue(0, 0, &tmpl, 1), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST_F(PKCS11CardTest, FindObjectsInitInvalidSession)
{
    EXPECT_EQ(C_FindObjectsInit(9999, nullptr, 0), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, FindObjectsInvalidSession)
{
    CK_OBJECT_HANDLE obj;
    CK_ULONG count;
    EXPECT_EQ(C_FindObjects(9999, &obj, 1, &count), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, FindObjectsFinalInvalidSession)
{
    EXPECT_EQ(C_FindObjectsFinal(9999), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, FindObjectsWithoutInit)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // FindObjects without FindObjectsInit
        CK_OBJECT_HANDLE obj;
        CK_ULONG count;
        EXPECT_EQ(C_FindObjects(hSession, &obj, 1, &count), CKR_OPERATION_NOT_INITIALIZED);

        // FindObjectsFinal without FindObjectsInit
        EXPECT_EQ(C_FindObjectsFinal(hSession), CKR_OPERATION_NOT_INITIALIZED);

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, FindObjectsDoubleInit)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        EXPECT_EQ(C_FindObjectsInit(hSession, nullptr, 0), CKR_OK);
        // Second init without final
        EXPECT_EQ(C_FindObjectsInit(hSession, nullptr, 0), CKR_OPERATION_ACTIVE);

        C_FindObjectsFinal(hSession);
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, GetAttributeValueInvalidObject)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_ATTRIBUTE tmpl = {CKA_CLASS, nullptr, 0};
        EXPECT_EQ(C_GetAttributeValue(hSession, 9999, &tmpl, 1), CKR_OBJECT_HANDLE_INVALID);

        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// Object discovery — happy-path tests (hardware-guarded)
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, FindAllObjectsOnToken)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Empty template matches all objects
        EXPECT_EQ(C_FindObjectsInit(hSession, nullptr, 0), CKR_OK);

        CK_OBJECT_HANDLE objs[32];
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, objs, 32, &count), CKR_OK);

        // Count should be even (cert/key pairs) — may be 0 on Apollo cards
        EXPECT_EQ(count % 2, 0u);

        EXPECT_EQ(C_FindObjectsFinal(hSession), CKR_OK);
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, FindCertificatesOnly)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE tmpl = {CKA_CLASS, &certClass, sizeof(certClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &tmpl, 1), CKR_OK);

        CK_OBJECT_HANDLE objs[16];
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, objs, 16, &count), CKR_OK);

        // Verify each returned object is a certificate
        for (CK_ULONG i = 0; i < count; ++i) {
            CK_OBJECT_CLASS cls;
            CK_ATTRIBUTE getAttr = {CKA_CLASS, &cls, sizeof(cls)};
            EXPECT_EQ(C_GetAttributeValue(hSession, objs[i], &getAttr, 1), CKR_OK);
            EXPECT_EQ(cls, CKO_CERTIFICATE);
        }

        EXPECT_EQ(C_FindObjectsFinal(hSession), CKR_OK);
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, GetAttributeValueSizeQuery)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Find first certificate
        CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE findTmpl = {CKA_CLASS, &certClass, sizeof(certClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);

        CK_OBJECT_HANDLE obj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &obj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            // Size query: pValue=NULL should return size
            CK_ATTRIBUTE sizeAttr = {CKA_VALUE, nullptr, 0};
            EXPECT_EQ(C_GetAttributeValue(hSession, obj, &sizeAttr, 1), CKR_OK);
            EXPECT_GT(sizeAttr.ulValueLen, 0u);

            // Buffer too small
            CK_BYTE smallBuf[1];
            CK_ATTRIBUTE smallAttr = {CKA_VALUE, smallBuf, 1};
            EXPECT_EQ(C_GetAttributeValue(hSession, obj, &smallAttr, 1), CKR_BUFFER_TOO_SMALL);

            // Invalid attribute for cert: CKA_SIGN is only on private keys
            CK_ATTRIBUTE badAttr = {CKA_SIGN, nullptr, 0};
            EXPECT_EQ(C_GetAttributeValue(hSession, obj, &badAttr, 1), CKR_ATTRIBUTE_TYPE_INVALID);
        }

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, FindObjectsBatching)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        EXPECT_EQ(C_FindObjectsInit(hSession, nullptr, 0), CKR_OK);

        // Fetch one at a time
        std::vector<CK_OBJECT_HANDLE> allHandles;
        while (true) {
            CK_OBJECT_HANDLE obj;
            CK_ULONG count = 0;
            EXPECT_EQ(C_FindObjects(hSession, &obj, 1, &count), CKR_OK);
            if (count == 0)
                break;
            allHandles.push_back(obj);
        }

        // All handles should be unique
        std::set<CK_OBJECT_HANDLE> uniqueHandles(allHandles.begin(), allHandles.end());
        EXPECT_EQ(uniqueHandles.size(), allHandles.size());

        EXPECT_EQ(C_FindObjectsFinal(hSession), CKR_OK);
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, CertKeyPairShareID)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Find all objects
        EXPECT_EQ(C_FindObjectsInit(hSession, nullptr, 0), CKR_OK);
        CK_OBJECT_HANDLE objs[32];
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, objs, 32, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            // Build a map: CKA_ID -> {cert_count, key_count}
            std::map<std::vector<uint8_t>, std::pair<int, int>> idMap;

            for (CK_ULONG i = 0; i < count; ++i) {
                // Get class
                CK_OBJECT_CLASS cls;
                CK_ATTRIBUTE clsAttr = {CKA_CLASS, &cls, sizeof(cls)};
                EXPECT_EQ(C_GetAttributeValue(hSession, objs[i], &clsAttr, 1), CKR_OK);

                // Get ID size
                CK_ATTRIBUTE idSizeAttr = {CKA_ID, nullptr, 0};
                EXPECT_EQ(C_GetAttributeValue(hSession, objs[i], &idSizeAttr, 1), CKR_OK);

                std::vector<uint8_t> id(idSizeAttr.ulValueLen);
                CK_ATTRIBUTE idAttr = {CKA_ID, id.data(), static_cast<CK_ULONG>(id.size())};
                EXPECT_EQ(C_GetAttributeValue(hSession, objs[i], &idAttr, 1), CKR_OK);

                if (cls == CKO_CERTIFICATE)
                    idMap[id].first++;
                else if (cls == CKO_PRIVATE_KEY)
                    idMap[id].second++;
            }

            // Each ID should have exactly one cert and one key
            for (auto& [id, counts] : idMap) {
                EXPECT_EQ(counts.first, 1) << "Expected 1 cert for ID";
                EXPECT_EQ(counts.second, 1) << "Expected 1 key for ID";
            }
        }

        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// Helper: get PIN from environment variable (never hardcode PINs!)
// Returns empty string if LIBRESCRS_TEST_PIN is not set.
//
// NOTE: This PIN guard infrastructure (getTestPIN, g_pinFailed, loginWithAbort,
// SKIP_IF_PIN_FAILED) duplicates signing_test_support.h. It is kept local
// because pkcs11_test links against the raw PKCS#11 C API and does not link
// SigningTestSupport. Consolidation is tracked as a backlog item.
// ---------------------------------------------------------------------------

static std::string getTestPIN()
{
    const char* pin = std::getenv("LIBRESCRS_TEST_PIN");
    return pin ? std::string(pin) : std::string();
}

// ---------------------------------------------------------------------------
// Global flag: set when a wrong PIN is detected. All subsequent PIN-dependent
// tests will be skipped to prevent burning remaining PIN retries.
// ---------------------------------------------------------------------------

static bool g_pinFailed = false;

// Helper: attempt login, set g_pinFailed on wrong PIN.
// Returns CKR_OK on success, or the actual error code.
static CK_RV loginWithAbort(CK_SESSION_HANDLE hSession, const std::string& pin)
{
    std::vector<CK_UTF8CHAR> pinVec(pin.begin(), pin.end());
    CK_RV rv = C_Login(hSession, CKU_USER, pinVec.data(), static_cast<CK_ULONG>(pinVec.size()));
    if (rv == CKR_PIN_INCORRECT || rv == CKR_PIN_LOCKED) {
        g_pinFailed = true;
        std::cerr << "\n*** PIN VERIFICATION FAILED (rv=0x" << std::hex << rv << std::dec
                  << "). Aborting all subsequent PIN tests. ***\n"
                  << "*** Check LIBRESCRS_TEST_PIN environment variable. ***\n"
                  << std::endl;
    }
    return rv;
}

#define SKIP_IF_PIN_FAILED()                                                                                           \
    do {                                                                                                               \
        if (g_pinFailed)                                                                                               \
            GTEST_SKIP() << "Skipped: previous PIN verification failed";                                               \
    } while (0)

// ---------------------------------------------------------------------------
// C_SignInit / C_Sign — error cases (no hardware needed)
// ---------------------------------------------------------------------------

TEST(PKCS11Test, SignInitBeforeInit)
{
    CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(C_SignInit(0, &mech, 0), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, SignBeforeInit)
{
    CK_ULONG sigLen = 0;
    EXPECT_EQ(C_Sign(0, nullptr, 0, nullptr, &sigLen), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST_F(PKCS11CardTest, SignInitInvalidSession)
{
    CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
    EXPECT_EQ(C_SignInit(9999, &mech, 0), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, SignWithoutInit)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_BYTE data[1] = {0};
        CK_ULONG sigLen = 256;
        CK_BYTE sig[256];
        EXPECT_EQ(C_Sign(hSession, data, 1, sig, &sigLen), CKR_OPERATION_NOT_INITIALIZED);

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignInitDoubleInit)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Login first — login invalidates cached objects (PACE cards)
        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OPERATION_ACTIVE);
                CK_ULONG sigLen = 0;
                C_Sign(hSession, nullptr, 0, nullptr, &sigLen);
            }
            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// C_SignInit / C_Sign — happy-path tests (hardware-guarded)
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, SignInitInvalidMechanism)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
        CK_OBJECT_HANDLE keyObj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            CK_MECHANISM badMech = {CKM_SHA256, nullptr, 0};
            EXPECT_EQ(C_SignInit(hSession, &badMech, keyObj), CKR_MECHANISM_INVALID);
        }

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignInitWithCertificate)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_OBJECT_CLASS certClass = CKO_CERTIFICATE;
        CK_ATTRIBUTE findTmpl = {CKA_CLASS, &certClass, sizeof(certClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
        CK_OBJECT_HANDLE certObj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &certObj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
            EXPECT_EQ(C_SignInit(hSession, &mech, certObj), CKR_KEY_TYPE_INCONSISTENT);
        }

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignInitWithPrivateKey)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Filter for signing-capable private keys only. Serbian eID (and
        // other eIDs) expose both an authentication key (canSign=FALSE) and
        // a digital-signature key (canSign=TRUE). Without CKA_SIGN=TRUE in
        // the filter, C_FindObjects returns whichever key sorts first,
        // which may be the auth key — SignInit on it legitimately returns
        // CKR_KEY_TYPE_INCONSISTENT rather than the login-state error we
        // want to assert here.
        CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
        CK_BBOOL ckTrue = CK_TRUE;
        CK_ATTRIBUTE findTmpl[] = {
            {CKA_CLASS, &keyClass, sizeof(keyClass)},
            {CKA_SIGN, &ckTrue, sizeof(ckTrue)},
        };
        EXPECT_EQ(C_FindObjectsInit(hSession, findTmpl, 2), CKR_OK);
        CK_OBJECT_HANDLE keyObj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            // Without login, signInit should fail
            CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
            EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_USER_NOT_LOGGED_IN);

            // Login-dependent part requires LIBRESCRS_TEST_PIN
            auto testPIN = getTestPIN();
            if (!testPIN.empty() && !g_pinFailed) {
                CK_RV loginRv = loginWithAbort(hSession, testPIN);
                if (loginRv == CKR_OK) {
                    // Re-find objects — login invalidates cached objects (PACE cards)
                    EXPECT_EQ(C_FindObjectsInit(hSession, findTmpl, 2), CKR_OK);
                    count = 0;
                    EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
                    C_FindObjectsFinal(hSession);

                    if (count > 0) {
                        EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);
                        CK_ULONG sigLen = 0;
                        C_Sign(hSession, nullptr, 0, nullptr, &sigLen);
                    }
                    C_Logout(hSession);
                }
            }
        }

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignSizeQuery)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Login first — login invalidates cached objects (PACE cards)
        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                // Size query: pSignature = NULL
                CK_ULONG sigLen = 0;
                EXPECT_EQ(C_Sign(hSession, nullptr, 0, nullptr, &sigLen), CKR_OK);
                EXPECT_EQ(sigLen, 256u); // RSA-2048

                // Sign state should still be active after size query — consume it
                CK_BYTE dummyData[1] = {0};
                CK_BYTE sigBuf[256];
                sigLen = 256;
                CK_RV rv = C_Sign(hSession, dummyData, 1, sigBuf, &sigLen);
                (void)rv; // may be CKR_OK or CKR_DEVICE_ERROR
            }
            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignAndVerify)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Login first — PACE cards need login before objects become visible
        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_BBOOL bTrue = CK_TRUE;
            CK_ATTRIBUTE findTmpl[] = {
                {CKA_CLASS, &keyClass, sizeof(keyClass)},
                {CKA_SIGN, &bTrue, sizeof(bTrue)},
            };
            EXPECT_EQ(C_FindObjectsInit(hSession, findTmpl, 2), CKR_OK);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                // SHA-256 DigestInfo prefix (19 bytes) + 32-byte hash = 51 bytes
                const CK_BYTE digestInfo[] = {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03,
                                              0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
                                              // SHA-256("test")
                                              0x9f, 0x86, 0xd0, 0x81, 0x88, 0x4c, 0x7d, 0x65, 0x9a, 0x2f, 0xea, 0xa0,
                                              0xc5, 0x5a, 0xd0, 0x15, 0xa3, 0xbf, 0x4f, 0x1b, 0x2b, 0x0b, 0x82, 0x2c,
                                              0xd1, 0x5d, 0x6c, 0x15, 0xb0, 0xf0, 0x0a, 0x08};

                CK_BYTE sigBuf[512];
                CK_ULONG sigLen = sizeof(sigBuf);
                CK_RV rv = C_Sign(hSession, const_cast<CK_BYTE_PTR>(digestInfo), sizeof(digestInfo), sigBuf, &sigLen);
                EXPECT_EQ(rv, CKR_OK) << "C_Sign failed with rv=0x" << std::hex << rv;
                if (rv == CKR_OK) {
                    EXPECT_GT(sigLen, 0u);
                    bool allZero = true;
                    for (CK_ULONG i = 0; i < sigLen; ++i) {
                        if (sigBuf[i] != 0) {
                            allZero = false;
                            break;
                        }
                    }
                    EXPECT_FALSE(allZero);
                }
            } else {
                ADD_FAILURE() << "No private keys found after login";
            }

            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignAndVerifyCombinedSHA256)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_BBOOL bTrue = CK_TRUE;
            CK_ATTRIBUTE findTmpl[] = {
                {CKA_CLASS, &keyClass, sizeof(keyClass)},
                {CKA_SIGN, &bTrue, sizeof(bTrue)},
            };
            EXPECT_EQ(C_FindObjectsInit(hSession, findTmpl, 2), CKR_OK);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                const CK_BYTE msg[] = "hello world";
                CK_BYTE sigBuf[512];
                CK_ULONG sigLen = sizeof(sigBuf);
                CK_RV rv = C_Sign(hSession, const_cast<CK_BYTE_PTR>(msg), sizeof(msg) - 1, sigBuf, &sigLen);
                EXPECT_EQ(rv, CKR_OK) << "C_Sign(CKM_SHA256_RSA_PKCS) failed with rv=0x" << std::hex << rv;
                if (rv == CKR_OK) {
                    EXPECT_GT(sigLen, 0u);
                    bool allZero = true;
                    for (CK_ULONG i = 0; i < sigLen; ++i) {
                        if (sigBuf[i] != 0) {
                            allZero = false;
                            break;
                        }
                    }
                    EXPECT_FALSE(allZero);
                }
            } else {
                ADD_FAILURE() << "No signing keys found after login";
            }

            C_Logout(hSession);
        }
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignConsumesState)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        // Login first — login invalidates cached objects (PACE cards)
        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                CK_BYTE data[1] = {0};
                CK_BYTE sigBuf[256];
                CK_ULONG sigLen = sizeof(sigBuf);
                C_Sign(hSession, data, 1, sigBuf, &sigLen);

                // Second sign should fail — state consumed
                sigLen = sizeof(sigBuf);
                EXPECT_EQ(C_Sign(hSession, data, 1, sigBuf, &sigLen), CKR_OPERATION_NOT_INITIALIZED);
            }
            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// C_GetMechanismList / C_GetMechanismInfo tests
// ---------------------------------------------------------------------------

TEST(PKCS11Test, GetMechanismListBeforeInit)
{
    CK_ULONG count = 0;
    EXPECT_EQ(C_GetMechanismList(0, nullptr, &count), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, GetMechanismInfoBeforeInit)
{
    CK_MECHANISM_INFO info;
    EXPECT_EQ(C_GetMechanismInfo(0, CKM_RSA_PKCS, &info), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST_F(PKCS11CardTest, GetMechanismListValid)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        // Size query
        CK_ULONG mechCount = 0;
        EXPECT_EQ(C_GetMechanismList(slot, nullptr, &mechCount), CKR_OK);
        EXPECT_GE(mechCount, 1u);

        // Fill list
        std::vector<CK_MECHANISM_TYPE> mechs(mechCount);
        CK_ULONG fillMechCount = mechCount;
        EXPECT_EQ(C_GetMechanismList(slot, mechs.data(), &fillMechCount), CKR_OK);
        EXPECT_EQ(fillMechCount, mechCount);

        // CKM_RSA_PKCS should be present
        bool found = false;
        for (CK_ULONG i = 0; i < fillMechCount; ++i) {
            if (mechs[i] == CKM_RSA_PKCS)
                found = true;
        }
        EXPECT_TRUE(found);
    }
}

TEST_F(PKCS11CardTest, GetMechanismInfoRSAPKCS)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_MECHANISM_INFO info;
        EXPECT_EQ(C_GetMechanismInfo(slot, CKM_RSA_PKCS, &info), CKR_OK);
        EXPECT_GE(info.ulMinKeySize, 1024u);
        EXPECT_LE(info.ulMaxKeySize, 8192u);
        EXPECT_LE(info.ulMinKeySize, info.ulMaxKeySize);
        EXPECT_TRUE(info.flags & CKF_SIGN);

        // Unsupported mechanism
        EXPECT_EQ(C_GetMechanismInfo(slot, CKM_SHA256, &info), CKR_MECHANISM_INVALID);
    }
}

// ---------------------------------------------------------------------------
// CKM_RSA_PKCS_PSS — error cases (no hardware needed)
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, SignInitPSSNoParams)
{
    CK_MECHANISM mech = {CKM_RSA_PKCS_PSS, nullptr, 0};
    EXPECT_EQ(C_SignInit(9999, &mech, 0), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, SignInitPSSMissingParams)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
        CK_OBJECT_HANDLE keyObj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            // Raw PSS (without hash) is unsupported — must be rejected
            CK_MECHANISM mechNoParam = {CKM_RSA_PKCS_PSS, nullptr, 0};
            EXPECT_EQ(C_SignInit(hSession, &mechNoParam, keyObj), CKR_MECHANISM_INVALID);

            CK_ULONG dummy = 0;
            CK_MECHANISM mechBadLen = {CKM_RSA_PKCS_PSS, &dummy, sizeof(CK_ULONG)};
            EXPECT_EQ(C_SignInit(hSession, &mechBadLen, keyObj), CKR_MECHANISM_INVALID);

            // Combined hash+PSS with missing params — mechanism is valid but params invalid
            CK_MECHANISM mechCombinedNoParam = {CKM_SHA256_RSA_PKCS_PSS, nullptr, 0};
            EXPECT_EQ(C_SignInit(hSession, &mechCombinedNoParam, keyObj), CKR_MECHANISM_PARAM_INVALID);

            CK_MECHANISM mechCombinedBadLen = {CKM_SHA256_RSA_PKCS_PSS, &dummy, sizeof(CK_ULONG)};
            EXPECT_EQ(C_SignInit(hSession, &mechCombinedBadLen, keyObj), CKR_MECHANISM_PARAM_INVALID);
        }

        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// Mechanism list — hardware-guarded
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, GetMechanismListContents)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_ULONG mechCount = 0;
        C_GetMechanismList(slot, nullptr, &mechCount);
        std::vector<CK_MECHANISM_TYPE> mechs(mechCount);
        C_GetMechanismList(slot, mechs.data(), &mechCount);

        bool foundPKCS = false, foundPSS = false;
        for (CK_ULONG i = 0; i < mechCount; ++i) {
            if (mechs[i] == CKM_RSA_PKCS)
                foundPKCS = true;
            if (mechs[i] == CKM_SHA256_RSA_PKCS_PSS)
                foundPSS = true;
        }
        EXPECT_TRUE(foundPKCS);
        // Combined hash+PSS mechanisms are advertised for TLS 1.3 client auth
        EXPECT_TRUE(foundPSS);

        CK_MECHANISM_INFO info;
        EXPECT_EQ(C_GetMechanismInfo(slot, CKM_RSA_PKCS, &info), CKR_OK);
        EXPECT_GE(info.ulMinKeySize, 1024u);
        EXPECT_LE(info.ulMaxKeySize, 8192u);
        EXPECT_LE(info.ulMinKeySize, info.ulMaxKeySize);
        EXPECT_TRUE(info.flags & CKF_SIGN);
        EXPECT_TRUE(info.flags & CKF_HW);

        // Combined hash+PSS mechanism info should be valid
        EXPECT_EQ(C_GetMechanismInfo(slot, CKM_SHA256_RSA_PKCS_PSS, &info), CKR_OK);
        EXPECT_TRUE(info.flags & CKF_SIGN);

        // Raw PSS (without hash) must still be rejected
        EXPECT_EQ(C_GetMechanismInfo(slot, CKM_RSA_PKCS_PSS, &info), CKR_MECHANISM_INVALID);
    }
}

TEST_F(PKCS11CardTest, SignAndVerifyPSS)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
        CK_OBJECT_HANDLE keyObj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            CK_RV loginRv = loginWithAbort(hSession, testPIN);
            if (loginRv == CKR_OK) {
                CK_RSA_PKCS_PSS_PARAMS pssParams = {CKM_SHA256, CKG_MGF1_SHA256, 32};
                CK_MECHANISM mechPSS = {CKM_SHA256_RSA_PKCS_PSS, &pssParams, sizeof(pssParams)};
                CK_RV initRv = C_SignInit(hSession, &mechPSS, keyObj);

                if (initRv == CKR_OK) {
                    const CK_BYTE msg[] = "PSS signing test";
                    CK_BYTE sigBuf[512];
                    CK_ULONG sigLen = sizeof(sigBuf);
                    CK_RV rv = C_Sign(hSession, const_cast<CK_BYTE_PTR>(msg), sizeof(msg) - 1, sigBuf, &sigLen);
                    EXPECT_EQ(rv, CKR_OK) << "C_Sign(PSS) failed: 0x" << std::hex << rv;
                    if (rv == CKR_OK) {
                        EXPECT_GT(sigLen, 0u);
                    }
                } else {
                    // Card may not support PSS — skip
                    GTEST_SKIP() << "Card does not support PSS (signInit: 0x" << std::hex << initRv << ")";
                }
                C_Logout(hSession);
            }
        }
        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignUpdateFinalPSS)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
        CK_OBJECT_HANDLE keyObj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            CK_RV loginRv = loginWithAbort(hSession, testPIN);
            if (loginRv == CKR_OK) {
                CK_RSA_PKCS_PSS_PARAMS pssParams = {CKM_SHA256, CKG_MGF1_SHA256, 32};
                CK_MECHANISM mechPSS = {CKM_SHA256_RSA_PKCS_PSS, &pssParams, sizeof(pssParams)};
                CK_RV initRv = C_SignInit(hSession, &mechPSS, keyObj);

                if (initRv == CKR_OK) {
                    CK_BYTE part1[] = "PSS multi";
                    CK_BYTE part2[] = "-part test";
                    EXPECT_EQ(C_SignUpdate(hSession, part1, sizeof(part1) - 1), CKR_OK);
                    EXPECT_EQ(C_SignUpdate(hSession, part2, sizeof(part2) - 1), CKR_OK);

                    CK_BYTE sigBuf[512];
                    CK_ULONG sigLen = sizeof(sigBuf);
                    CK_RV rv = C_SignFinal(hSession, sigBuf, &sigLen);
                    EXPECT_EQ(rv, CKR_OK) << "C_SignFinal(PSS) failed: 0x" << std::hex << rv;
                    if (rv == CKR_OK) {
                        EXPECT_GT(sigLen, 0u);
                    }
                } else {
                    GTEST_SKIP() << "Card does not support PSS";
                }
                C_Logout(hSession);
            }
        }
        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// CKM_SHA*_RSA_PKCS combined hash+sign (TLS 1.2 client auth mechanisms)
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, SignAndVerifyCombinedSHA512)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
        CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
        EXPECT_EQ(C_FindObjectsInit(hSession, &findTmpl, 1), CKR_OK);
        CK_OBJECT_HANDLE keyObj;
        CK_ULONG count = 0;
        EXPECT_EQ(C_FindObjects(hSession, &keyObj, 1, &count), CKR_OK);
        C_FindObjectsFinal(hSession);

        if (count > 0) {
            CK_RV loginRv = loginWithAbort(hSession, testPIN);
            if (loginRv == CKR_OK) {
                // CKM_SHA512_RSA_PKCS: data is raw message, library hashes it
                CK_MECHANISM mech = {CKM_SHA512_RSA_PKCS, nullptr, 0};
                CK_RV initRv = C_SignInit(hSession, &mech, keyObj);

                if (initRv == CKR_OK) {
                    const CK_BYTE msg[] = "hello world";
                    CK_BYTE sigBuf[256];
                    CK_ULONG sigLen = sizeof(sigBuf);
                    CK_RV rv = C_Sign(hSession, const_cast<CK_BYTE_PTR>(msg), sizeof(msg) - 1, sigBuf, &sigLen);
                    if (rv == CKR_OK) {
                        EXPECT_EQ(sigLen, 256u);
                        bool allZero = true;
                        for (CK_ULONG i = 0; i < sigLen; ++i) {
                            if (sigBuf[i] != 0) {
                                allZero = false;
                                break;
                            }
                        }
                        EXPECT_FALSE(allZero);
                    }
                } else {
                    GTEST_SKIP() << "Card does not support CKM_SHA512_RSA_PKCS";
                }

                C_Logout(hSession);
            }
        }

        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// Multi-part signing (C_SignUpdate / C_SignFinal)
// ---------------------------------------------------------------------------

TEST(PKCS11Test, SignUpdateBeforeInit)
{
    CK_BYTE data[] = {0x01};
    EXPECT_EQ(C_SignUpdate(1, data, sizeof(data)), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST(PKCS11Test, SignFinalBeforeInit)
{
    CK_BYTE sig[256];
    CK_ULONG sigLen = sizeof(sig);
    EXPECT_EQ(C_SignFinal(1, sig, &sigLen), CKR_CRYPTOKI_NOT_INITIALIZED);
}

TEST_F(PKCS11CardTest, SignUpdateInvalidSession)
{
    CK_BYTE data[] = {0x01};
    EXPECT_EQ(C_SignUpdate(9999, data, sizeof(data)), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, SignFinalInvalidSession)
{
    CK_BYTE sig[256];
    CK_ULONG sigLen = sizeof(sig);
    EXPECT_EQ(C_SignFinal(9999, sig, &sigLen), CKR_SESSION_HANDLE_INVALID);
}

TEST_F(PKCS11CardTest, SignUpdateWithoutSignInit)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_BYTE data[] = {0x01};
        EXPECT_EQ(C_SignUpdate(hSession, data, sizeof(data)), CKR_OPERATION_NOT_INITIALIZED);

        C_CloseSession(hSession);
    }
}

TEST_F(PKCS11CardTest, SignFinalWithoutSignInit)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_BYTE sig[256];
        CK_ULONG sigLen = sizeof(sig);
        EXPECT_EQ(C_SignFinal(hSession, sig, &sigLen), CKR_OPERATION_NOT_INITIALIZED);

        C_CloseSession(hSession);
    }
}

// C_SignUpdate must reject CKM_RSA_PKCS (single-part only)
TEST_F(PKCS11CardTest, SignUpdateRejectsSinglePartMechanism)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        auto testPIN = getTestPIN();
        if (!testPIN.empty() && !g_pinFailed) {
            CK_RV loginRv = loginWithAbort(hSession, testPIN);
            if (loginRv == CKR_OK) {
                CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
                CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
                C_FindObjectsInit(hSession, &findTmpl, 1);
                CK_OBJECT_HANDLE keyObj;
                CK_ULONG count = 0;
                C_FindObjects(hSession, &keyObj, 1, &count);
                C_FindObjectsFinal(hSession);

                if (count > 0) {
                    CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
                    EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                    CK_BYTE data[] = {0x01, 0x02, 0x03};
                    // CKM_RSA_PKCS is single-part — SignUpdate must fail
                    EXPECT_EQ(C_SignUpdate(hSession, data, sizeof(data)), CKR_FUNCTION_NOT_SUPPORTED);

                    // Operation should be terminated after error
                    EXPECT_EQ(C_SignUpdate(hSession, data, sizeof(data)), CKR_OPERATION_NOT_INITIALIZED);
                }

                C_Logout(hSession);
            }
        }

        C_CloseSession(hSession);
    }
}

// C_Sign must fail after C_SignUpdate (multi-part started)
TEST_F(PKCS11CardTest, SignRejectsAfterSignUpdate)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            C_FindObjectsInit(hSession, &findTmpl, 1);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            C_FindObjects(hSession, &keyObj, 1, &count);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                CK_BYTE data[] = "hello";
                EXPECT_EQ(C_SignUpdate(hSession, data, sizeof(data) - 1), CKR_OK);

                // C_Sign must fail — multi-part already started
                CK_BYTE sigBuf[256];
                CK_ULONG sigLen = sizeof(sigBuf);
                EXPECT_EQ(C_Sign(hSession, data, sizeof(data) - 1, sigBuf, &sigLen), CKR_FUNCTION_FAILED);

                // Operation should be terminated
                EXPECT_EQ(C_SignUpdate(hSession, data, sizeof(data) - 1), CKR_OPERATION_NOT_INITIALIZED);
            }

            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

// C_SignFinal size query (pSignature==NULL) must not consume sign state
TEST_F(PKCS11CardTest, SignFinalSizeQuery)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            C_FindObjectsInit(hSession, &findTmpl, 1);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            C_FindObjects(hSession, &keyObj, 1, &count);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                CK_BYTE data[] = "test data for size query";
                EXPECT_EQ(C_SignUpdate(hSession, data, sizeof(data) - 1), CKR_OK);

                // Size query — should NOT consume state
                CK_ULONG sigLen = 0;
                EXPECT_EQ(C_SignFinal(hSession, nullptr, &sigLen), CKR_OK);
                EXPECT_GE(sigLen, 256u);

                // Actual sign should still work after size query
                std::vector<CK_BYTE> sigBuf(sigLen);
                EXPECT_EQ(C_SignFinal(hSession, sigBuf.data(), &sigLen), CKR_OK);
                EXPECT_GE(sigLen, 256u);

                // State should be consumed now
                CK_ULONG sigLen2 = sigLen;
                EXPECT_EQ(C_SignFinal(hSession, sigBuf.data(), &sigLen2), CKR_OPERATION_NOT_INITIALIZED);
            }

            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

// Multi-part sign with multiple C_SignUpdate calls
TEST_F(PKCS11CardTest, SignUpdateMultipleChunks)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            C_FindObjectsInit(hSession, &findTmpl, 1);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            C_FindObjects(hSession, &keyObj, 1, &count);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                // Sign "hello world" in two chunks via multi-part
                CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                CK_BYTE chunk1[] = "hello ";
                CK_BYTE chunk2[] = "world";
                EXPECT_EQ(C_SignUpdate(hSession, chunk1, 6), CKR_OK);
                EXPECT_EQ(C_SignUpdate(hSession, chunk2, 5), CKR_OK);

                CK_BYTE sigMulti[256];
                CK_ULONG sigMultiLen = sizeof(sigMulti);
                CK_RV rv = C_SignFinal(hSession, sigMulti, &sigMultiLen);
                EXPECT_EQ(rv, CKR_OK);

                // Now sign the same message in single-part
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);
                CK_BYTE wholeMsg[] = "hello world";
                CK_BYTE sigSingle[256];
                CK_ULONG sigSingleLen = sizeof(sigSingle);
                rv = C_Sign(hSession, wholeMsg, 11, sigSingle, &sigSingleLen);
                EXPECT_EQ(rv, CKR_OK);

                // Both signatures should be identical (same data, same hash, same key)
                EXPECT_EQ(sigMultiLen, sigSingleLen);
                EXPECT_EQ(std::vector<uint8_t>(sigMulti, sigMulti + sigMultiLen),
                          std::vector<uint8_t>(sigSingle, sigSingle + sigSingleLen));
            }

            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

// C_SignUpdate with zero-length data (valid no-op)
TEST_F(PKCS11CardTest, SignUpdateZeroLength)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            C_FindObjectsInit(hSession, &findTmpl, 1);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            C_FindObjects(hSession, &keyObj, 1, &count);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                // Zero-length update should be a valid no-op
                EXPECT_EQ(C_SignUpdate(hSession, nullptr, 0), CKR_OK);

                // Follow up with real data and finish
                CK_BYTE data[] = "test";
                EXPECT_EQ(C_SignUpdate(hSession, data, 4), CKR_OK);

                CK_BYTE sig[256];
                CK_ULONG sigLen = sizeof(sig);
                EXPECT_EQ(C_SignFinal(hSession, sig, &sigLen), CKR_OK);
                EXPECT_GE(sigLen, 256u);
            }

            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

// C_SignFinal must reject CKM_RSA_PKCS (not a combined-hash mechanism)
TEST_F(PKCS11CardTest, SignFinalRejectsSinglePartMechanism)
{
    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        auto testPIN = getTestPIN();
        if (!testPIN.empty() && !g_pinFailed) {
            CK_RV loginRv = loginWithAbort(hSession, testPIN);
            if (loginRv == CKR_OK) {
                CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
                CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
                C_FindObjectsInit(hSession, &findTmpl, 1);
                CK_OBJECT_HANDLE keyObj;
                CK_ULONG count = 0;
                C_FindObjects(hSession, &keyObj, 1, &count);
                C_FindObjectsFinal(hSession);

                if (count > 0) {
                    // Init with CKM_RSA_PKCS (single-part only)
                    CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
                    EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                    // SignFinal should reject — not a multi-part mechanism
                    CK_BYTE sig[256];
                    CK_ULONG sigLen = sizeof(sig);
                    EXPECT_EQ(C_SignFinal(hSession, sig, &sigLen), CKR_FUNCTION_NOT_SUPPORTED);

                    // Operation terminated
                    EXPECT_EQ(C_SignFinal(hSession, sig, &sigLen), CKR_OPERATION_NOT_INITIALIZED);
                }

                C_Logout(hSession);
            }
        }

        C_CloseSession(hSession);
    }
}

// ---------------------------------------------------------------------------
// Slot API without C_GetSlotList (SunPKCS11 pattern)
// ---------------------------------------------------------------------------

TEST_F(PKCS11CardTest, GetTokenInfoWithoutGetSlotList)
{
    CK_TOKEN_INFO info;
    // Even without calling C_GetSlotList, slot 9999 should be invalid
    EXPECT_EQ(C_GetTokenInfo(9999, &info), CKR_SLOT_ID_INVALID);
}

TEST_F(PKCS11CardTest, OpenSessionWithoutGetSlotList)
{
    CK_SESSION_HANDLE hSession;
    // Invalid slot should fail even without prior C_GetSlotList
    EXPECT_EQ(C_OpenSession(9999, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_SLOT_ID_INVALID);
}

// ---------------------------------------------------------------------------
// C_Sign edge cases
// ---------------------------------------------------------------------------

// C_Sign with CKM_RSA_PKCS and data too large (>245 bytes)
TEST_F(PKCS11CardTest, SignDataTooLarge)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            C_FindObjectsInit(hSession, &findTmpl, 1);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            C_FindObjects(hSession, &keyObj, 1, &count);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                // 246 bytes exceeds the 245-byte limit for RSA PKCS#1 v1.5 (2048-bit key)
                std::vector<CK_BYTE> largeData(246, 0x42);
                CK_BYTE sigBuf[256];
                CK_ULONG sigLen = sizeof(sigBuf);
                EXPECT_EQ(C_Sign(hSession, largeData.data(), static_cast<CK_ULONG>(largeData.size()), sigBuf, &sigLen),
                          CKR_DATA_LEN_RANGE);
            }

            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

// C_SignFinal with NULL pulSignatureLen
TEST_F(PKCS11CardTest, SignFinalNullSigLen)
{
    SKIP_IF_PIN_FAILED();
    auto testPIN = getTestPIN();
    if (testPIN.empty())
        GTEST_SKIP() << "Set LIBRESCRS_TEST_PIN to run";

    if (slot != static_cast<CK_SLOT_ID>(-1)) {
        CK_SESSION_HANDLE hSession;
        EXPECT_EQ(C_OpenSession(slot, CKF_SERIAL_SESSION, nullptr, nullptr, &hSession), CKR_OK);

        CK_RV loginRv = loginWithAbort(hSession, testPIN);
        if (loginRv == CKR_OK) {
            CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
            CK_ATTRIBUTE findTmpl = {CKA_CLASS, &keyClass, sizeof(keyClass)};
            C_FindObjectsInit(hSession, &findTmpl, 1);
            CK_OBJECT_HANDLE keyObj;
            CK_ULONG count = 0;
            C_FindObjects(hSession, &keyObj, 1, &count);
            C_FindObjectsFinal(hSession);

            if (count > 0) {
                CK_MECHANISM mech = {CKM_SHA256_RSA_PKCS, nullptr, 0};
                EXPECT_EQ(C_SignInit(hSession, &mech, keyObj), CKR_OK);

                CK_BYTE data[] = "test";
                EXPECT_EQ(C_SignUpdate(hSession, data, 4), CKR_OK);
                EXPECT_EQ(C_SignFinal(hSession, nullptr, nullptr), CKR_ARGUMENTS_BAD);
            }

            C_Logout(hSession);
        }

        C_CloseSession(hSession);
    }
}

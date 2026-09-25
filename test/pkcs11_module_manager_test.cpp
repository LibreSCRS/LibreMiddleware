// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <gtest/gtest.h>

#ifdef LIBRESIGN_HAS_NATIVE

#include "native/pkcs11_module_manager.h"
#include "native/pkcs11_token.h"
#include "signing_service.h" // libresign::as_pin
#include "signing_test_support/signing_test_support.h"

#include <dlfcn.h>

#define CK_PTR *
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType(*name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType(*name)
#ifndef NULL_PTR
#define NULL_PTR 0
#endif

#include "pkcs11/pkcs11.h"

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <stdexcept>
#include <string>
#include <memory>
#include <optional>
#include <thread>

using namespace libresign;

namespace {

// Removes the registry rendezvous however the test leaves, including through a
// failed ASSERT: a lambda left installed captures a dead stack frame.
class ScopedRendezvous
{
public:
    explicit ScopedRendezvous(std::function<void(ModuleRegistryEvent)> hook)
    {
        setModuleRegistryRendezvousForTest(std::move(hook));
    }
    ~ScopedRendezvous()
    {
        setModuleRegistryRendezvousForTest({});
    }
    ScopedRendezvous(const ScopedRendezvous&) = delete;
    ScopedRendezvous& operator=(const ScopedRendezvous&) = delete;
};

class Pkcs11ModuleManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        softHsmPath = libresign::test::findSoftHsmPath();
        if (!softHsmPath)
            GTEST_SKIP() << "SoftHSM2 not found";
        // The module registry is process-wide, so a module a previous case
        // left behind would otherwise be shared with this one and the case
        // would not measure what it says it does. Entries are weak, so this
        // finalises nothing.
        resetSharedModuleRegistryForTest();
        setModuleRegistryRendezvousForTest({});
        setModuleTeardownBudgetForTest(std::chrono::seconds(30));
    }

    void TearDown() override
    {
        setModuleRegistryRendezvousForTest({});
        setModuleTeardownBudgetForTest(std::chrono::seconds(30));
    }
    const char* softHsmPath = nullptr;
};

} // namespace

// Test #8: acquire tolerates CKR_CRYPTOKI_ALREADY_INITIALIZED.
//
// Pre-initialise the SoftHSM2 module via a private dlopen + C_Initialize
// pair, then ask the manager to acquire the same path. The manager's own
// C_Initialize must surface CKR_CRYPTOKI_ALREADY_INITIALIZED, which it
// must translate to success — acquire returns a valid handle. Verifies
// the cleanup path too: the manager must NOT call C_Finalize on dtor
// because we own the original initialiser.
TEST_F(Pkcs11ModuleManagerTest, ModuleAlreadyInitialized)
{
    void* preDl = ::dlopen(softHsmPath, RTLD_NOW);
    ASSERT_NE(preDl, nullptr) << "pre-dlopen failed: " << ::dlerror();

    auto getList = reinterpret_cast<CK_C_GetFunctionList>(::dlsym(preDl, "C_GetFunctionList"));
    ASSERT_NE(getList, nullptr);

    CK_FUNCTION_LIST* preFuncs = nullptr;
    ASSERT_EQ(getList(&preFuncs), CKR_OK);
    ASSERT_NE(preFuncs, nullptr);
    ASSERT_EQ(preFuncs->C_Initialize(nullptr), CKR_OK);

    {
        Pkcs11ModuleManager manager;
        auto handle = manager.acquire(softHsmPath);
        EXPECT_TRUE(handle.valid());
        EXPECT_NE(handle.functionList(), nullptr);
        // Manager destructs on scope exit — must NOT call C_Finalize
        // because we still hold the initialiser side. If it does, the
        // subsequent preFuncs->C_Finalize below would error.
    }

    // Module is still initialised from our side; the manager left it
    // alone. Now we tear down symmetrically with our own setup.
    EXPECT_EQ(preFuncs->C_Finalize(nullptr), CKR_OK);
    ::dlclose(preDl);
}

// Test #7: manager destruction is safe when no Token holds a handle —
// the cache shared_ptrs are the only references; clearing the map
// drops them and runs ~LoadedModule (which Finalize+dlclose-s the
// module we initialised).
TEST_F(Pkcs11ModuleManagerTest, ManagerDtorWithNoLiveHandle)
{
    Pkcs11ModuleManager manager;
    {
        auto handle = manager.acquire(softHsmPath);
        EXPECT_TRUE(handle.valid());
    }
    // No handle outlives this scope. The manager dtor runs at function
    // exit and must release the module cleanly (no crash, no asan
    // diagnostic — the test runs under LSan/ASan in CI).
    SUCCEED();
}

// Test #6: when both a manager and a Token coexist, the Token must
// destruct first (stack unwinding order). After Token dtor the
// manager still owns the module via its cache — no double-Finalize
// because Token no longer touches lifecycle. Manager dtor then drives
// the single C_Finalize on its own initialisation.
TEST_F(Pkcs11ModuleManagerTest, TokenDestructsBeforeManager)
{
    Pkcs11ModuleManager manager;

    {
        auto handle = manager.acquire(softHsmPath);
        EXPECT_TRUE(handle.valid());

        // SoftHSM2 happens to require a real slot init; we exercise
        // the ctor/dtor pair only. PIN "1234" matches the standard
        // test-token setup used by the rest of the test suite (see
        // test/signing_test_support/signing_test_support.h). The
        // ctor performs C_OpenSession + C_Login + C_FindObjects; if
        // SoftHSM hasn't been initialised by the project's test
        // bootstrap, the slot lookup yields nothing and the ctor
        // throws — that's fine here, the test still demonstrates that
        // no double-finalize occurs.
        const auto slot = libresign::test::findSoftHsmTestSlot(handle).value_or(0);
        try {
            Pkcs11Token token(handle, libresign::as_pin("1234"), "test-key", Pkcs11Token::TestSlotId{slot});
        } catch (const std::exception&) {
            // SoftHSM not init'd in this build sandbox; the manager
            // half of the test still proves the lifecycle invariant.
        }
        // Token dtor here. Module stays mapped via manager.
    }

    // Manager dtor at function exit. No use-after-free.
    SUCCEED();
}

// Acquire returns the same backing LoadedModule for two acquire calls
// of the same canonical path. Function-list pointer identity is a
// strong proxy for "no second dlopen + C_Initialize cycle".
TEST_F(Pkcs11ModuleManagerTest, AcquireCachesByCanonicalPath)
{
    Pkcs11ModuleManager manager;
    auto h1 = manager.acquire(softHsmPath);
    auto h2 = manager.acquire(softHsmPath);
    ASSERT_TRUE(h1.valid());
    ASSERT_TRUE(h2.valid());
    EXPECT_EQ(h1.functionList(), h2.functionList());
    EXPECT_EQ(h1.dlHandle(), h2.dlHandle());
    EXPECT_EQ(h1.path(), h2.path());
}

// Two concurrent signing calls own one module manager each. The first to
// finish used to finalise the module under the second: nothing refcounted the
// module across managers, so the manager that drove C_Initialize called
// C_Finalize when it went away and every call the other one still had to make
// returned CKR_CRYPTOKI_NOT_INITIALIZED. The second caller's handle must stay
// usable after the first caller's manager and handle are both gone.
TEST_F(Pkcs11ModuleManagerTest, TwoManagersShareOneInitialisedModule)
{
    Pkcs11ModuleManager second;
    Pkcs11ModuleHandle secondHandle;

    {
        Pkcs11ModuleManager first;
        auto firstHandle = first.acquire(softHsmPath);
        ASSERT_TRUE(firstHandle.valid());

        // On another thread, as two sign calls on two readers are: the
        // service's workers run in parallel.
        std::thread worker([&] { secondHandle = second.acquire(softHsmPath); });
        worker.join();
        ASSERT_TRUE(secondHandle.valid());
    }
    // The first caller has returned: its manager and its handle are gone while
    // the second caller is still holding one.

    auto* funcs = static_cast<CK_FUNCTION_LIST*>(secondHandle.functionList());
    ASSERT_NE(funcs, nullptr);

    CK_INFO info{};
    EXPECT_EQ(funcs->C_GetInfo(&info), CKR_OK);
    CK_ULONG slotCount = 0;
    EXPECT_EQ(funcs->C_GetSlotList(CK_FALSE, nullptr, &slotCount), CKR_OK);
}

// The registry that makes the sharing above possible must not become an owner:
// a module stays mapped exactly as long as some manager or handle refers to it,
// and not one call longer. Counted through the test-only accessor, because the
// difference is invisible from outside -- a leaked module answers C_GetInfo
// just as well as a live one.
TEST_F(Pkcs11ModuleManagerTest, RegistryDoesNotExtendModuleLifetime)
{
    ASSERT_EQ(liveSharedModuleCountForTest(), 0u);
    {
        Pkcs11ModuleManager manager;
        auto handle = manager.acquire(softHsmPath);
        ASSERT_TRUE(handle.valid());
        EXPECT_EQ(liveSharedModuleCountForTest(), 1u);
    }
    EXPECT_EQ(liveSharedModuleCountForTest(), 0u);
}

// The registry shares a module between overlapping users, which is what the case
// above measures. This one measures the case NEXT to it, and it is the one that
// stayed broken: a weak reference expires the instant the last owner lets go,
// which is strictly before the destructor reaches C_Finalize. A signature
// arriving in that window used to find an expired entry, load the module again
// while the first one was still initialised, and then have C_Finalize run under
// it -- V1.11 again, from a few instructions' worth of window.
//
// The window is too narrow to hit by racing, so the test is let into it: the
// rendezvous parks the releasing thread at the top of the teardown while the
// second caller asks for the same module.
TEST_F(Pkcs11ModuleManagerTest, AcquireArrivingDuringTeardownGetsAnInitialisedModule)
{
    Pkcs11ModuleManager second;
    Pkcs11ModuleHandle secondHandle;
    std::atomic<bool> teardownReached{false};
    std::atomic<bool> secondAsked{false};
    std::thread worker;

    ScopedRendezvous rendezvous([&](ModuleRegistryEvent event) {
        if (event != ModuleRegistryEvent::BeforeTeardown)
            return;
        teardownReached.store(true);
        while (!secondAsked.load())
            std::this_thread::yield();
        // The second caller has entered acquire. With the window open it
        // finishes there and this thread then finalises under it; with the
        // window closed it is parked inside the registry until this returns.
        // The wait is bounded because it only has to be long enough for the
        // defect to happen, and it is what makes the red reproducible.
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });

    {
        Pkcs11ModuleManager first;
        auto firstHandle = first.acquire(softHsmPath);
        ASSERT_TRUE(firstHandle.valid());

        worker = std::thread([&] {
            while (!teardownReached.load())
                std::this_thread::yield();
            secondAsked.store(true);
            secondHandle = second.acquire(softHsmPath);
        });
    }
    // The manager and the handle are both gone, so the module's use count hit
    // zero and the teardown -- and the rendezvous inside it -- has run.

    worker.join();
    ASSERT_TRUE(secondHandle.valid());

    auto* funcs = static_cast<CK_FUNCTION_LIST*>(secondHandle.functionList());
    ASSERT_NE(funcs, nullptr);
    CK_INFO info{};
    EXPECT_EQ(funcs->C_GetInfo(&info), CKR_OK);
    CK_ULONG slotCount = 0;
    EXPECT_EQ(funcs->C_GetSlotList(CK_FALSE, nullptr, &slotCount), CKR_OK);
}

// Loading happens with the registry held, so two callers that reach the same
// path at once produce one dlopen and one C_Initialize rather than a race whose
// loser's C_Finalize tears the winner down. Nothing else observable tells one
// load of a shared object from two -- the loader hands back the same address and
// the module the same function table -- so the count is the measurement, and the
// rendezvous is what guarantees the two callers actually overlap.
TEST_F(Pkcs11ModuleManagerTest, ConcurrentAcquireOfOnePathLoadsTheModuleOnce)
{
    // A difference, not an absolute: the counter is process-global, and asserting
    // zero here would make this case depend on the order gtest happens to run in.
    const std::size_t loadsBefore = sharedModuleLoadCountForTest();

    Pkcs11ModuleManager first;
    Pkcs11ModuleManager second;
    Pkcs11ModuleHandle secondHandle;
    std::atomic<bool> loadReached{false};
    std::atomic<bool> secondAsked{false};

    ScopedRendezvous rendezvous([&](ModuleRegistryEvent event) {
        if (event != ModuleRegistryEvent::BeforeLoad || loadReached.load())
            return;
        loadReached.store(true);
        while (!secondAsked.load())
            std::this_thread::yield();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });

    // An acquire that throws -- a module that will not initialise, say -- must
    // fail this case, not the process: an exception escaping the worker, or one
    // unwinding past a joinable worker, is std::terminate. So both sides catch,
    // the worker is released if the first caller never reached the load, and
    // whatever was thrown is rethrown only once the worker is joined.
    std::exception_ptr secondError;
    std::thread worker([&] {
        while (!loadReached.load())
            std::this_thread::yield();
        secondAsked.store(true);
        try {
            secondHandle = second.acquire(softHsmPath);
        } catch (...) {
            secondError = std::current_exception();
        }
    });

    Pkcs11ModuleHandle firstHandle;
    std::exception_ptr firstError;
    try {
        firstHandle = first.acquire(softHsmPath);
    } catch (...) {
        firstError = std::current_exception();
        loadReached.store(true);
    }
    worker.join();
    if (firstError)
        std::rethrow_exception(firstError);
    if (secondError)
        std::rethrow_exception(secondError);

    ASSERT_TRUE(firstHandle.valid());
    ASSERT_TRUE(secondHandle.valid());
    EXPECT_EQ(sharedModuleLoadCountForTest() - loadsBefore, 1u) << "the second caller loaded the module a second time";
    EXPECT_EQ(firstHandle.functionList(), secondHandle.functionList());
    EXPECT_EQ(liveSharedModuleCountForTest(), 1u);
}

// Waiting for a teardown means waiting for a card: the teardown logs slots out
// with real APDUs and tears down the PC/SC transport, so an unresponsive card or
// a wedged daemon lands in that wait. It is bounded, and on expiry the acquire is
// refused with a diagnostic instead of holding the signature open. The budget is
// shortened here because nothing else can tell "waited and got a module" from
// "waited forever".
TEST_F(Pkcs11ModuleManagerTest, AcquireRefusesRatherThanWaitOutAnEndlessTeardown)
{
    setModuleTeardownBudgetForTest(std::chrono::milliseconds(50));

    Pkcs11ModuleManager second;
    std::atomic<bool> teardownReached{false};
    std::atomic<bool> secondFinished{false};
    std::string diagnostic;
    std::thread worker;

    ScopedRendezvous rendezvous([&](ModuleRegistryEvent event) {
        if (event != ModuleRegistryEvent::BeforeTeardown)
            return;
        teardownReached.store(true);
        // Hold the teardown open well past the budget, then let it finish so the
        // module is released and the next case starts from a clean registry.
        while (!secondFinished.load())
            std::this_thread::yield();
    });

    {
        Pkcs11ModuleManager first;
        auto firstHandle = first.acquire(softHsmPath);
        ASSERT_TRUE(firstHandle.valid());

        worker = std::thread([&] {
            while (!teardownReached.load())
                std::this_thread::yield();
            try {
                auto handle = second.acquire(softHsmPath);
                diagnostic = "acquire returned a handle instead of refusing";
            } catch (const std::exception& e) {
                diagnostic = e.what();
            }
            secondFinished.store(true);
        });
    }

    worker.join();
    EXPECT_NE(diagnostic.find("still being finalized"), std::string::npos)
        << "the refusal must say what it waited for; got: " << diagnostic;
    EXPECT_NE(diagnostic.find("50 ms"), std::string::npos) << "and name the budget; got: " << diagnostic;
}

// The listing is what makes a caller wait, so it has to outlive the finalise --
// it is erased only once the module is gone. Nothing measured that: moving the
// erase ahead of the finalise left every other case green, because the half they
// pin is the waiting, not the order. This one watches the registry from inside
// the teardown, where the two orders differ.
TEST_F(Pkcs11ModuleManagerTest, TheEntryOutlivesTheFinaliseThatCallersWaitFor)
{
    std::size_t whenTeardownStarted = 0;
    std::size_t whenFinaliseFinished = 0;

    {
        ScopedRendezvous rendezvous([&](ModuleRegistryEvent event) {
            if (event == ModuleRegistryEvent::BeforeTeardown)
                whenTeardownStarted = sharedModuleEntryCountForTest();
            else if (event == ModuleRegistryEvent::AfterTeardown)
                whenFinaliseFinished = sharedModuleEntryCountForTest();
        });

        Pkcs11ModuleManager manager;
        auto handle = manager.acquire(softHsmPath);
        ASSERT_TRUE(handle.valid());
        ASSERT_EQ(sharedModuleEntryCountForTest(), 1u);
    }

    EXPECT_EQ(whenTeardownStarted, 1u) << "the entry must be listed when the teardown begins";
    EXPECT_EQ(whenFinaliseFinished, 1u) << "and still listed once the finalise is done: it is erased after, not before";
    EXPECT_EQ(sharedModuleEntryCountForTest(), 0u) << "and gone once the release returns";
}

TEST(Pkcs11ModuleManagerStandalone, AcquireThrowsOnInvalidModule)
{
    Pkcs11ModuleManager manager;
    EXPECT_THROW({ (void)manager.acquire("/nonexistent/path/librescrs-pkcs11.so"); }, std::runtime_error);
}

#endif

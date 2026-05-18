// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Pkcs11/SessionInjection.h>

// Single source of truth for the magic cookie + token struct: the public
// C ABI header that the librescrs-pkcs11 module also consumes. Including
// (rather than mirroring) eliminates the ABI-drift risk of two parallel
// definitions falling out of sync.
#include <LibreSCRS/Pkcs11/AttachHook.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <dlfcn.h>

#include <new>
#include <utility>

namespace LibreSCRS::Pkcs11 {

namespace {

using AttachFn = int (*)(const char*, const LibrescrsPkcs11AttachTokenV1*);
using DetachFn = int (*)(const char*);

constexpr int kStatusOk = LIBRESCRS_PKCS11_ATTACH_OK;

} // namespace

std::expected<SessionAttachment, SessionAttachment::Error>
SessionAttachment::attach(const std::filesystem::path& modulePath, std::string readerName,
                          std::shared_ptr<LibreSCRS::SmartCard::CardSession> session) noexcept
try {
    if (modulePath.empty() || readerName.empty() || !session)
        return std::unexpected(Error::InvalidArguments);

    // RTLD_NOLOAD: pin the module mapping while this attachment lives.
    // The libresign caller owns the original load lifecycle; this retain
    // protects against a premature dlclose race that would otherwise
    // SEGV inside ~SessionAttachment when the detach hook is dispatched.
    void* handle = ::dlopen(modulePath.c_str(), RTLD_NOLOAD | RTLD_NOW);
    if (!handle) {
        // Defensive fallback: if the module is not yet mapped (rare —
        // libresign always loads first, but external callers may invoke
        // attach before any other module activity), perform a fresh load
        // and let the dlopen refcount keep it pinned.
        handle = ::dlopen(modulePath.c_str(), RTLD_NOW);
        if (!handle)
            return std::unexpected(Error::ModuleNotLoaded);
    }

    auto* attachFn = reinterpret_cast<AttachFn>(::dlsym(handle, "librescrs_pkcs11_attach_session"));
    if (!attachFn) {
        ::dlclose(handle);
        return std::unexpected(Error::DlsymFailed);
    }

    LibrescrsPkcs11AttachTokenV1 token{};
    token.magic = LIBRESCRS_PKCS11_ATTACH_MAGIC_V1;
    // Pass a pointer to our local shared_ptr; the module copy-constructs
    // its registry entry from *sptr inside the hook, so the address is
    // only required to outlive the synchronous hook call.
    token.session_ptr = static_cast<void*>(&session);
    token.flags = 0UL;

    const int rc = attachFn(readerName.c_str(), &token);
    if (rc != kStatusOk) {
        ::dlclose(handle);
        return std::unexpected(Error::Rejected);
    }

    SessionAttachment sa;
    sa.moduleHandle = handle;
    sa.reader = std::move(readerName);
    sa.heldSession = std::move(session);
    return sa;
} catch (const std::bad_alloc&) {
    return std::unexpected(Error::OutOfMemory);
} catch (...) {
    return std::unexpected(Error::OutOfMemory);
}

SessionAttachment::SessionAttachment(SessionAttachment&& other) noexcept
    : moduleHandle(std::exchange(other.moduleHandle, nullptr)), reader(std::move(other.reader)),
      heldSession(std::move(other.heldSession))
{
    other.reader.clear();
    other.heldSession.reset();
}

SessionAttachment& SessionAttachment::operator=(SessionAttachment&& other) noexcept
{
    if (this != &other) {
        detach();
        moduleHandle = std::exchange(other.moduleHandle, nullptr);
        reader = std::move(other.reader);
        heldSession = std::move(other.heldSession);
        other.reader.clear();
        other.heldSession.reset();
    }
    return *this;
}

SessionAttachment::~SessionAttachment()
{
    detach();
}

void SessionAttachment::detach() noexcept
{
    if (!moduleHandle)
        return;

    auto* detachFn = reinterpret_cast<DetachFn>(::dlsym(moduleHandle, "librescrs_pkcs11_detach_session"));
    if (detachFn && !reader.empty())
        (void)detachFn(reader.c_str());

    // CRITICAL ordering: drop any secure channel installed on the session
    // BEFORE dlclose. The PKCS#11 module statically links the SecureChannel
    // TU and therefore ships its own copy of PaceChannel / BacChannel /
    // PlainChannel vtables. A channel established by the module-side
    // PKCS#15 provider holds a vptr into the module image. If we dlclose
    // first, the host's later ~CardSession invokes the channel's virtual
    // destructor through that now-unmapped vtable and crashes.
    //
    // heldSession is a shared_ptr alias of the host's CardSession — all
    // other aliases (SignPage::session, the worker lambda's captured
    // session, SigningService::sign's parameter) observe the same Impl,
    // so clearing the channel here clears it for every alias.
    if (heldSession)
        heldSession->clearActiveChannel();

    ::dlclose(moduleHandle);
    moduleHandle = nullptr;
    reader.clear();
    heldSession.reset();
}

} // namespace LibreSCRS::Pkcs11

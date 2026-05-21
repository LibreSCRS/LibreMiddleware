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

    // The module's lifecycle (dlopen / dlclose / C_Initialize / C_Finalize)
    // is driven by libresign::Pkcs11ModuleManager — the manager keeps the
    // mapping alive across all signing operations. We acquire the
    // attach/detach symbols through a non-retaining lookup that piggy-
    // backs on the already-loaded mapping rather than driving our own
    // dlopen+dlclose pair. RTLD_NOLOAD here is purely a probe: it succeeds
    // iff the module is already in the process address space, without
    // bumping its refcount. If the manager has not loaded the module
    // (external caller skipping the libresign service entry point) we
    // surface ModuleNotLoaded so the caller can route through the
    // manager.
    void* probe = ::dlopen(modulePath.c_str(), RTLD_NOLOAD | RTLD_NOW);
    if (!probe)
        return std::unexpected(Error::ModuleNotLoaded);

    auto* attachFn = reinterpret_cast<AttachFn>(::dlsym(probe, "librescrs_pkcs11_attach_session"));
    // The RTLD_NOLOAD probe itself bumps the loader-side refcount per
    // POSIX (each successful dlopen, even non-retaining-style, requires
    // a matching dlclose). Drop it immediately whether or not the
    // symbol lookup succeeded — the manager retains the real mapping.
    if (!attachFn) {
        ::dlclose(probe);
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
    ::dlclose(probe); // matches the RTLD_NOLOAD dlopen above
    if (rc != kStatusOk)
        return std::unexpected(Error::Rejected);

    SessionAttachment sa;
    sa.modulePath = modulePath;
    sa.reader = std::move(readerName);
    sa.heldSession = std::move(session);
    return sa;
} catch (const std::bad_alloc&) {
    return std::unexpected(Error::OutOfMemory);
} catch (...) {
    return std::unexpected(Error::OutOfMemory);
}

SessionAttachment::SessionAttachment(SessionAttachment&& other) noexcept
    : modulePath(std::move(other.modulePath)), reader(std::move(other.reader)),
      heldSession(std::move(other.heldSession))
{
    other.modulePath.clear();
    other.reader.clear();
    other.heldSession.reset();
}

SessionAttachment& SessionAttachment::operator=(SessionAttachment&& other) noexcept
{
    if (this != &other) {
        detach();
        modulePath = std::move(other.modulePath);
        reader = std::move(other.reader);
        heldSession = std::move(other.heldSession);
        other.modulePath.clear();
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
    if (modulePath.empty() && reader.empty() && !heldSession)
        return;

    // Acquire a non-retaining probe into the module address space so we
    // can dispatch the detach hook. The manager keeps the module mapped
    // for the entire process lifetime, so RTLD_NOLOAD always succeeds
    // here on a healthy host. If it fails (test harness manually
    // unloaded the module, dynamic loader inconsistency), skip the
    // hook — the module has no surviving SessionRegistry entry to
    // clear, and the detach becomes a pure local cleanup.
    if (!modulePath.empty() && !reader.empty()) {
        if (void* probe = ::dlopen(modulePath.c_str(), RTLD_NOLOAD | RTLD_NOW)) {
            if (auto* detachFn = reinterpret_cast<DetachFn>(::dlsym(probe, "librescrs_pkcs11_detach_session")))
                (void)detachFn(reader.c_str());
            ::dlclose(probe);
        }
    }

    // CardSession lifetime stays with the host. The module manager
    // keeps the loaded PKCS#11 module mapped, so any SecureChannel
    // installed on the session via the module-side PKCS#15 probe
    // continues to point at a live vtable across this detach. We
    // intentionally do NOT clear the session's active channel here —
    // the host process owns the channel and may need it for the next
    // sign or for cleanup at the host's own pace.
    modulePath.clear();
    reader.clear();
    heldSession.reset();
}

} // namespace LibreSCRS::Pkcs11

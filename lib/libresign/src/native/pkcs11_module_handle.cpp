// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "native/pkcs11_module_handle.h"

#include <utility>

namespace libresign {

Pkcs11ModuleHandle::Pkcs11ModuleHandle(std::shared_ptr<const Pkcs11ModuleView> moduleView) noexcept
    : view(std::move(moduleView))
{}

void* Pkcs11ModuleHandle::functionList() const noexcept
{
    return view ? view->functions : nullptr;
}

void* Pkcs11ModuleHandle::dlHandle() const noexcept
{
    return view ? view->dlopenHandle : nullptr;
}

const std::filesystem::path& Pkcs11ModuleHandle::path() const noexcept
{
    static const std::filesystem::path empty;
    return view ? view->canonicalPath : empty;
}

} // namespace libresign

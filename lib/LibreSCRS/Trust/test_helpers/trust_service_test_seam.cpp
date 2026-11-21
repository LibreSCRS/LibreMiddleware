// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

// Replaces TrustStoreServiceEntry.cpp in the service's test copy.

#include "trust_service_test_seam.h"

#include "internal/TrustStoreServiceImpl.h"

#include <mutex>
#include <utility>

namespace LibreSCRS::Trust {

namespace {

std::mutex certificateMutex;
std::string certificatePath;

} // namespace

void Testing::setTrustedListSigningCertificate(std::string path)
{
    std::lock_guard lock(certificateMutex);
    certificatePath = std::move(path);
}

libresign::TrustedListEntry TrustStoreService::Impl::entryFor(const TrustedListSource& src) const
{
    libresign::TrustedListEntry entry;
    entry.url = src.url;
    entry.isLotl = src.lotl;
    entry.eager = src.eager;
    std::lock_guard lock(certificateMutex);
    entry.signingCertPath = certificatePath;
    return entry;
}

} // namespace LibreSCRS::Trust

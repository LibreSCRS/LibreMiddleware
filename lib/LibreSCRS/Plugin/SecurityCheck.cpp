// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Plugin/SecurityCheck.h>

namespace LibreSCRS::Plugin {

void SecurityStatus::computeOverall()
{
    overallIntegrity = SecurityCheck::Status::NotPerformed;
    overallAuthenticity = SecurityCheck::Status::NotPerformed;
    overallGenuineness = SecurityCheck::Status::NotPerformed;

    for (const auto& check : checks) {
        SecurityCheck::Status* target = nullptr;
        switch (check.category) {
        case SecurityCategory::DataIntegrity:
            target = &overallIntegrity;
            break;
        case SecurityCategory::Authenticity:
            target = &overallAuthenticity;
            break;
        case SecurityCategory::Genuineness:
            target = &overallGenuineness;
            break;
        case SecurityCategory::Other:
            continue;
        }

        if (check.status == SecurityCheck::Status::Failed) {
            *target = SecurityCheck::Status::Failed;
        } else if (check.status == SecurityCheck::Status::Passed && *target != SecurityCheck::Status::Failed) {
            *target = SecurityCheck::Status::Passed;
        } else if (check.status == SecurityCheck::Status::NotSupported &&
                   *target == SecurityCheck::Status::NotPerformed) {
            *target = SecurityCheck::Status::NotSupported;
        }
    }
}

} // namespace LibreSCRS::Plugin

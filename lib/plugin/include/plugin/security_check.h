// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <string>
#include <vector>

namespace plugin {

struct SecurityCheck {
    std::string checkId;
    std::string category;

    enum Status {
        PASSED,
        FAILED,
        NOT_PERFORMED,
        NOT_SUPPORTED,
        SKIPPED
    };
    Status status = NOT_PERFORMED;

    std::string label;
    std::string detail;
    std::string errorDetail;
};

struct SecurityStatus {
    std::vector<SecurityCheck> checks;

    SecurityCheck::Status overallIntegrity = SecurityCheck::NOT_PERFORMED;
    SecurityCheck::Status overallAuthenticity = SecurityCheck::NOT_PERFORMED;
    SecurityCheck::Status overallGenuineness = SecurityCheck::NOT_PERFORMED;

    void computeOverall();
};

inline std::string statusToString(SecurityCheck::Status s)
{
    switch (s) {
    case SecurityCheck::PASSED: return "PASSED";
    case SecurityCheck::FAILED: return "FAILED";
    case SecurityCheck::NOT_PERFORMED: return "NOT_PERFORMED";
    case SecurityCheck::NOT_SUPPORTED: return "NOT_SUPPORTED";
    case SecurityCheck::SKIPPED: return "SKIPPED";
    }
    return "UNKNOWN";
}

inline SecurityCheck::Status statusFromString(const std::string& s)
{
    if (s == "PASSED") return SecurityCheck::PASSED;
    if (s == "FAILED") return SecurityCheck::FAILED;
    if (s == "NOT_SUPPORTED") return SecurityCheck::NOT_SUPPORTED;
    if (s == "SKIPPED") return SecurityCheck::SKIPPED;
    return SecurityCheck::NOT_PERFORMED;
}

inline void SecurityStatus::computeOverall()
{
    overallIntegrity = SecurityCheck::NOT_PERFORMED;
    overallAuthenticity = SecurityCheck::NOT_PERFORMED;
    overallGenuineness = SecurityCheck::NOT_PERFORMED;

    for (const auto& check : checks) {
        auto& target = (check.category == "data_integrity") ? overallIntegrity
                     : (check.category == "data_authenticity") ? overallAuthenticity
                     : (check.category == "chip_genuineness") ? overallGenuineness
                     : overallIntegrity;

        if (check.category != "data_integrity" &&
            check.category != "data_authenticity" &&
            check.category != "chip_genuineness")
            continue;

        if (check.status == SecurityCheck::FAILED)
            target = SecurityCheck::FAILED;
        else if (check.status == SecurityCheck::PASSED && target != SecurityCheck::FAILED)
            target = SecurityCheck::PASSED;
        else if (check.status == SecurityCheck::NOT_SUPPORTED &&
                 target == SecurityCheck::NOT_PERFORMED)
            target = SecurityCheck::NOT_SUPPORTED;
    }
}

} // namespace plugin

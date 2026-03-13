// SPDX-License-Identifier: LGPL-2.1-or-later
// Copyright hirashix0@proton.me

#ifndef HEALTHCARD_HEALTHCARD_H
#define HEALTHCARD_HEALTHCARD_H

#include "healthcard/healthtypes.h"
#include <cardedge/cardedgetypes.h>
#include <memory>
#include <string>
#include <vector>

namespace smartcard {
class PCSCConnection;
}

namespace healthcard {

class HealthCard
{
public:
    static bool probe(const std::string& readerName);

    explicit HealthCard(const std::string& readerName);
    ~HealthCard();
    HealthCard(const HealthCard&) = delete;
    HealthCard& operator=(const HealthCard&) = delete;

    HealthDocumentData readDocumentData();

    cardedge::CertificateList readCertificates();
    cardedge::PINResult getPINTriesLeft();
    cardedge::PINResult changePIN(const std::string& oldPin, const std::string& newPin);

private:
    std::unique_ptr<smartcard::PCSCConnection> connection;

    void initCard();
    std::vector<uint8_t> readFile(const std::vector<uint8_t>& fileId);
};

} // namespace healthcard

#endif // HEALTHCARD_HEALTHCARD_H

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <string>
#include <utility>
#include <vector>
#include "cardedgetypes.h"

namespace smartcard {
class PCSCConnection;
}

namespace cardedge {

// All functions below assume the PKI applet (AID_PKCS15) is already selected,
// i.e. they are called from within a PkiAppletGuard scope.

// Read and decompress all certificates from the mscp/ directory.
// Returns kxc* (key-exchange) and ksc* (signature) certificates in directory order,
// each paired with its private key FID derived from cmapfile.
CertificateList readCertificates(smartcard::PCSCConnection& conn);

// Return the current PIN retry counter without consuming a retry.
PINResult getPINTriesLeft(smartcard::PCSCConnection& conn);

// Verify the user PIN (null-padded to 8 bytes). Decrements the retry counter on failure.
PINResult verifyPIN(smartcard::PCSCConnection& conn, const std::string& pin);

// Change the user PIN.
PINResult changePIN(smartcard::PCSCConnection& conn, const std::string& oldPin, const std::string& newPin);

// Compute a digital signature using MSE SET (RSA-2048) + PSO Compute Digital Signature.
// data must be a DER DigestInfo; the applet applies PKCS#1 v1.5 padding.
std::vector<uint8_t> signData(smartcard::PCSCConnection& conn, uint16_t keyReference, const std::vector<uint8_t>& data);

// Discover private key FIDs by parsing the cmapfile on the PKI applet.
// Returns { label, keyFID } pairs in certificate order.
std::vector<std::pair<std::string, uint16_t>> discoverKeyReferences(smartcard::PCSCConnection& conn);

} // namespace cardedge

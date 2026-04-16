// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace libresign {

enum class SignatureFormat { PAdES, CAdES, XAdES, ASiC_E, JAdES };

enum class SignaturePackaging { ENVELOPED, DETACHED };

enum class SignatureLevel { B_B, B_T, B_LT, B_LTA };

struct TSAConfig
{
    std::string url;
    int timeoutSeconds = 10;
    bool crlEnabled = true;  // passed to RevocationClient for B-LT/B-LTA
    bool ocspEnabled = true; // passed to RevocationClient for B-LT/B-LTA
};

struct VisualSignatureParams
{
    bool enabled = false;
    int page = -1; // -1 = last page
    float x = 0, y = 0, width = 200, height = 50;
    std::string text;       // Pre-formatted signature text (GUI builds this)
    std::string signerName; // Kept for backward compat
    std::string reason;
    std::string location;
};

struct SigningRequest
{
    std::vector<uint8_t> document;
    std::string fileName;
    SignatureFormat format = SignatureFormat::PAdES;
    SignaturePackaging packaging = SignaturePackaging::ENVELOPED;
    SignatureLevel level = SignatureLevel::B_T;
    TSAConfig tsa;
    VisualSignatureParams visual;
    bool allowExpiredCertificate = false; // for testing with expired certs
};

struct SigningResult
{
    bool success = false;
    std::vector<uint8_t> signedDocument;
    std::string errorMessage;
};

struct TrustedListEntry
{
    std::string url;
    bool isLotl = false;              // TLSource vs LOTLSource
    bool eager = true;                // sync vs background loading
    std::string signingCertPath;      // optional: override pinned cert (PEM or DER file)
};

struct TrustConfig
{
    std::vector<TrustedListEntry> trustedLists;
    std::string cacheDirectory;
    bool crlEnabled = true;
    bool ocspEnabled = true;
};

} // namespace libresign

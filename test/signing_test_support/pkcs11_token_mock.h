// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace libresign::test {

/// @brief Skeleton interface for a mockable PKCS#11 token used in
/// cancellation / disconnect tests.
///
/// LibreMiddleware's current @c libresign::Pkcs11Token is a concrete class
/// constructed directly from a module path + reader name; the signing modules
/// (@c CAdESModule, @c PAdESModule, @c JAdESModule, @c XAdESModule,
/// @c ASiCModule) hold @c Pkcs11Token& references rather than a virtual base.
/// Injecting a mock therefore requires either:
///
///   1. Extracting a virtual base interface from @c Pkcs11Token and routing
///      every signing module through it (cross-cutting refactor — touches
///      every module .cpp file, the signing provider TUs, the native service,
///      and every callsite).
///   2. A templated-of-token approach where modules become class templates
///      parameterised on the token type (also cross-cutting; uglier consumer
///      code).
///
/// Both options are out of scope for the test-infrastructure phase. The
/// shape declared here documents what the mock surface needs once the
/// refactor lands and gives the cancellation tests a single place to track
/// when the dependency lands. Until then the cancellation test bodies in
/// @c test/cancellation_test.cpp run as SKIPPED placeholders so the suite
/// surfaces the expected coverage without a destination implementation.
class IPkcs11Token
{
public:
    virtual ~IPkcs11Token() = default;

    virtual std::vector<uint8_t> sign(std::span<const uint8_t> hash, const std::string& algorithm,
                                      std::span<const uint8_t> rawData) = 0;
    virtual std::vector<uint8_t> certificate() const = 0;
    virtual std::vector<std::vector<uint8_t>> certificateChain() const = 0;
};

/// Configurable mock used by the cancellation tests once the refactor lands.
/// Returns @p signValue from @ref sign by default; if @ref errorOnSign is
/// non-zero, throws @c std::runtime_error("PKCS#11 error: 0x<code>") to
/// simulate @c CKR_TOKEN_REMOVED / @c CKR_PIN_LEN_RANGE / etc.
class MockPkcs11Token : public IPkcs11Token
{
public:
    std::vector<uint8_t> sign(std::span<const uint8_t> /*hash*/, const std::string& /*algorithm*/,
                              std::span<const uint8_t> /*rawData*/) override;
    std::vector<uint8_t> certificate() const override;
    std::vector<std::vector<uint8_t>> certificateChain() const override;

    std::vector<uint8_t> signValue;
    std::vector<uint8_t> cert;
    std::vector<std::vector<uint8_t>> chain;
    unsigned long errorOnSign = 0; // PKCS#11 CK_RV when non-zero
};

} // namespace libresign::test

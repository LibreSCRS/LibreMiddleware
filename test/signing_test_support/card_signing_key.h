// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

// A real card's signing key, reached the way production reaches it: the card's
// plugin on a session for the reader. Only the tests that sign on a card link
// this, so the others carry no plugin registry and no card stack.

#include "native/signing_key.h"

#include <memory>
#include <string>

namespace libresign::test {

struct TestConfig;

/// The signing key of the card in @p config's reader, reached as production
/// reaches it: a session on the reader (with LIBRESCRS_TEST_CAN deposited for
/// PACE when set), the first plugin that claims the card and reads a signing
/// key from it, and that key -- the one labelled @p config.keyAlias, else the
/// first. Null, with @p skipReason filled, when there is no such key.
std::unique_ptr<SigningKey> openCardSigningKey(const TestConfig& config, std::string& skipReason);

} // namespace libresign::test

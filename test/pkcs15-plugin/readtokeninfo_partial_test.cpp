// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Defensive-readTokenInfo regression anchor for pkcs15-plugin.
///
/// Confirms that the pkcs15 plugin's @c readTokenInfo override never escapes
/// an exception to the caller, regardless of:
///
///   - channel activation failure (no live PC/SC connection)
///   - empty / missing EF(TokenInfo) data (label / serial / manufacturer
///     all empty, which would otherwise hit @c CardFieldGroup::addText's
///     "empty value with no prior field" guard rail)
///
/// The plugin returns a (possibly empty) @c CardFieldGroup so the
/// presentation layer can render its placeholder header instead of
/// surfacing a fatal read error.

#include <LibreSCRS/Plugin/CardData.h>
#include <LibreSCRS/Plugin/CardPluginService.h>
#include <LibreSCRS/SmartCard/CardSession.h>
#include <LibreSCRS/SmartCard/detail/CardSessionInjection.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <memory>
#include <stdexcept>

namespace {

std::filesystem::path pluginDir()
{
    return std::filesystem::path(PLUGIN_DIR);
}

std::shared_ptr<LibreSCRS::Plugin::CardPlugin> findPkcs15(LibreSCRS::Plugin::CardPluginService& registry)
{
    for (const auto& p : registry.plugins()) {
        if (p->pluginId() == "pkcs15")
            return p;
    }
    return nullptr;
}

} // namespace

// ---------------------------------------------------------------------------
// Path (a): channel activation fails. A detached @c CardSession has no
// owned PC/SC connection, so @c activateChannelFor short-circuits with
// @c ChannelActivationError::ReaderError. The plugin must catch that
// failure and return an empty group rather than letting an exception
// escape (or, worse, leaking a partially-populated group whose state is
// undefined).
// ---------------------------------------------------------------------------
TEST(Pkcs15ReadTokenInfoPartial, AcquireChannelFailureReturnsEmptyGroupWithoutThrowing)
{
    LibreSCRS::Plugin::CardPluginService registry{pluginDir()};
    auto plugin = findPkcs15(registry);
    ASSERT_NE(plugin, nullptr);

    auto session = LibreSCRS::SmartCard::detail::makeDetachedCardSession("Phantom Reader 0");
    ASSERT_NE(session, nullptr);

    LibreSCRS::Plugin::CardFieldGroup group;
    EXPECT_NO_THROW({ group = plugin->readTokenInfo(*session); });

    // Empty group: no fields populated when activation never reached the
    // EF(TokenInfo) read step.
    EXPECT_TRUE(group.fields.empty());

    // The group key/label are populated up-front so the presentation
    // layer can still render the section header from an empty group.
    EXPECT_EQ(group.groupKey, "token");
}

// ---------------------------------------------------------------------------
// CardFieldGroup::addText contract anchor.
//
// readTokenInfo's defensive helper relies on @c addText throwing on
// `(empty value, empty fields)` so the plugin must guard the call site by
// skipping empty values. This test locks the contract down so a future
// relaxation of @c addText that silently no-ops on empty values surfaces
// here as a failing expectation, prompting a re-check of the plugin's
// skip-on-empty guard.
// ---------------------------------------------------------------------------
TEST(Pkcs15ReadTokenInfoPartial, CardFieldGroupAddTextRejectsEmptyValueOnEmptyGroup)
{
    LibreSCRS::Plugin::CardFieldGroup group;
    group.groupKey = "token";
    group.groupLabel = "Token Info";

    EXPECT_THROW(group.addText("label", "Label", ""), std::logic_error);
    EXPECT_TRUE(group.fields.empty());

    // A non-empty value succeeds, and the subsequent empty-value call
    // becomes safe (returns the last existing field) — this is the
    // upstream contract the plugin relies on when fields are populated
    // out of order.
    EXPECT_NO_THROW(group.addText("serial_number", "Serial Number", "SN-1"));
    EXPECT_EQ(group.fields.size(), 1u);
    EXPECT_NO_THROW(group.addText("label", "Label", ""));
    EXPECT_EQ(group.fields.size(), 1u);
}

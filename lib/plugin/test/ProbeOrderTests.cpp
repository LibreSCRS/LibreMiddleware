// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

/// @file
/// @brief Probe order must be decided by configuration, not by the order the
///        plugin .so files happened to be loaded in.
///
/// Probing stops at the first plugin that claims a card, so when two plugins
/// share a priority AND both claim the same card, whichever sorts first decides
/// what the user is shown. These tests force the REVERSE input order and
/// require the same answer, because a test that only ever feeds the natural
/// order passes for the same accidental reason a manual trial does.

#include "probe_order.h"

#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/SmartCard/CardSession.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <span>
#include <memory>
#include <string>
#include <vector>

namespace {

class NamedPlugin final : public LibreSCRS::Plugin::CardPlugin
{
public:
    NamedPlugin(const std::string& id, int priority)
    {
        setIdentity(id, id, priority);
    }

    LibreSCRS::Plugin::CardCapabilities capabilities() const override
    {
        return {};
    }

    std::span<const LibreSCRS::Plugin::Atr> supportedAtrs() const noexcept override
    {
        return {};
    }

protected:
    LibreSCRS::Plugin::ReadResult doReadCard(LibreSCRS::SmartCard::CardSession& /*session*/,
                                             GroupCallback /*onGroup*/) const override
    {
        return LibreSCRS::Plugin::ReadResult::ok({});
    }
};

std::shared_ptr<LibreSCRS::Plugin::CardPlugin> make(const std::string& id, int priority)
{
    return std::make_shared<NamedPlugin>(id, priority);
}

std::vector<std::string> idsAfterSort(std::vector<std::shared_ptr<LibreSCRS::Plugin::CardPlugin>> plugins)
{
    std::sort(plugins.begin(), plugins.end(), LibreSCRS::Plugin::Internal::probeOrderBefore);
    std::vector<std::string> ids;
    ids.reserve(plugins.size());
    for (const auto& p : plugins) {
        ids.push_back(p->pluginId());
    }
    return ids;
}

} // namespace

// Priority is the primary key and still decides.
TEST(ProbeOrder, LowerPriorityIsProbedFirst)
{
    const auto ids = idsAfterSort({make("late", 900), make("early", 100), make("middle", 500)});
    EXPECT_EQ(ids, (std::vector<std::string>{"early", "middle", "late"}));
}

// The one that matters: two plugins that share a priority. Feed them in both
// orders and require the same answer. Without a tie-break std::sort leaves this
// unspecified -- so the shipped ordering of two 800s would be whatever the
// filesystem handed the loader.
TEST(ProbeOrder, TiedPrioritiesDoNotDependOnLoadOrder)
{
    const auto forward = idsAfterSort({make("alpha", 800), make("bravo", 800)});
    const auto reverse = idsAfterSort({make("bravo", 800), make("alpha", 800)});

    EXPECT_EQ(forward, reverse) << "tied plugins must not reorder with their load order";
    EXPECT_EQ(forward, (std::vector<std::string>{"alpha", "bravo"}));
}

// The same, with the tie in the middle of a larger set: three entries, and the
// tie is NOT at either end -- with two candidates "take the first" and "take
// the last" both pass by accident.
TEST(ProbeOrder, TiedPrioritiesStayPutAmongOtherPriorities)
{
    const std::vector<std::string> expected{"early", "alpha", "bravo", "late"};

    EXPECT_EQ(idsAfterSort({make("early", 100), make("alpha", 800), make("bravo", 800), make("late", 900)}), expected);
    EXPECT_EQ(idsAfterSort({make("late", 900), make("bravo", 800), make("alpha", 800), make("early", 100)}), expected);
    EXPECT_EQ(idsAfterSort({make("bravo", 800), make("late", 900), make("early", 100), make("alpha", 800)}), expected);
}

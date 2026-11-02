// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

/// @file
/// @brief @ref LibreSCRS::Plugin::ScopedPinDeposit — a signing PIN deposited
///        in a card plugin for one operation, erased when the operation ends.

#include <LibreSCRS/Logging.h>
#include <LibreSCRS/Plugin/CardPlugin.h>
#include <LibreSCRS/Secure/String.h>
#include <LibreSCRS/SmartCard/CardSession.h>

namespace LibreSCRS::Plugin {

/// @brief Deposits a PIN in a card plugin for @p session (the plugin's
///        `"pin"` credential) and erases it again when the scope ends,
///        whichever way it ends.
///
/// The one rule every host follows for the PIN of a signature: it lives in
/// the plugin for the operation and no longer -- unless the operation
/// succeeded with a key the card does not want the PIN for every time, and
/// the host chose to keep it for further signatures in the same session
/// (@ref keepForLease). A kept PIN stays deposited until the host erases it
/// or calls @ref CardPlugin::clearCredentials for the session.
///
/// A deposit that throws half-way is erased before the exception leaves the
/// constructor. Erasing never throws out of the destructor; an erase that
/// fails is logged as a warning, since the PIN may then still be in the
/// plugin until its session ends.
///
/// Header-only: nothing here is an exported symbol.
/// @since 5.0
class ScopedPinDeposit
{
public:
    ScopedPinDeposit(CardPlugin& plugin, LibreSCRS::SmartCard::CardSession& session,
                     const LibreSCRS::Secure::String& pin)
        : plugin(&plugin), session(session)
    {
        try {
            plugin.setCredentials(session, "pin", pin);
        } catch (...) {
            erase();
            throw;
        }
    }

    ~ScopedPinDeposit()
    {
        erase();
    }

    /// @brief Keep the PIN deposited past this scope: the operation
    ///        succeeded and the host leases the PIN to the session.
    void keepForLease() noexcept
    {
        plugin = nullptr;
    }

    ScopedPinDeposit(const ScopedPinDeposit&) = delete;
    ScopedPinDeposit& operator=(const ScopedPinDeposit&) = delete;
    ScopedPinDeposit(ScopedPinDeposit&&) = delete;
    ScopedPinDeposit& operator=(ScopedPinDeposit&&) = delete;

private:
    void erase() noexcept
    {
        if (plugin == nullptr)
            return;
        try {
            plugin->setCredentials(session, "pin", LibreSCRS::Secure::String{});
        } catch (...) {
            // The plugin's own session teardown is then what forgets the PIN.
            reportFailedErase();
        }
        plugin = nullptr;
    }

    // The log call allocates and runs the host's sink, either of which can
    // throw; this runs from the destructor.
    static void reportFailedErase() noexcept
    {
        try {
            LibreSCRS::log::warn("could not erase the PIN deposited in the card plugin");
        } catch (...) {
            // Nothing left to report through.
        }
    }

    CardPlugin* plugin;
    LibreSCRS::SmartCard::CardSession& session;
};

} // namespace LibreSCRS::Plugin

// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Plugin/CardPlugin.h>

namespace LibreSCRS::Plugin {

// Key function: this single out-of-line virtual method anchors the vtable +
// typeinfo for CardPlugin to the CardPlugin_Impl archive. Without a key
// function, GCC/Clang emit both as weak symbols in every TU that
// instantiates a derived class, which breaks cross-.so dynamic_cast and
// typeinfo identity under macOS two-level namespaces and Windows dllimport-
// consumer builds. See Itanium C++ ABI §5.1.
//
// Lives inside CardPlugin_Impl (not LibreSCRS_Plugin) so every existing
// CardPlugin consumer — plugins, tests, the host application — pulls it in
// transitively through the same target they already link for the registry.
CardPlugin::~CardPlugin() = default;

} // namespace LibreSCRS::Plugin

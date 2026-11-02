// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <LibreSCRS/Plugin/CardPlugin.h>

namespace LibreSCRS::Plugin {

// Key function (Itanium C++ ABI §5.1): this out-of-line virtual destructor
// makes the translation unit that defines it the one that emits the vtable and
// typeinfo for CardPlugin, instead of a weak copy in every translation unit
// that defines a derived class.
//
// It is compiled into CardPlugin_Impl, an OBJECT library. libLibreSCRS_Plugin
// absorbs it and is the only LibreSCRS library that exports it, together with
// the vtable and typeinfo; a library that needs the plugin layer links
// LibreSCRS_Plugin. A card plugin module absorbs it as well and keeps its copy
// hidden, so type identity of CardPlugin across the host/plugin boundary is
// not guaranteed -- see ~CardPlugin() in CardPlugin.h.
CardPlugin::~CardPlugin() = default;

} // namespace LibreSCRS::Plugin

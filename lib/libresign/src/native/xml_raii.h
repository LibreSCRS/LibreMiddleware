// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <memory>
#include <libxml/tree.h>
#include <libxml/xpath.h>

namespace libresign {

// libxml2 RAII deleters — null-checked because some libxml2 free functions
// are not null-safe.

struct XmlDocDeleter
{
    void operator()(xmlDocPtr p) const
    {
        if (p)
            xmlFreeDoc(p);
    }
};
struct XPathCtxDeleter
{
    void operator()(xmlXPathContextPtr p) const
    {
        if (p)
            xmlXPathFreeContext(p);
    }
};
struct XPathObjDeleter
{
    void operator()(xmlXPathObjectPtr p) const
    {
        if (p)
            xmlXPathFreeObject(p);
    }
};

using XmlDocPtr = std::unique_ptr<xmlDoc, XmlDocDeleter>;
using XPathCtxPtr = std::unique_ptr<xmlXPathContext, XPathCtxDeleter>;
using XPathObjPtr = std::unique_ptr<xmlXPathObject, XPathObjDeleter>;

} // namespace libresign

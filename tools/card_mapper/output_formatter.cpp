// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "output_formatter.h"

#include <format>
#include <sstream>

namespace card_mapper {

std::string formatHex(const std::vector<uint8_t>& bytes)
{
    std::string result;
    for (size_t i = 0; i < bytes.size(); ++i) {
        if (i > 0) {
            result += ' ';
        }
        result += std::format("{:02X}", bytes[i]);
    }
    return result;
}

std::string formatFid(uint8_t hi, uint8_t lo)
{
    return std::format("{:02X}{:02X}", hi, lo);
}

namespace {

std::string formatAsciiTreeImpl(const FileNode& root, const std::string& prefix, bool isLast, int depth)
{
    static const std::string kBranch = "\xe2\x94\x9c\xe2\x94\x80\xe2\x94\x80 "; // ├──
    static const std::string kCorner = "\xe2\x94\x94\xe2\x94\x80\xe2\x94\x80 "; // └──
    static const std::string kPipe = "\xe2\x94\x82   ";                         // │
    static const std::string kSpace = "    ";

    std::string result;

    // Build the current node line
    std::string connector;
    std::string childPrefix;
    if (depth == 0) {
        // Root node — no connector
        connector = "";
        childPrefix = "";
    } else {
        connector = isLast ? kCorner : kBranch;
        childPrefix = prefix + (isLast ? kSpace : kPipe);
    }

    result += prefix + connector + root.name;

    // Add FID if nonzero
    if (root.fidHi != 0 || root.fidLo != 0) {
        result += " (" + formatFid(root.fidHi, root.fidLo) + ")";
    }

    // Add format info
    if (!root.format.empty()) {
        result += std::string(" \xe2\x80\x94 ") + root.format; // —
    }

    // Add size estimate
    if (!root.sizeEstimate.empty()) {
        result += ", " + root.sizeEstimate;
    }

    // Add note
    if (!root.note.empty()) {
        result += " " + root.note;
    }

    result += "\n";

    // Recurse into children
    for (size_t i = 0; i < root.children.size(); ++i) {
        bool last = (i == root.children.size() - 1);
        result += formatAsciiTreeImpl(root.children[i], childPrefix, last, depth + 1);
    }

    return result;
}

} // anonymous namespace

std::string formatAsciiTree(const FileNode& root)
{
    return formatAsciiTreeImpl(root, "", true, 0);
}

static std::string sanitizeId(const std::string& name)
{
    std::string id;
    for (char c : name) {
        if (std::isalnum(static_cast<unsigned char>(c))) {
            id += c;
        }
    }
    return id;
}

std::string formatMermaidTree(const FileNode& root, const std::string& parentId)
{
    std::string result;
    std::string nodeId = parentId.empty() ? sanitizeId(root.name) : parentId + "_" + sanitizeId(root.name);

    // Build node label
    std::string label = root.name;
    if (root.fidHi != 0 || root.fidLo != 0) {
        label += "<br/>" + formatFid(root.fidHi, root.fidLo);
    }
    if (!root.format.empty()) {
        label += std::string(" \xe2\x80\x94 ") + root.format; // —
    }

    if (parentId.empty()) {
        // Root node: start with graph TD
        result += "graph TD\n";
        result += "  " + nodeId + "[\"" + label + "\"]\n";
    } else {
        result += "  " + parentId + " --> " + nodeId + "[\"" + label + "\"]\n";
    }

    for (const auto& child : root.children) {
        result += formatMermaidTree(child, nodeId);
    }

    return result;
}

std::string formatAppletDoc(const AppletInfo& applet)
{
    std::ostringstream out;

    // Title
    out << "# " << applet.name << " \xe2\x80\x94 Applet File System Map\n\n";

    // Overview table
    out << "## Overview\n";
    out << "| Property | Value |\n";
    out << "|----------|-------|\n";
    out << "| Applet | " << applet.description << " |\n";

    for (size_t i = 0; i < applet.aids.size(); ++i) {
        std::string aidLabel = (i < applet.aidNames.size()) ? applet.aidNames[i] : "";
        std::string prefix = (i == 0) ? "| Application AID" : "|";
        out << prefix << " | `" << formatHex(applet.aids[i]) << "`";
        if (!aidLabel.empty()) {
            out << " (" << aidLabel << ")";
        }
        out << " |\n";
    }

    out << "| Authentication | " << applet.authentication << " |\n";
    out << "| Plugin | `" << applet.pluginName << "` |\n";
    out << "\n";

    // File System Structure
    out << "## File System Structure\n\n";

    out << "### ASCII Tree\n";
    out << "```\n";
    out << formatAsciiTree(applet.rootNode);
    out << "```\n\n";

    out << "### Mermaid Diagram\n";
    out << "```mermaid\n";
    out << formatMermaidTree(applet.rootNode);
    out << "```\n\n";

    // Data Elements
    if (!applet.dataFiles.empty()) {
        out << "## Data Elements\n\n";
        for (const auto& df : applet.dataFiles) {
            out << "### " << df.name << " (" << formatFid(df.fidHi, df.fidLo) << ")\n";
            out << "| Tag | Field Key | Name | Type | Example |\n";
            out << "|-----|-----------|------|------|----------|\n";
            for (const auto& tag : df.tags) {
                out << "| " << tag.tag << " | " << tag.fieldKey << " | " << tag.name << " | " << tag.type << " | "
                    << tag.example << " |\n";
            }
            out << "\n";
        }
    }

    // Read Procedure
    if (!applet.readProcedure.empty()) {
        out << "## Read Procedure\n\n";
        for (size_t i = 0; i < applet.readProcedure.size(); ++i) {
            out << (i + 1) << ". " << applet.readProcedure[i] << "\n";
        }
        out << "\n";
    }

    // APDU Trace (verbose)
    if (!applet.apduTrace.empty()) {
        out << "## APDU Trace\n\n";
        out << "```\n";
        out << applet.apduTrace;
        out << "```\n\n";
    }

    return out.str();
}

std::string formatProfileDoc(const ProfileInfo& profile)
{
    std::ostringstream out;

    out << "# " << profile.name << " \xe2\x80\x94 Card Profile\n\n";

    // Overview table
    out << "## Overview\n";
    out << "| Property | Value |\n";
    out << "|----------|-------|\n";
    out << "| Profile | " << profile.description << " |\n";

    // Known ATRs
    if (!profile.knownATRs.empty()) {
        out << "| Known ATRs |";
        for (size_t i = 0; i < profile.knownATRs.size(); ++i) {
            if (i > 0) {
                out << ",";
            }
            out << " `" << profile.knownATRs[i] << "`";
        }
        out << " |\n";
    }

    // Known Cards
    if (!profile.knownCards.empty()) {
        out << "| Known Cards |";
        for (size_t i = 0; i < profile.knownCards.size(); ++i) {
            if (i > 0) {
                out << ",";
            }
            out << " " << profile.knownCards[i];
        }
        out << " |\n";
    }
    out << "\n";

    // Applets Present
    out << "## Applets Present\n\n";
    out << "| Applet | AID | Documentation |\n";
    out << "|--------|-----|---------------|\n";
    for (const auto& ref : profile.applets) {
        out << "| " << ref.name << " | `" << formatHex(ref.aid) << "`"
            << " | [" << ref.name << "](" << ref.docPath << ")"
            << " |\n";
    }
    out << "\n";

    // Notes
    if (!profile.notes.empty()) {
        out << "## Card-Specific Notes\n";
        out << profile.notes << "\n";
    }

    return out.str();
}

} // namespace card_mapper

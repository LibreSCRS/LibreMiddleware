// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace card_mapper {

struct FileNode
{
    std::string name;             // e.g. "EF.DocumentData"
    uint8_t fidHi = 0, fidLo = 0; // e.g. 0x0F, 0x02
    std::string format;           // e.g. "TLV", "binary JPEG", "X.509"
    std::string sizeEstimate;     // e.g. "~120B"
    std::string note;             // e.g. "[Apollo only]"
    bool isDir = false;
    std::vector<FileNode> children;
};

struct TagInfo
{
    uint16_t tag;
    std::string fieldKey;  // e.g. "doc_reg_no"
    std::string name;      // e.g. "Registration number"
    std::string type;      // e.g. "string", "binary"
    std::string example;   // optional example value
};

struct DataFile
{
    std::string name;              // e.g. "EF.DocumentData"
    uint8_t fidHi = 0, fidLo = 0;
    std::vector<TagInfo> tags;
};

struct AppletInfo
{
    std::string name;
    std::string description;
    std::vector<std::vector<uint8_t>> aids;
    std::vector<std::string> aidNames;
    std::string authentication;    // "None", "PIN", "PACE"
    std::string pluginName;
    FileNode rootNode;
    std::vector<DataFile> dataFiles;
    std::vector<std::string> readProcedure;  // step-by-step read instructions
    std::string apduTrace;                    // verbose APDU trace (Markdown section)
};

struct ProfileInfo
{
    std::string name;
    std::string description;
    std::vector<std::string> knownATRs;
    std::vector<std::string> knownCards;
    struct AppletRef
    {
        std::string name;
        std::vector<uint8_t> aid;
        std::string docPath;       // relative link
    };
    std::vector<AppletRef> applets;
    std::string notes;
};

// Generate complete applet Markdown document
std::string formatAppletDoc(const AppletInfo& applet);

// Generate complete profile Markdown document
std::string formatProfileDoc(const ProfileInfo& profile);

// Helpers (also used by tests)
std::string formatAsciiTree(const FileNode& root);
std::string formatMermaidTree(const FileNode& root, const std::string& parentId = "");
std::string formatHex(const std::vector<uint8_t>& bytes);
std::string formatFid(uint8_t hi, uint8_t lo);

} // namespace card_mapper

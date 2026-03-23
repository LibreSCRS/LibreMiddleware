// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include <pkcs15/pkcs15_parser.h>

#include <smartcard/ber.h>

#include <stdexcept>
#include <string>

namespace pkcs15 {

namespace {

// Extract the first OCTET STRING (tag 0x04) value from a BER field tree.
// Searches children recursively through constructed SEQUENCEs.
std::vector<uint8_t> findFirstOctetString(const smartcard::BERField& node)
{
    for (const auto& child : node.children) {
        if (child.tag == 0x04 && !child.constructed) {
            return child.value;
        }
        if (child.constructed) {
            auto result = findFirstOctetString(child);
            if (!result.empty()) {
                return result;
            }
        }
    }
    return {};
}

// Extract the first UTF8String (tag 0x0C) or UTF8-like string from a BER field's children.
std::string findFirstString(const smartcard::BERField& node)
{
    for (const auto& child : node.children) {
        // UTF8String (0x0C), PrintableString (0x13), IA5String (0x16)
        if ((child.tag == 0x0C || child.tag == 0x13 || child.tag == 0x16) && !child.constructed) {
            return child.asString();
        }
        if (child.constructed) {
            auto result = findFirstString(child);
            if (!result.empty()) {
                return result;
            }
        }
    }
    return {};
}

// Find a child BER field by tag. Returns nullptr if not found.
const smartcard::BERField* findChild(const smartcard::BERField& node, uint32_t tag)
{
    for (const auto& child : node.children) {
        if (child.tag == tag) {
            return &child;
        }
    }
    return nullptr;
}

// Parse an ASN.1 INTEGER value from raw bytes (big-endian, possibly signed).
int64_t parseInteger(const std::vector<uint8_t>& bytes)
{
    if (bytes.empty()) {
        return 0;
    }
    int64_t val = 0;
    for (auto b : bytes) {
        val = (val << 8) | b;
    }
    return val;
}

// Extract path bytes from a typeAttributes [1] CONSTRUCTED node.
// Structure: [1] { SEQUENCE { SEQUENCE { OCTET STRING path } [, ...] } }
std::vector<uint8_t> extractPath(const smartcard::BERField& typeAttrs)
{
    // typeAttrs is [1] CONSTRUCTED containing a SEQUENCE
    for (const auto& seq : typeAttrs.children) {
        if (seq.tag == 0x30 && seq.constructed) {
            return findFirstOctetString(seq);
        }
    }
    return {};
}

// Extract key size from typeAttributes [1] CONSTRUCTED node.
// Structure: [1] { SEQUENCE { SEQUENCE { OCTET STRING path }, INTEGER keySize } }
uint16_t extractKeySize(const smartcard::BERField& typeAttrs)
{
    for (const auto& outerSeq : typeAttrs.children) {
        if (outerSeq.tag == 0x30 && outerSeq.constructed) {
            // Look for INTEGER after the path SEQUENCE
            for (const auto& child : outerSeq.children) {
                if (child.tag == 0x02 && !child.constructed) {
                    return static_cast<uint16_t>(parseInteger(child.value));
                }
            }
        }
    }
    return 0;
}

} // anonymous namespace

// =============================================================================
// parseODF — parse EF.ODF (Object Directory File)
//
// Structure: sequence of context-tagged entries [A0]..[A8]
// Each entry: [tag] { SEQUENCE { OCTET STRING path } }
// =============================================================================
ObjectDirectory parseODF(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    ObjectDirectory odf;
    auto root = smartcard::parseBER(data.data(), data.size());

    for (const auto& entry : root.children) {
        auto path = findFirstOctetString(entry);
        if (path.empty()) {
            continue;
        }

        switch (entry.tag) {
        case 0xA0:
            odf.privateKeysPath = std::move(path);
            break;
        case 0xA1:
            odf.publicKeysPath = std::move(path);
            break;
        case 0xA2:
            odf.trustedPublicKeysPath = std::move(path);
            break;
        case 0xA3:
            odf.secretKeysPath = std::move(path);
            break;
        case 0xA4:
            odf.certificatesPath = std::move(path);
            break;
        case 0xA5:
            odf.trustedCertificatesPath = std::move(path);
            break;
        case 0xA6:
            odf.usefulCertificatesPath = std::move(path);
            break;
        case 0xA7:
            odf.dataObjectsPath = std::move(path);
            break;
        case 0xA8:
            odf.authObjectsPath = std::move(path);
            break;
        default:
            break; // silently skip unknown tags
        }
    }

    return odf;
}

// =============================================================================
// parseTokenInfo — parse EF.TokenInfo
//
// TokenInfo ::= SEQUENCE {
//   version          INTEGER,
//   serialNumber     OCTET STRING,
//   manufacturerID   UTF8String OPTIONAL,
//   label            [0] IMPLICIT UTF8String OPTIONAL,
//   tokenFlags       BIT STRING,
//   ...
// }
// =============================================================================
TokenInfo parseTokenInfo(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    TokenInfo info;
    auto root = smartcard::parseBER(data.data(), data.size());

    // The outer SEQUENCE should be the first child of root
    const smartcard::BERField* seq = nullptr;
    for (const auto& child : root.children) {
        if (child.tag == 0x30 && child.constructed) {
            seq = &child;
            break;
        }
    }
    if (!seq) {
        return info;
    }

    // Walk through children in order:
    // [0] INTEGER version
    // [1] OCTET STRING serialNumber
    // [2+] optional: UTF8String manufacturerID, [0] label, BIT STRING tokenFlags
    for (const auto& child : seq->children) {
        if (child.tag == 0x04 && !child.constructed && info.serialNumber.empty()) {
            // OCTET STRING — typically printable ASCII; binary serials will be lossy
            info.serialNumber = child.asString();
        } else if (child.tag == 0x0C && !child.constructed) {
            // UTF8String — manufacturerID
            info.manufacturer = child.asString();
        } else if (child.tag == 0x80 && !child.constructed) {
            // [0] IMPLICIT — label
            info.label = child.asString();
        }
    }

    return info;
}

// =============================================================================
// parseCDF — parse Certificate Directory File
//
// Each entry:
// SEQUENCE {
//   SEQUENCE { UTF8String label }                     -- CommonObjectAttributes
//   SEQUENCE { OCTET STRING id, BOOLEAN authority }   -- CommonCertificateAttributes
//   [1] CONSTRUCTED { ... path ... }                  -- typeAttributes
// }
// =============================================================================
std::vector<CertificateInfo> parseCDF(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    std::vector<CertificateInfo> certs;
    auto root = smartcard::parseBER(data.data(), data.size());

    for (const auto& entry : root.children) {
        if (entry.tag != 0x30 || !entry.constructed) {
            continue;
        }

        CertificateInfo cert;

        // Child 0: CommonObjectAttributes SEQUENCE { UTF8String label }
        if (entry.children.size() >= 1 && entry.children[0].tag == 0x30) {
            cert.label = findFirstString(entry.children[0]);
        }

        // Child 1: CommonCertificateAttributes SEQUENCE { OCTET STRING id, BOOLEAN authority }
        if (entry.children.size() >= 2 && entry.children[1].tag == 0x30) {
            const auto& certAttrs = entry.children[1];
            for (const auto& child : certAttrs.children) {
                if (child.tag == 0x04 && !child.constructed) {
                    cert.id = child.value;
                } else if (child.tag == 0x01 && !child.constructed) {
                    // BOOLEAN: 0x00 = false, anything else = true
                    cert.authority = !child.value.empty() && child.value[0] != 0x00;
                }
            }
        }

        // Child 2: [1] CONSTRUCTED — typeAttributes with path
        const auto* typeAttrs = findChild(entry, 0xA1);
        if (typeAttrs) {
            cert.path = extractPath(*typeAttrs);
        }

        certs.push_back(std::move(cert));
    }

    return certs;
}

// =============================================================================
// parsePrKDF — parse Private Key Directory File
//
// Each entry:
// SEQUENCE {
//   SEQUENCE { UTF8String label }                      -- CommonObjectAttributes
//   SEQUENCE { OCTET STRING id, BIT STRING usage }     -- CommonKeyAttributes
//   [1] CONSTRUCTED { SEQUENCE { path, INTEGER size } } -- typeAttributes
// }
// =============================================================================
std::vector<PrivateKeyInfo> parsePrKDF(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    std::vector<PrivateKeyInfo> keys;
    auto root = smartcard::parseBER(data.data(), data.size());

    for (const auto& entry : root.children) {
        if (entry.tag != 0x30 || !entry.constructed) {
            continue;
        }

        PrivateKeyInfo key;

        // Child 0: CommonObjectAttributes
        if (entry.children.size() >= 1 && entry.children[0].tag == 0x30) {
            key.label = findFirstString(entry.children[0]);
        }

        // Child 1: CommonKeyAttributes
        if (entry.children.size() >= 2 && entry.children[1].tag == 0x30) {
            const auto& keyAttrs = entry.children[1];
            for (const auto& child : keyAttrs.children) {
                if (child.tag == 0x04 && !child.constructed) {
                    key.id = child.value;
                }
            }
        }

        // Child: [1] CONSTRUCTED — typeAttributes with path and key size
        const auto* typeAttrs = findChild(entry, 0xA1);
        if (typeAttrs) {
            key.path = extractPath(*typeAttrs);
            key.keySizeBits = extractKeySize(*typeAttrs);
        }

        keys.push_back(std::move(key));
    }

    return keys;
}

// =============================================================================
// parseAODF — parse Authentication Object Directory File
//
// Each entry:
// SEQUENCE {
//   SEQUENCE { UTF8String label [, BIT STRING flags] }  -- CommonObjectAttributes
//   SEQUENCE { OCTET STRING authId }                    -- CommonAuthObjectAttributes
//   [1] CONSTRUCTED {                                   -- typeAttributes
//     SEQUENCE {                                        -- PinAttributes
//       BIT STRING pinFlags
//       ENUMERATED pinType
//       INTEGER minLength
//       INTEGER storedLength
//       INTEGER maxLength
//       [0] IMPLICIT INTEGER pinReference
//       SEQUENCE { OCTET STRING path }
//     }
//   }
// }
//
// pinFlags bit positions (PKCS#15):
//   bit 1 = local
//   bit 4 = initialized
//   bit 3 = unblock-disabled
// =============================================================================
std::vector<PinInfo> parseAODF(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    std::vector<PinInfo> pins;
    auto root = smartcard::parseBER(data.data(), data.size());

    for (const auto& entry : root.children) {
        if (entry.tag != 0x30 || !entry.constructed) {
            continue;
        }

        PinInfo pin;

        // Child 0: CommonObjectAttributes SEQUENCE { UTF8String label }
        if (entry.children.size() >= 1 && entry.children[0].tag == 0x30) {
            pin.label = findFirstString(entry.children[0]);
        }

        // Child: [1] CONSTRUCTED — typeAttributes containing PinAttributes SEQUENCE
        const auto* typeAttrs = findChild(entry, 0xA1);
        if (!typeAttrs) {
            pins.push_back(std::move(pin));
            continue;
        }

        // Find the PinAttributes SEQUENCE inside [1]
        const smartcard::BERField* pinAttrs = nullptr;
        for (const auto& child : typeAttrs->children) {
            if (child.tag == 0x30 && child.constructed) {
                pinAttrs = &child;
                break;
            }
        }
        if (!pinAttrs) {
            pins.push_back(std::move(pin));
            continue;
        }

        // Parse PinAttributes fields in order:
        // BIT STRING pinFlags, ENUMERATED pinType, INTEGER min, INTEGER stored,
        // INTEGER max, [0] IMPLICIT pinRef, SEQUENCE path
        int intIndex = 0; // track which INTEGER we're on (min=0, stored=1, max=2)
        for (const auto& field : pinAttrs->children) {
            if (field.tag == 0x03 && !field.constructed && field.value.size() >= 2) {
                // BIT STRING pinFlags
                uint8_t flagsByte = field.value[1];
                // PKCS#15 PinFlags: case-sensitive(0), local(1), change-disabled(2),
                //   unblock-disabled(3), initialized(4), needs-padding(5), ...
                // Bit numbering: bit 0 is the MSB of the first content byte
                // So bit 1 (local) = 0x40, bit 3 (unblock-disabled) = 0x10,
                //    bit 4 (initialized) = 0x08, bit 5 (needs-padding) = 0x04
                pin.local = (flagsByte & 0x40) != 0;
                pin.unblockDisabled = (flagsByte & 0x10) != 0;
                pin.initialized = (flagsByte & 0x08) != 0;
            } else if (field.tag == 0x0A && !field.constructed) {
                // ENUMERATED pinType — ASN.1 integers are signed; guard the cast
                auto val = parseInteger(field.value);
                if (val >= 0 && val <= 4) {
                    pin.pinType = static_cast<PinType>(val);
                }
            } else if (field.tag == 0x02 && !field.constructed) {
                // INTEGER — min, stored, max in order
                auto val = static_cast<int>(parseInteger(field.value));
                switch (intIndex) {
                case 0:
                    pin.minLength = val;
                    break;
                case 1:
                    pin.storedLength = val;
                    break;
                case 2:
                    pin.maxLength = val;
                    break;
                default:
                    break;
                }
                intIndex++;
            } else if (field.tag == 0x80 && !field.constructed) {
                // [0] IMPLICIT INTEGER — pinReference
                pin.pinReference = field.value.empty() ? 0 : field.value[0];
            } else if (field.tag == 0x30 && field.constructed) {
                // SEQUENCE — path
                pin.path = findFirstOctetString(field);
            }
        }

        pins.push_back(std::move(pin));
    }

    return pins;
}

} // namespace pkcs15

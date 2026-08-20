// SPDX-License-Identifier: LGPL-2.1-or-later
// SPDX-FileCopyrightText: 2026 hirashix0

#include "pkcs15_parser.h"

#include <ber.h>

#include <algorithm>
#include <stdexcept>
#include <string>

namespace pkcs15 {

namespace {

// Extract the first OCTET STRING (tag 0x04) value from a BER field tree.
// Searches children recursively through constructed SEQUENCEs.
std::vector<uint8_t> findFirstOctetString(const LibreSCRS::SmartCard::Internal::BERField& node)
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
std::string findFirstString(const LibreSCRS::SmartCard::Internal::BERField& node)
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
const LibreSCRS::SmartCard::Internal::BERField* findChild(const LibreSCRS::SmartCard::Internal::BERField& node,
                                                          uint32_t tag)
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
std::vector<uint8_t> extractPath(const LibreSCRS::SmartCard::Internal::BERField& typeAttrs)
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
uint16_t extractKeySize(const LibreSCRS::SmartCard::Internal::BERField& typeAttrs)
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
    auto root = LibreSCRS::SmartCard::Internal::parseBER(data.data(), data.size());

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
// The serialNumber OCTET STRING as a string safe to publish.
//
// PKCS#15 gives serialNumber no character-set contract, and some cards put
// binary in it -- one observed card wraps its ICCSN in a nested ISO 7816 `84`
// TLV. The bytes do not stay put: this value becomes
// CK_TOKEN_INFO.serialNumber, which becomes the `serial` field of every
// pkcs11: URI the token publishes, and it reaches generated documentation,
// where one unprintable byte makes the entire file invalid UTF-8.
//
// So: unwrap a nested `84` TLV if that is exactly what the content is, then
// pass printable ASCII through unchanged (a text serial is an identity that
// existing consumers already match on, and re-encoding it would change that
// identity) and hex-encode anything else -- the same choice the APDU trace
// already makes for binary ids.
[[nodiscard]] std::string renderSerialNumber(const std::vector<uint8_t>& raw)
{
    std::span<const uint8_t> bytes{raw};
    // ISO 7816 `84` (file identifier / ICCSN) wrapping the whole content.
    if (bytes.size() >= 2 && bytes[0] == 0x84 && static_cast<std::size_t>(bytes[1]) + 2 == bytes.size()) {
        bytes = bytes.subspan(2);
    }
    if (bytes.empty()) {
        return {};
    }

    const bool printable = std::all_of(bytes.begin(), bytes.end(), [](uint8_t b) { return b >= 0x20 && b < 0x7F; });
    if (printable) {
        return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
    }

    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const uint8_t b : bytes) {
        out.push_back(kHex[b >> 4]);
        out.push_back(kHex[b & 0x0F]);
    }
    return out;
}

TokenInfo parseTokenInfo(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    TokenInfo info;
    auto root = LibreSCRS::SmartCard::Internal::parseBER(data.data(), data.size());

    // The outer SEQUENCE should be the first child of root
    const LibreSCRS::SmartCard::Internal::BERField* seq = nullptr;
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
            info.serialNumber = renderSerialNumber(child.value);
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
    auto root = LibreSCRS::SmartCard::Internal::parseBER(data.data(), data.size());

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
// Each entry is one alternative of the PrivateKeyType CHOICE, and the OUTER
// tag is the key's algorithm:
//
//   SEQUENCE  (untagged) -- privateRSAKey
//   [0]                  -- privateECKey
//
// with the same body either way:
//   SEQUENCE { UTF8String label, ... }                  -- CommonObjectAttributes
//   SEQUENCE { OCTET STRING id, BIT STRING usage, ... } -- CommonKeyAttributes
//   [1] CONSTRUCTED { SEQUENCE { path [, INTEGER size] } } -- typeAttributes
//
// typeAttributes is [1] for BOTH -- ISO 7816-15 gives it that tag regardless
// of algorithm, so it can never discriminate one. Only the outer tag can.
// =============================================================================
std::vector<PrivateKeyInfo> parsePrKDF(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    std::vector<PrivateKeyInfo> keys;
    auto root = LibreSCRS::SmartCard::Internal::parseBER(data.data(), data.size());

    for (const auto& entry : root.children) {
        if (!entry.constructed) {
            continue;
        }
        // The CHOICE tag IS the algorithm. The remaining alternatives
        // ([1] DH, [2] DSA, [3] KEA) have no representation in KeyType, and a
        // key published under the wrong algorithm is worse than one this build
        // admits it cannot describe -- so they are skipped, not guessed at.
        PrivateKeyInfo key;
        if (entry.tag == 0x30) {
            key.keyType = KeyType::Rsa;
        } else if (entry.tag == 0xA0) {
            key.keyType = KeyType::Ec;
        } else {
            continue;
        }

        // Child 0: CommonObjectAttributes
        if (entry.children.size() >= 1 && entry.children[0].tag == 0x30) {
            key.label = findFirstString(entry.children[0]);
            // authId — OCTET STRING after the label and optional BIT STRING
            // flags — and userConsent, the INTEGER that may follow it. Both are
            // optional, so neither ends the walk: a record carrying only
            // userConsent must still yield it.
            bool pastLabel = false;
            for (const auto& child : entry.children[0].children) {
                if (!pastLabel && (child.tag == 0x0C || child.tag == 0x13 || child.tag == 0x16)) {
                    pastLabel = true;
                } else if (pastLabel && child.tag == 0x04 && !child.constructed && key.authId.empty()) {
                    key.authId = child.value;
                } else if (pastLabel && child.tag == 0x02 && !child.constructed && !child.value.empty()) {
                    key.userConsent = child.value.back();
                }
            }
        }

        // Child 1: CommonKeyAttributes { id, usage, [accessFlags], [keyReference], ... }
        if (entry.children.size() >= 2 && entry.children[1].tag == 0x30) {
            const auto& keyAttrs = entry.children[1];
            bool foundId = false;
            bool foundUsage = false;
            for (const auto& child : keyAttrs.children) {
                if (child.tag == 0x04 && !child.constructed && !foundId) {
                    key.id = child.value;
                    foundId = true;
                } else if (child.tag == 0x03 && !child.constructed && !foundUsage) {
                    // KeyUsageFlags BIT STRING — value[0] = unused bits count.
                    // PKCS#15 bit positions (ASN.1 named bits, MSB-first):
                    //   0=encrypt(0x80), 1=decrypt(0x40), 2=sign(0x20), 3=signRecover(0x10),
                    //   4=wrap(0x08), 5=unwrap(0x04), 6=verify(0x02), 7=verifyRecover(0x01),
                    //   8=derive(byte2:0x80), 9=nonRepudiation(byte2:0x40)
                    foundUsage = true;
                    if (child.value.size() >= 2) {
                        uint8_t flagsByte = child.value[1];
                        bool hasSign = (flagsByte & 0x30) != 0; // sign(0x20) | signRecover(0x10)
                        bool hasNonRepudiation = child.value.size() >= 3 && (child.value[2] & 0x40) != 0;
                        key.canSign = hasSign || hasNonRepudiation;
                    }
                } else if (child.tag == 0x02 && !child.value.empty()) {
                    // keyReference INTEGER (PKCS#15 range 0-255).
                    // .back() is safe: ASN.1 encodes 0x80 as {0x00, 0x80}, .back() = 0x80.
                    key.keyReference = child.value.back();
                }
            }
        }

        // typeAttributes — [1] for every key type, so it carries the path and
        // (for RSA) the modulus length, and says NOTHING about the algorithm.
        // An EC record legitimately has no key size; leaving it 0 is the
        // truthful answer, not a short read.
        if (const auto* typeAttrs = findChild(entry, 0xA1)) {
            key.path = extractPath(*typeAttrs);
            key.keySizeBits = extractKeySize(*typeAttrs);
        }

        keys.push_back(std::move(key));
    }

    return keys;
}

// =============================================================================
// parsePuKDF — parse Public Key Directory File
//
// PublicKeyType is the same CHOICE shape as PrivateKeyType, and the outer tag
// is again the algorithm: the untagged SEQUENCE is publicRSAKey, [0] is
// publicECKey. typeAttributes is [1] for both.
//
// A public key has no authId and no userConsent -- nothing protects it -- so
// only the identity, the reference and the path are lifted. The id is the
// point: it is what pairs this record with its private half and with the
// certificate, and it is the only source of the public key that does not
// require reading and parsing a certificate.
// =============================================================================
std::vector<PublicKeyInfo> parsePuKDF(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    std::vector<PublicKeyInfo> keys;
    auto root = LibreSCRS::SmartCard::Internal::parseBER(data.data(), data.size());

    for (const auto& entry : root.children) {
        if (!entry.constructed) {
            continue;
        }
        PublicKeyInfo key;
        if (entry.tag == 0x30) {
            key.keyType = KeyType::Rsa;
        } else if (entry.tag == 0xA0) {
            key.keyType = KeyType::Ec;
        } else {
            continue; // DH / DSA / KEA have no representation here
        }

        // CommonObjectAttributes — label only.
        if (!entry.children.empty() && entry.children[0].tag == 0x30) {
            key.label = findFirstString(entry.children[0]);
        }

        // CommonKeyAttributes { id, usage, [native], [keyReference], ... }
        if (entry.children.size() >= 2 && entry.children[1].tag == 0x30) {
            bool foundId = false;
            for (const auto& child : entry.children[1].children) {
                if (child.tag == 0x04 && !child.constructed && !foundId) {
                    key.id = child.value;
                    foundId = true;
                } else if (child.tag == 0x02 && !child.constructed && !child.value.empty()) {
                    // keyReference INTEGER. .back() is safe: ASN.1 encodes 0x80
                    // as {0x00, 0x80}, so the low byte is the value.
                    key.keyReference = child.value.back();
                }
            }
        }

        if (const auto* typeAttrs = findChild(entry, 0xA1)) {
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
// pinFlags bit positions (PKCS#15, MSB-first in the first content byte):
//   bit 1 = local
//   bit 2 = change-disabled
//   bit 3 = unblock-disabled
//   bit 4 = initialized
//   bit 6 = unblockingPin
//   bit 7 = soPin
// =============================================================================
std::vector<PinInfo> parseAODF(std::span<const uint8_t> data)
{
    if (data.empty()) {
        return {};
    }

    std::vector<PinInfo> pins;
    auto root = LibreSCRS::SmartCard::Internal::parseBER(data.data(), data.size());

    for (const auto& entry : root.children) {
        if (entry.tag != 0x30 || !entry.constructed) {
            continue;
        }

        PinInfo pin;

        // Child 0: CommonObjectAttributes SEQUENCE { label [, flags]
        // [, authId] [, accessControlRules] }
        if (entry.children.size() >= 1 && entry.children[0].tag == 0x30) {
            pin.label = findFirstString(entry.children[0]);
            // Protecting-object authId — the OCTET STRING after the label
            // (and optional BIT STRING flags) among the DIRECT children.
            // Mirrors parsePrKDF's CommonObjectAttributes extraction; the
            // accessControlRules' nested OCTET STRINGs sit one level
            // deeper inside a constructed SEQUENCE and are not picked up.
            bool pastLabel = false;
            for (const auto& child : entry.children[0].children) {
                if (!pastLabel && (child.tag == 0x0C || child.tag == 0x13 || child.tag == 0x16)) {
                    pastLabel = true;
                } else if (pastLabel && child.tag == 0x04 && !child.constructed) {
                    pin.authId = child.value;
                    break;
                }
            }
        }

        // CommonAuthObjectAttributes — the SEQUENCE between CommonObjectAttributes and [1] typeAttributes
        // Contains this PIN's own PKCS#15 object ID
        for (size_t ci = 1; ci < entry.children.size(); ++ci) {
            const auto& child = entry.children[ci];
            if (child.tag == 0xA1)
                break; // reached typeAttributes
            if (child.tag == 0x30 && child.constructed) {
                for (const auto& inner : child.children) {
                    if (inner.tag == 0x04 && !inner.constructed) {
                        pin.id = inner.value;
                        break;
                    }
                }
                if (!pin.id.empty())
                    break;
            }
        }

        // Child: [1] CONSTRUCTED — typeAttributes containing PinAttributes SEQUENCE
        const auto* typeAttrs = findChild(entry, 0xA1);
        if (!typeAttrs) {
            pins.push_back(std::move(pin));
            continue;
        }

        // Find the PinAttributes SEQUENCE inside [1]
        const LibreSCRS::SmartCard::Internal::BERField* pinAttrs = nullptr;
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
        for (size_t fi = 0; fi < pinAttrs->children.size(); ++fi) {
            const auto& field = pinAttrs->children[fi];

            if (field.tag == 0x03 && !field.constructed && field.value.size() >= 2) {
                uint8_t flagsByte = field.value[1];
                pin.local = (flagsByte & 0x40) != 0;
                pin.changeDisabled = (flagsByte & 0x20) != 0;
                pin.unblockDisabled = (flagsByte & 0x10) != 0;
                pin.initialized = (flagsByte & 0x08) != 0;
                pin.unblockingPin = (flagsByte & 0x02) != 0;
                pin.soPin = (flagsByte & 0x01) != 0;
            } else if (field.tag == 0x0A && !field.constructed) {
                auto val = parseInteger(field.value);
                if (val >= 0 && val <= 4) {
                    pin.pinType = static_cast<PinType>(val);
                }
            } else if (field.tag == 0x02 && !field.constructed) {
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
                    pin.hasMaxLength = true;
                    break;
                default:
                    break;
                }
                intIndex++;
            } else if (field.tag == 0x80 && !field.constructed) {
                pin.pinReference = field.value.empty() ? 0 : field.value[0];
            } else if (field.tag == 0x04 && !field.constructed && field.value.size() == 1) {
                pin.padChar = field.value[0];
            } else if (field.tag == 0x18 && !field.constructed) {
                pin.lastPinChange = field.asString();
            } else if (field.tag == 0x30 && field.constructed) {
                pin.path = findFirstOctetString(field);
            }
        }

        pins.push_back(std::move(pin));
    }

    return pins;
}

} // namespace pkcs15

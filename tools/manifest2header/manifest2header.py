#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

"""Lower a per-plugin manifest.json into a constexpr C++ header.

The output declares per-plugin namespace-scope constants under
``LibreSCRS::Plugin::generated::<id>`` that the plugin's
``supportedAtrs()`` override returns by reference.

Static-lifetime contract (4.0 hardening):
- ``kAtrs`` is emitted as ``inline const std::array<Atr, N>`` at
  namespace scope. The storage duration is therefore static; a
  ``std::span`` over it is safe for the lifetime of the plugin.
- Plugins MUST consume the generated header rather than authoring an
  inline member-vector; the registry caches ``supportedAtrs()`` spans
  and a member-vector would dangle.
- The codegen tool is the only path that produces the canonical shape;
  CardPlugin.h's doxygen on ``supportedAtrs()`` documents the
  non-codegen-bypass requirement so a plugin that wants to author its
  own ``kAtrs`` (e.g. for testing) still uses namespace-scope storage.

Usage:
    manifest2header.py --input lib/X-plugin/manifest.json
                       --output build/.../manifest.h
                       --schema cmake/schemas/plugin-manifest.schema.json

References:
"""

import argparse
import json
import re
import sys
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover — handled with hard-fail in validate().
    jsonschema = None


# Strict pluginId regex used to gate codegen. The pluginId is interpolated
# directly into a C++ ``namespace`` declaration (after ``-`` -> ``_`` swap),
# so any character that breaks an identifier — `:`, `;`, `/`, `\\`,
# whitespace, `{`, `}`, etc. — must be rejected before the lowering
# step runs. Mirrors the schema's ``^[a-z][a-z0-9-]*$`` constraint with
# a length cap; the schema is the primary defence, this is belt-and-
# braces in case the schema is bypassed (jsonschema missing in a stripped
# CI image; manual invocation; future schema relaxation).
PLUGIN_ID_REGEX = re.compile(r"^[a-z][a-z0-9-]{0,63}$")


CAPABILITY_TO_ENUM = {
    "PKI": "CardCapabilities::PKI",
    "PinManagement": "CardCapabilities::PinManagement",
    "IdentityData": "CardCapabilities::IdentityData",
    "EmrtdCrypto": "CardCapabilities::EmrtdCrypto",
}


def hex_string_to_bytes(s: str) -> list[int]:
    return [int(token, 16) for token in s.split()]


def cpp_string_escape(s: str) -> str:
    """Escape a Python string for safe inclusion in a C++ string literal.

    The manifest schema constrains pluginId to ASCII identifier characters,
    but displayName is free-form (arbitrary UTF-8 with minLength=1). Without
    escaping a displayName containing ``"`` or ``\\`` would terminate the
    literal early or emit ill-formed code (CWE-94: code generation /
    injection). This function escapes the small set of characters that have
    syntactic meaning in a C++ string literal; any other byte passes
    through unchanged so non-ASCII display names render correctly.
    """
    out: list[str] = []
    for ch in s:
        if ch == '"' or ch == '\\':
            out.append('\\')
            out.append(ch)
        elif ch == '\n':
            out.append('\\n')
        elif ch == '\r':
            out.append('\\r')
        elif ch == '\t':
            out.append('\\t')
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append(f'\\x{ord(ch):02x}')
        else:
            out.append(ch)
    return "".join(out)


def emit_atr_array(atrs: list[dict]) -> str:
    if not atrs:
        return ""
    lines = []
    for entry in atrs:
        bytes_init = ", ".join(f"0x{b:02X}" for b in hex_string_to_bytes(entry["value"]))
        if entry.get("mask"):
            mask_init = ", ".join(f"0x{b:02X}" for b in hex_string_to_bytes(entry["mask"]))
            lines.append(
                f"    Atr{{ {{{bytes_init}}}, "
                f"std::optional<std::vector<std::uint8_t>>{{std::vector<std::uint8_t>{{{mask_init}}}}} }}"
            )
        else:
            lines.append(f"    Atr{{ {{{bytes_init}}}, std::nullopt }}")
    return ",\n".join(lines)


def validate_plugin_id(plugin_id: str) -> None:
    """Hard-fail on a malformed ``pluginId``.

    The string is interpolated into a C++ ``namespace`` declaration after
    ``-`` -> ``_`` mapping. Any character outside the allowed set would
    produce ill-formed C++ (best case: build error; worst case: code
    injection — e.g. ``"foo}; namespace evil { ..."``). Reject before
    interpolation.
    """
    if not isinstance(plugin_id, str) or not PLUGIN_ID_REGEX.match(plugin_id):
        print(f"manifest pluginId is malformed: {plugin_id!r} "
              f"(must match {PLUGIN_ID_REGEX.pattern})", file=sys.stderr)
        sys.exit(1)


def render(manifest: dict) -> str:
    plugin_id = manifest["pluginId"]
    validate_plugin_id(plugin_id)
    namespace_id = plugin_id.replace("-", "_")
    capabilities = manifest["capabilities"]
    capabilities_expr = (
        " | ".join(CAPABILITY_TO_ENUM[c] for c in capabilities)
        if capabilities else "CardCapabilities::None"
    )
    n_atrs = len(manifest["atrs"])
    atr_body = emit_atr_array(manifest["atrs"])

    header = f"""// Generated from manifest.json. Do not edit.
#pragma once
#include <LibreSCRS/Plugin/PluginTypes.h>
#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace LibreSCRS::Plugin::generated::{namespace_id} {{

inline constexpr std::string_view kPluginId    = "{cpp_string_escape(plugin_id)}";
inline constexpr std::string_view kDisplayName = "{cpp_string_escape(manifest["displayName"])}";
inline constexpr CardCapabilities kCapabilities = {capabilities_expr};

"""

    if n_atrs == 0:
        header += "inline const std::array<Atr, 0> kAtrs{};\n"
    else:
        header += (
            f"inline const std::array<Atr, {n_atrs}> kAtrs{{{{\n"
            f"{atr_body}\n"
            "}};\n"
        )

    header += f"\n}} // namespace LibreSCRS::Plugin::generated::{namespace_id}\n"
    return header


def validate(manifest: dict, schema_path: Path) -> None:
    if jsonschema is None:
        # Hard-fail rather than skip: the schema is the primary line of
        # defence between attacker-controllable manifest input and the
        # generated C++ namespace declaration / capability bitmap. Skipping
        # validation silently was a security footgun. CI must
        # ``pip install jsonschema``; manual invocation must do likewise.
        print("error: jsonschema is required for manifest validation but is not installed.\n"
              "       Install with `pip install jsonschema` (or add it to your CI image).",
              file=sys.stderr)
        sys.exit(1)
    with schema_path.open() as f:
        schema = json.load(f)
    jsonschema.validate(manifest, schema)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--schema", required=True, type=Path)
    args = parser.parse_args()

    with args.input.open() as f:
        manifest = json.load(f)

    try:
        validate(manifest, args.schema)
    except Exception as e:
        print(f"manifest validation failed: {e}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(render(manifest))
    return 0


if __name__ == "__main__":
    sys.exit(main())

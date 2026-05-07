#!/usr/bin/env python3
"""
Generate sorted constexpr OID lookup table from OpenSSL objects.txt + curated TSVs.

Usage:
    generate_oid_table.py --output OUT.cpp INPUT_FILE [INPUT_FILE ...]

Inputs:
    - openssl-objects.txt — OpenSSL native arc format (space-separated arc).
    - *.tsv               — TSV with header `oid<TAB>friendly_name[<TAB>category[<TAB>source]]`.

Output:
    C++ source file with sorted constexpr array of OID → friendly-name pairs
    plus an OidNameTableHandle wrapping it for the lookup function.

Validation:
    - All OIDs are dotted-decimal.
    - Same OID provided by different sources with the SAME name → coalesced.
    - Same OID with DIFFERENT names → first source wins; subsequent
      conflicts logged to stderr (NOT fatal — OpenSSL has duplicates and
      synonyms by design).
"""

import argparse
import sys
from pathlib import Path
from typing import Optional


def parse_openssl_objects(path: Path) -> dict[str, str]:
    """Parse OpenSSL objects.txt arc format with symbolic resolution.

    Format:
        ARC : SHORT_NAME [ : LONG_NAME ]
    where ARC is space-separated tokens. Each token is either a digit
    (literal arc) or a symbolic reference defined by a SHORT_NAME on a
    previous line. Examples:
        0                : ITU-T           : itu-t
        iso 2            : member-body     : ISO Member Body
        member-body 840  : ISO-US          : ISO US Member Body

    Aliases (`!Alias newname existingname`) declare an alias for a previously
    defined symbol; the new name resolves to the same OID.

    Prefer LONG_NAME when present; fall back to SHORT_NAME.
    """
    symbol_to_oid: dict[str, str] = {}
    out: dict[str, str] = {}
    # Pending C-name override from a `!Cname X` directive on the previous
    # line. Applies to the next non-comment entry as an additional alias.
    pending_cname: Optional[str] = None
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("!Alias "):
            # Two forms supported:
            #   !Alias newname existing_symbol
            #     -> newname = existing_symbol's OID
            #   !Alias newname existing_symbol arc1 arc2 ...
            #     -> newname = existing_symbol's OID + .arc1.arc2...
            parts = line.split()
            if len(parts) >= 3:
                new_name = parts[1]
                existing_symbol = parts[2]
                extra_arcs = parts[3:]
                if existing_symbol in symbol_to_oid and all(a.isdigit() for a in extra_arcs):
                    base_oid = symbol_to_oid[existing_symbol]
                    if extra_arcs:
                        symbol_to_oid[new_name] = base_oid + "." + ".".join(extra_arcs)
                    else:
                        symbol_to_oid[new_name] = base_oid
            continue
        if line.startswith("!Cname "):
            # !Cname X — register X as an alias for the OID on the next entry.
            parts = line.split()
            if len(parts) >= 2:
                pending_cname = parts[1]
            continue
        if line.startswith("!"):
            # Other directives (!global, etc.) — ignore.
            pending_cname = None
            continue
        if ":" not in line:
            continue

        parts = [p.strip() for p in line.split(":")]
        if len(parts) < 2:
            continue

        arc_tokens = parts[0].split()
        if not arc_tokens:
            continue

        # Resolve the arc. First token is digit (root) or symbol; subsequent
        # tokens are digits.
        first = arc_tokens[0]
        if first.isdigit():
            base_oid_arcs = [first]
        elif first in symbol_to_oid:
            base_oid_arcs = symbol_to_oid[first].split(".")
        else:
            # Unknown symbol — skip; the upstream file may reference symbols
            # we don't track yet.
            continue

        rest = arc_tokens[1:]
        if not all(t.isdigit() for t in rest):
            continue  # Mixed/ill-formed arc — skip.

        all_arcs = base_oid_arcs + rest
        oid = ".".join(all_arcs)

        short_name = parts[1] if len(parts) >= 2 else ""
        long_name = parts[2] if len(parts) >= 3 and parts[2] else ""

        # Register BOTH short and long name as symbol aliases — OpenSSL uses
        # the long name as the C-identifier for arc references in many places
        # (e.g. `iso 2 : member-body : ISO Member Body`, then `member-body 840`
        # uses long_name "member-body"), but other places use short_name
        # (e.g. `id-pkix 3 : id-kp` then `id-kp 1 : serverAuth`). Registering
        # both maximises subsequent symbolic resolution success.
        if short_name:
            symbol_to_oid[short_name] = oid
        if long_name and long_name != short_name:
            symbol_to_oid[long_name] = oid
        if pending_cname:
            symbol_to_oid[pending_cname] = oid
            pending_cname = None

        # Record the OID with the friendly name (long name preferred for display).
        name = long_name or short_name
        if name:
            out[oid] = name
    return out


def parse_tsv(path: Path) -> dict[str, str]:
    """Parse a 2- to 4-column TSV with `oid<TAB>friendly_name` header."""
    out: dict[str, str] = {}
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    if not lines:
        return out
    # Skip header (first non-comment line).
    started = False
    for line in lines:
        line = line.rstrip("\r\n")
        if not line or line.startswith("#"):
            continue
        if not started:
            started = True
            continue  # header line
        fields = line.split("\t")
        if len(fields) < 2:
            continue
        oid, name = fields[0].strip(), fields[1].strip()
        if oid and name:
            out[oid] = name
    return out


def validate_oid(oid: str) -> bool:
    """Validate dotted-decimal format: digits separated by dots, no empty arcs."""
    if not oid:
        return False
    parts = oid.split(".")
    return all(part.isdigit() for part in parts)


def merge(sources: list[tuple[str, dict[str, str]]]) -> dict[str, str]:
    """Merge OID maps. First source wins on conflict; warn otherwise."""
    merged: dict[str, str] = {}
    seen_source: dict[str, str] = {}
    conflict_count = 0
    for source_label, src in sources:
        for oid, name in src.items():
            if not validate_oid(oid):
                print(
                    f"WARNING: invalid OID format {oid!r} in {source_label}, skipping",
                    file=sys.stderr,
                )
                continue
            if oid in merged:
                if merged[oid] != name:
                    conflict_count += 1
                    if conflict_count <= 5:
                        print(
                            f"INFO: OID {oid} conflict — keeping '{merged[oid]}' "
                            f"(from {seen_source[oid]}); skipping '{name}' "
                            f"(from {source_label})",
                            file=sys.stderr,
                        )
                # Coalesce same name (no-op).
            else:
                merged[oid] = name
                seen_source[oid] = source_label
    if conflict_count > 5:
        print(
            f"INFO: {conflict_count - 5} additional OID conflicts not shown.",
            file=sys.stderr,
        )
    return merged


def emit(merged: dict[str, str], output_path: Path) -> None:
    """Emit sorted C++ constexpr table.

    Output structure:
        anonymous namespace { constexpr OidNameEntry kOidNamesArray[N] = {...}; }
        const OidNameTableHandle kOidNamesTable{kOidNamesArray, N};
    The handle is the symbol the lookup TU links against; the array itself
    stays internal-linkage to avoid ODR concerns across TUs.
    """
    sorted_items = sorted(merged.items())
    lines = [
        "// AUTO-GENERATED by tools/generate_oid_table.py — DO NOT EDIT.",
        "// Regenerate by re-running the build (CMake codegen target) or by",
        "// invoking the tool manually.",
        "//",
        f"// {len(sorted_items)} entries merged from OpenSSL objects.txt + curated TSVs.",
        "",
        "// SPDX-License-Identifier: LGPL-2.1-or-later",
        "// SPDX-FileCopyrightText: 2026 hirashix0",
        "",
        "#ifndef LIBRESCRS_INTERNAL_BUILD",
        "#define LIBRESCRS_INTERNAL_BUILD",
        "#endif",
        '#include "OidDatabase.h"',
        "",
        "#include <cstddef>",
        "",
        "namespace LibreSCRS::Certificate::detail {",
        "",
        "namespace {",
        f"constexpr std::size_t kOidNamesCount = {len(sorted_items)};",
        "",
        f"constexpr OidNameEntry kOidNamesArray[kOidNamesCount] = {{",
    ]
    for oid, name in sorted_items:
        # Escape backslashes + double quotes defensively.
        name_esc = name.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'    {{"{oid}", "{name_esc}"}},')
    lines += [
        "};",
        "",
        "} // anonymous namespace",
        "",
        "const OidNameTableHandle kOidNamesTable{kOidNamesArray, kOidNamesCount};",
        "",
        "} // namespace LibreSCRS::Certificate::detail",
        "",
    ]
    output_path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("inputs", nargs="+", type=Path)
    args = p.parse_args()

    sources: list[tuple[str, dict[str, str]]] = []
    for inp in args.inputs:
        if not inp.exists():
            print(f"ERROR: input file not found: {inp}", file=sys.stderr)
            return 1
        if inp.suffix == ".txt":
            sources.append((inp.name, parse_openssl_objects(inp)))
        elif inp.suffix == ".tsv":
            sources.append((inp.name, parse_tsv(inp)))
        else:
            print(f"ERROR: unrecognized input format: {inp}", file=sys.stderr)
            return 1

    merged = merge(sources)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    emit(merged, args.output)
    print(
        f"Generated {args.output} with {len(merged)} entries "
        f"from {len(sources)} sources",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

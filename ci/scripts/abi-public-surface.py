#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-public-surface.py -- helper of abi-snapshot.sh: the export, import and
# inline-body rules over the public LibreSCRS surface.
#
# The public surface is read from the compiler, not from the header text: the
# installed headers (include/LibreSCRS minus every detail/ directory, exactly
# what `install(DIRECTORY include/LibreSCRS ...)` ships) are compiled as one
# translation unit the way a consumer compiles them -- LIBRESCRS_INTERNAL_BUILD
# undefined -- and clang's JSON AST supplies the mangled name of every function
# and variable they declare, and the qualified name of every class they define.
# A comparison of mangled names needs no parser for C++ or for demangled text.
#
# Not public, even though the AST holds them:
#   - a friend declaration: it names an entity, it does not declare it for the
#     consumer;
#   - anything whose symbol spells a namespace or class named Internal or
#     detail (or a project *_detail namespace), its parameter types included.
#
# An exported symbol is attributed to a public declaration when it is:
#   - the mangled name of a public function or variable (constructors and
#     destructors in every variant the ABI emits: C1/C2, D0/D1/D2);
#   - a thunk, TLS wrapper/init or guard variable of one;
#   - the vtable, VTT, typeinfo or typeinfo name of a class the installed
#     headers DEFINE (a forward declaration does not publish a vtable).
# Matching by mangled name also judges every type in a signature: a function
# whose parameter type no installed header declares has no installed
# declaration to match. The one residual: a type the installed headers only
# forward-declare (a pimpl `Impl`) passes in a signature, which is what the
# private pimpl constructors rely on.
#
# The rules (strict):
#   Exports: every exported symbol rooted in namespace LibreSCRS is
#      attributed and not internal, or is the typeinfo, typeinfo name or
#      vtable of a thrown exception type listed in the allowlist.
#   Imports: every LibreSCRS symbol a SHIPPED image imports (the core
#      libraries, the card plugins, the installed test archive; never a test
#      executable) is exported by a core library, and is public or one of those
#      listed exception symbols (a catch imports the typeinfo).
#   Inline bodies: every LibreSCRS function an inline body of an installed
#      header calls without defining it is exported by a core library, and is
#      public: a consumer that calls the inline function links it.
#   Installed headers: none opens a preprocessor condition on
#      LIBRESCRS_INTERNAL_BUILD -- a consumer and the library see one class.
#   Additions: with a base allowlist (the one at the merge base), every listed
#      entry must already be in it -- the list only shrinks.
#
# Allowlist (ci/abi/5.x-internal-exports.txt): "<library>\t<demangled symbol>\t<reason>".
#   reason "thrown: <why>"    -- the typeinfo, typeinfo name or vtable of an
#                                exception type that leaves its library: a
#                                catch elsewhere needs it exported whether or
#                                not any shipped image imports it. Verified,
#                                not trusted: the library that exports it must
#                                contain a throw of the type -- a call to
#                                __cxa_throw whose typeinfo argument is loaded
#                                from that typeinfo's address or its GOT slot,
#                                read from the x86_64 disassembly. An entry
#                                with no such throw site is stale.
#   An entry for an importer ("imported: ...") is refused: no shipped image
#   may import an internal symbol, so none is listed for one.
#
# usage: abi-public-surface.py --clang C --include-root DIR --exports F
#            --imports F --allowlist F --images F [--base-allowlist F]
#   exports: "<library>\t<binding>\t<mangled>" per export of a core library.
#   imports: "<image>\t<mangled>" per undefined symbol of a shipped image.
#   images:  "<library>\t<path>" per core library, for the throw-site check.
# Exit 0 when every rule holds, 1 on a finding, 2 when it could not judge.

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile

FUNC_KINDS = {
    'FunctionDecl', 'CXXMethodDecl', 'CXXConstructorDecl', 'CXXDestructorDecl',
    'CXXConversionDecl', 'VarDecl',
}
# Subtrees that declare nothing a consumer can call by this exact mangled name.
SKIP_KINDS = {'FriendDecl', 'ClassTemplateDecl', 'FunctionTemplateDecl',
              'ClassTemplateSpecializationDecl', 'ClassTemplatePartialSpecializationDecl',
              'VarTemplateDecl', 'TypeAliasTemplateDecl'}


def fail(msg):
    print(f'FATAL: {msg}', file=sys.stderr)
    sys.exit(2)


def public_headers(root):
    base = os.path.join(root, 'LibreSCRS')
    found = []
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = sorted(d for d in dirnames if d != 'detail')
        for f in filenames:
            if f.endswith(('.h', '.hpp')):
                found.append(os.path.relpath(os.path.join(dirpath, f), root))
    return sorted(found)


def ast_objects(text):
    dec = json.JSONDecoder()
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        obj, i = dec.raw_decode(text, i)
        yield obj


class Surface:
    def __init__(self):
        self.funcs = set()       # mangled names declared (not as friend)
        self.records = set()     # 'N...E' encodings of defined classes
        self.by_id = {}          # AST node id -> mangled name
        self.defined = set()     # mangled names with a body in the headers
        self.called = {}         # referenced node id -> an inline caller's name


def walk_body(node, caller, surface):
    if isinstance(node, dict):
        for key in ('referencedDecl', 'referencedMemberDecl'):
            ref = node.get(key)
            if isinstance(ref, dict) and 'id' in ref:
                surface.called.setdefault(ref['id'], caller)
            elif isinstance(ref, str):
                surface.called.setdefault(ref, caller)
        for child in node.get('inner', []):
            walk_body(child, caller, surface)


def collect(node, path, surface):
    kind = node.get('kind')
    if kind in SKIP_KINDS:
        return
    name = node.get('name') or ''
    if kind == 'NamespaceDecl':
        if not name:  # anonymous namespace: nothing in it is exported
            return
        child_path = path + [name]
    elif kind == 'CXXRecordDecl':
        if node.get('isImplicit') or not name:
            return
        child_path = path + [name]
        if node.get('completeDefinition'):
            surface.records.add('N' + ''.join(f'{len(p)}{p}' for p in child_path) + 'E')
    elif kind in FUNC_KINDS:
        mangled = node.get('mangledName')
        if not mangled:
            return
        surface.by_id[node.get('id')] = mangled
        surface.funcs.add(mangled)
        if kind == 'CXXConstructorDecl':
            surface.funcs.add(mangled.replace('C1E', 'C2E', 1))
            surface.funcs.add(mangled.replace('C1E', 'C3E', 1))
            surface.funcs.add(mangled.replace('C1B', 'C2B', 1))
        elif kind == 'CXXDestructorDecl':
            for v in ('D0E', 'D2E'):
                surface.funcs.add(mangled.replace('D1E', v, 1))
        inner = [c for c in node.get('inner', []) if isinstance(c, dict)]
        body = [c for c in inner if c.get('kind') == 'CompoundStmt']
        if body or node.get('explicitlyDefaulted') or node.get('isImplicit') or \
                (kind == 'VarDecl' and (node.get('init') or inner)):
            surface.defined.add(mangled)
        caller = '::'.join(path + [name])
        for b in (body if kind != 'VarDecl' else inner):
            walk_body(b, caller, surface)
        return
    else:
        child_path = path
    for child in node.get('inner', []):
        if isinstance(child, dict):
            collect(child, child_path, surface)


def measure_surface(clang, root):
    headers = public_headers(root)
    if not headers:
        fail(f'no installed headers under {root}/LibreSCRS -- cannot measure the public surface')
    with tempfile.NamedTemporaryFile('w', suffix='.cpp', delete=False) as tu:
        for h in headers:
            tu.write(f'#include <{h}>\n')
        tu_path = tu.name
    try:
        proc = subprocess.run(
            [clang, '-std=c++23', '-w', '-x', 'c++', '-I', root, '-fsyntax-only',
             '-Xclang', '-ast-dump=json', '-Xclang', '-ast-dump-filter=LibreSCRS', tu_path],
            capture_output=True, text=True)
    except OSError as e:
        fail(f'cannot run {clang}: {e}')
    finally:
        os.unlink(tu_path)
    if proc.returncode != 0:
        sys.stderr.write(proc.stderr[-4000:])
        fail(f'{clang} could not compile the installed headers as a consumer does')
    surface = Surface()
    for obj in ast_objects(proc.stdout):
        if obj.get('kind') == 'NamespaceDecl' and obj.get('name') == 'LibreSCRS':
            collect(obj, [], surface)
    if not surface.funcs and not surface.records:
        fail(f'the AST of {len(headers)} installed header(s) declared nothing -- '
             'the measurement did not happen')
    return surface


THUNK = re.compile(r'^_ZT(?:hn?\d+_|vn?\d+_n?\d+_)')
LIBRESCRS = re.compile(r'^_Z.*9LibreSCRS')
# An internal scope spelled anywhere in the symbol, its parameter types
# included: a public function that takes an Internal:: type is not usable
# through the installed headers either.
INTERNAL_IN_TEXT = re.compile(r'\b(Internal|detail)::|[A-Za-z0-9]_detail::')
TYPEINFO_TEXT = re.compile(r'^(typeinfo for|typeinfo name for|vtable for) ')


def attributed(sym, surface):
    if sym in surface.funcs:
        return True
    m = THUNK.match(sym)
    if m:
        return '_Z' + sym[m.end():] in surface.funcs
    for prefix in ('_ZTH', '_ZTW', '_ZGV'):
        if sym.startswith(prefix):
            return '_Z' + sym[len(prefix):] in surface.funcs
    for prefix in ('_ZTV', '_ZTI', '_ZTS', '_ZTT'):
        if sym.startswith(prefix):
            return sym[len(prefix):] in surface.records
    return False


def demangle(names):
    if not names:
        return []
    try:
        proc = subprocess.run(['c++filt'], input='\n'.join(names) + '\n',
                              capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        fail(f'c++filt failed: {e}')
    out = proc.stdout.split('\n')[:len(names)]
    if len(out) != len(names):
        fail('c++filt returned fewer lines than it was given')
    return out


def read_allowlist(path, strict_refusals):
    entries = {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line.strip() or line.startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) != 3 or not parts[0] or not parts[1]:
                fail(f'{path}:{n}: expected "<library>\\t<demangled symbol>\\t<reason>", got {line!r}')
            reason = parts[2]
            if re.match(r'^imported: ', reason):
                strict_refusals.append(f'line {n}: {parts[0]}  {parts[1]}  -- {reason}')
            elif not re.match(r'^thrown: \S', reason):
                fail(f'{path}:{n}: the reason must start with "thrown: ", got {reason!r}')
            if reason.startswith('thrown:') and not TYPEINFO_TEXT.match(parts[1]):
                fail(f'{path}:{n}: "thrown:" is a reason only for the typeinfo, typeinfo name or vtable '
                     f'of an exception type, not for {parts[1]!r}')
            key = (parts[0], parts[1])
            if key in entries:
                fail(f'{path}:{n}: duplicate entry {parts[1]!r}')
            entries[key] = (n, reason)
    return entries


def internal_build_parts(include_root):
    """Lines of installed headers (include/LibreSCRS minus every detail/
    directory, what install() ships) that open a preprocessor condition on
    LIBRESCRS_INTERNAL_BUILD: such a header shows a consumer one class and the
    library's own build another."""
    hits = []
    root = os.path.join(include_root, 'LibreSCRS')
    cond = re.compile(r'^\s*#\s*(if|ifdef|ifndef|elif)\b.*\bLIBRESCRS_INTERNAL_BUILD\b')
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d != 'detail')
        for name in sorted(filenames):
            if not name.endswith(('.h', '.hpp')):
                continue
            path = os.path.join(dirpath, name)
            with open(path, errors='replace') as f:
                for n, line in enumerate(f, 1):
                    if cond.match(line):
                        hits.append(f'{os.path.relpath(path, include_root)}:{n}: {line.strip()}')
    return hits


def read_rows(path, width):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) != width:
                fail(f'malformed line in {path}: {line!r}')
            rows.append(parts)
    return rows


def bare(sym):
    return sym.split('@', 1)[0]


THROW_WINDOW = 12   # instructions before the call in which the typeinfo argument is loaded
_disassembly = {}


def throws_type(path, typeinfo):
    """True when the image at path calls __cxa_throw with the address of the
    typeinfo symbol `typeinfo` (mangled, _ZTI...) as its argument: loaded from
    the symbol itself or from the GOT slot the dynamic linker fills with it."""
    try:
        syms = subprocess.run(['nm', '-D', '--defined-only', path], capture_output=True, text=True,
                              check=True).stdout
        relocs = subprocess.run(['readelf', '-rW', path], capture_output=True, text=True, check=True).stdout
        if path not in _disassembly:
            _disassembly[path] = subprocess.run(['objdump', '-d', '--no-show-raw-insn', path],
                                                capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as e:
        fail(f'cannot read {path} for the throw-site check: {e}')
    addresses = set()
    for line in syms.splitlines():
        parts = line.split()
        if len(parts) >= 3 and bare(parts[2]) == typeinfo:
            addresses.add(int(parts[0], 16))
    for line in relocs.splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[2].endswith('GLOB_DAT') and bare(parts[4]) == typeinfo:
            addresses.add(int(parts[0], 16))
    if not addresses:
        return False
    recent = []
    for line in _disassembly[path].splitlines():
        if line.endswith('>:'):         # a new function: its loads are not this call's
            recent = []
            continue
        if '\t' not in line:
            continue
        if re.search(r'\bcall\b.*<__cxa_throw(@plt)?>', line):
            if addresses & set(recent[-THROW_WINDOW:]):
                return True
            recent = []
            continue
        m = re.search(r'#\s*([0-9a-f]+)\s*<', line)
        recent.append(int(m.group(1), 16) if m else None)
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--clang', required=True)
    ap.add_argument('--include-root', required=True)
    ap.add_argument('--exports', required=True)
    ap.add_argument('--imports', required=True)
    ap.add_argument('--allowlist', required=True)
    ap.add_argument('--images', required=True)
    ap.add_argument('--base-allowlist')
    args = ap.parse_args()

    strict_refusals = []
    allowlist = read_allowlist(args.allowlist, strict_refusals)
    base = read_allowlist(args.base_allowlist, []) if args.base_allowlist else None
    surface = measure_surface(args.clang, args.include_root)

    exports = read_rows(args.exports, 3)
    imports = read_rows(args.imports, 2)
    images = dict(read_rows(args.images, 2))
    if not exports:
        fail('no exported symbols to judge')

    # Exports -- every one.
    texts = demangle([e[2] for e in exports])
    exporter = {}       # bare mangled -> (library, demangled text as listed)
    offending = {}      # (library, text) -> binding
    mangled_of = {}     # (library, text) -> bare mangled
    for (lib, binding, sym), text in zip(exports, texts):
        b = bare(sym)
        exporter.setdefault(b, (lib, text))
        mangled_of.setdefault((lib, text), b)
        if LIBRESCRS.match(b) and (not attributed(b, surface) or INTERNAL_IN_TEXT.search(text)):
            offending.setdefault((lib, text), binding)

    def offending_key(mangled):
        hit = exporter.get(mangled)
        return hit if hit in offending else None

    rc = 0

    def report(title, lines, advice):
        nonlocal rc
        if not lines:
            return
        rc = 1
        print(f'{title} ({len(lines)}):', file=sys.stderr)
        for line in lines:
            print(f'  {line}', file=sys.stderr)
        print(f'       {advice}', file=sys.stderr)

    report('STRICT: the allowlist names an internal export for an importer',
           strict_refusals,
           'No shipped image may import an internal symbol. The only listed internal exports are the typeinfo, '
           'typeinfo name and vtable of an exception type the library throws ("thrown:").')

    header_parts = internal_build_parts(args.include_root)
    report('INSTALLED HEADER WITH AN INTERNAL-ONLY PART: a preprocessor condition on LIBRESCRS_INTERNAL_BUILD',
           header_parts,
           'An installed header is one header for every consumer. Move the internal declarations to a header '
           'that is not installed.')

    new = sorted(k for k in offending if k not in allowlist)
    report('EXPORT LEAK: exported symbols naming a LibreSCRS entity the installed headers do not '
           'declare (or an Internal/detail one)',
           [f'{lib}  {offending[(lib, text)]}  {text}' for lib, text in new],
           'Hide it (drop LIBRESCRS_PUBLIC_API), or declare it in an installed header as public API.')

    # Imports -- every one of a shipped image.
    imp_libre = [(img, bare(sym)) for img, sym in imports if LIBRESCRS.match(bare(sym))]
    imp_texts = demangle([s for _, s in imp_libre])
    unexported, unlisted = set(), set()
    for (img, sym), text in zip(imp_libre, imp_texts):
        if sym not in exporter:
            unexported.add(f'{img}  {text}')
            continue
        key = offending_key(sym)
        if key is None:
            continue
        # A catch of a listed thrown type imports its typeinfo; nothing else
        # internal may be imported, whatever the list says.
        if key not in allowlist or not allowlist[key][1].startswith('thrown:'):
            unlisted.add(f'{img}  {text}')
    report('IMPORT OF A HIDDEN SYMBOL: shipped images import LibreSCRS symbols no core library exports',
           sorted(unexported),
           'The image fails to load. Call public API, or export the symbol as public API.')
    report('IMPORT OF AN INTERNAL SYMBOL: shipped images import internal exports',
           sorted(unlisted),
           'Call public API instead. The only internal exports an image may import are those of a listed '
           'thrown exception type.')

    # Inline bodies -- calls from inline bodies of installed headers.
    inline_bad = set()
    for ref_id, caller in surface.called.items():
        mangled = surface.by_id.get(ref_id)
        if not mangled or mangled in surface.defined or not LIBRESCRS.match(mangled):
            continue
        variants = [mangled, mangled.replace('C1E', 'C2E', 1), mangled.replace('D1E', 'D2E', 1)]
        found = next((v for v in variants if v in exporter), None)
        if found is None:
            inline_bad.add(f'{caller} calls {demangle([mangled])[0]}, which no core library exports')
            continue
        key = offending_key(found)
        if key is None:
            continue
        inline_bad.add(f'{caller} calls {key[1]}, an internal export')
    report('INLINE BODY REACHES PAST THE PUBLIC SURFACE: inline code in installed headers',
           sorted(inline_bad),
           'A consumer calling the inline function links that symbol. Call public API from the header.')

    # Staleness: an entry must still be an internal export, and the library must
    # still throw its type.
    stale = []
    for key, (n, reason) in sorted(allowlist.items(), key=lambda kv: kv[1][0]):
        if key not in offending:
            stale.append(f'line {n}: {key[0]}  {key[1]}  -- no longer an internal export')
        elif reason.startswith('thrown:'):
            mangled = mangled_of[key]
            path = images.get(key[0])
            if path is None:
                fail(f'no image path for {key[0]} -- cannot verify a "thrown:" entry')
            if not throws_type(path, '_ZTI' + mangled[4:]):
                stale.append(f'line {n}: {key[0]}  {key[1]}  -- {key[0]} has no throw site for this type')
    report(f'STALE ALLOWLIST: entries in {args.allowlist}', stale,
           'Hide the symbol, and delete the line.')

    if base is not None:
        added = sorted((n, key) for key, (n, _) in allowlist.items() if key not in base)
        report('ALLOWLIST GREW: entries the allowlist at the base revision does not hold',
               [f'line {n}: {key[0]}  {key[1]}' for n, key in added],
               'The list only shrinks: an internal export is never added to it.')

    if rc == 0:
        print(f'Every exported, imported and inline-called LibreSCRS symbol is public, or the typeinfo of a '
              f'listed thrown exception type ({len(exports)} exports, {len(imp_libre)} shipped imports judged; '
              f'{len(allowlist)} listed, all "thrown:").')
    sys.exit(rc)


if __name__ == '__main__':
    main()

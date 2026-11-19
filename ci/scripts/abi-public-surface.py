#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-public-surface.py -- helper of abi-snapshot.sh: which exported symbols
# name a LibreSCRS entity that the installed headers do not declare.
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
#     detail (or a project *_detail namespace), its parameter types included:
#     an installed header may forward-declare such an entity for a friend or an
#     inline body, which does not make it API, and a public function that takes
#     such a type cannot be called through the installed headers either.
#
# An exported symbol is attributed to a public declaration when it is:
#   - the mangled name of a public function or variable (constructors and
#     destructors in every variant the ABI emits: C1/C2, D0/D1/D2);
#   - a thunk, TLS wrapper/init or guard variable of one;
#   - the vtable, VTT, typeinfo or typeinfo name of a class the installed
#     headers DEFINE (a forward declaration does not publish a vtable).
# Every other symbol rooted in namespace LibreSCRS is reported. A shape this
# helper does not know is reported too: an export nobody can attribute to a
# public declaration is exactly what the gate exists to refuse.
#
# Matching by mangled name also judges every type in a signature: a function
# whose parameter type no installed header declares has no installed
# declaration to match. The one residual: a type the installed headers only
# forward-declare (a pimpl `Impl`) passes in a signature, which is what the
# private pimpl constructors rely on.
#
# usage: abi-public-surface.py <clang++> <include-root> <exports.tsv> <allowlist> [<base allowlist>]
#   <exports.tsv>: one "<library>\t<binding>\t<mangled>" line per export.
#   <allowlist>: ci/abi/5.x-internal-exports.txt -- the internal exports that
#   shipped images still need, "<library>\t<symbol>\t<reason>". A stale entry
#   (no longer an internal export) fails.
#   <base allowlist>: the list at the base revision; an entry it does not hold
#   fails, so the list only shrinks.
# Exit 0 when every export is public or allowlisted, 1 on a finding, 2 when the
# public surface could not be measured.

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
              'VarTemplateDecl', 'TypeAliasTemplateDecl', 'CompoundStmt'}


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


def collect(node, path, funcs, records):
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
            records.add('N' + ''.join(f'{len(p)}{p}' for p in child_path) + 'E')
    elif kind in FUNC_KINDS:
        mangled = node.get('mangledName')
        if mangled:
            funcs.add(mangled)
            if kind == 'CXXConstructorDecl':
                funcs.add(mangled.replace('C1E', 'C2E', 1))
                funcs.add(mangled.replace('C1E', 'C3E', 1))
                funcs.add(mangled.replace('C1B', 'C2B', 1))
            elif kind == 'CXXDestructorDecl':
                for v in ('D0E', 'D2E'):
                    funcs.add(mangled.replace('D1E', v, 1))
        return
    else:
        child_path = path
    for child in node.get('inner', []):
        if isinstance(child, dict):
            collect(child, child_path, funcs, records)


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
    funcs, records = set(), set()
    for obj in ast_objects(proc.stdout):
        if obj.get('kind') == 'NamespaceDecl' and obj.get('name') == 'LibreSCRS':
            collect(obj, [], funcs, records)
    if not funcs and not records:
        fail(f'the AST of {len(headers)} installed header(s) declared {len(funcs)} function(s) '
             f'and {len(records)} class(es) -- the measurement did not happen')
    return funcs, records


THUNK = re.compile(r'^_ZT(?:hn?\d+_|vn?\d+_n?\d+_)')
LIBRESCRS = re.compile(r'^_Z.*9LibreSCRS')
# An internal scope spelled anywhere in the symbol, its parameter types
# included: a public function that takes an Internal:: type is not usable
# through the installed headers either.
INTERNAL_IN_TEXT = re.compile(r'\b(Internal|detail)::|[A-Za-z0-9]_detail::')


def attributed(sym, funcs, records):
    if sym in funcs:
        return True
    m = THUNK.match(sym)
    if m:
        return '_Z' + sym[m.end():] in funcs
    for prefix in ('_ZTH', '_ZTW', '_ZGV'):
        if sym.startswith(prefix):
            return '_Z' + sym[len(prefix):] in funcs
    for prefix in ('_ZTV', '_ZTI', '_ZTS', '_ZTT'):
        if sym.startswith(prefix):
            return sym[len(prefix):] in records
    return False


def demangle(names):
    try:
        proc = subprocess.run(['c++filt'], input='\n'.join(names) + '\n',
                              capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as e:
        fail(f'c++filt failed: {e}')
    out = proc.stdout.split('\n')[:len(names)]
    if len(out) != len(names):
        fail('c++filt returned fewer lines than it was given')
    return out


def read_allowlist(path):
    entries = {}
    with open(path) as f:
        for n, line in enumerate(f, 1):
            line = line.rstrip('\n')
            if not line.strip() or line.startswith('#'):
                continue
            parts = line.split('\t')
            if len(parts) != 3 or not all(p.strip() for p in parts):
                fail(f'{path}:{n}: expected "<library>\\t<demangled symbol>\\t<reason>", got {line!r}')
            key = (parts[0], parts[1])
            if key in entries:
                fail(f'{path}:{n}: duplicate entry {parts[1]!r}')
            entries[key] = n
    return entries


def main():
    if len(sys.argv) not in (5, 6):
        fail('usage: abi-public-surface.py <clang++> <include-root> <exports.tsv> <allowlist> [<base allowlist>]')
    clang, root, exports, allowlist_path = sys.argv[1:5]
    allowlist = read_allowlist(allowlist_path)
    base = read_allowlist(sys.argv[5]) if len(sys.argv) == 6 else None
    funcs, records = measure_surface(clang, root)

    rows = []
    with open(exports) as f:
        for line in f:
            line = line.rstrip('\n')
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) != 3:
                fail(f'malformed export line: {line!r}')
            rows.append(parts)
    if not rows:
        fail('no exported symbols to judge')
    texts = demangle([r[2] for r in rows])

    offending = {}
    for (lib, binding, sym), text in zip(rows, texts):
        bare = sym.split('@', 1)[0]
        if not LIBRESCRS.match(bare):
            continue
        if not attributed(bare, funcs, records) or INTERNAL_IN_TEXT.search(text):
            offending.setdefault((lib, text), binding)

    rc = 0
    new = sorted(k for k in offending if k not in allowlist)
    stale = sorted((n, k) for k, n in allowlist.items() if k not in offending)
    if new:
        rc = 1
        print(f'EXPORT LEAK: {len(new)} exported symbol(s) name a LibreSCRS entity the installed '
              'headers do not declare (or an Internal/detail one):', file=sys.stderr)
        for lib, text in new:
            print(f'  {lib}  {offending[(lib, text)]}  {text}', file=sys.stderr)
        print('       Hide it (drop LIBRESCRS_PUBLIC_API), or declare it in an installed header as\n'
              '       public API. The allowlist is not the place for a new one: it only shrinks.',
              file=sys.stderr)
    if stale:
        rc = 1
        print(f'STALE ALLOWLIST: {len(stale)} entr(y/ies) in {allowlist_path} name a symbol that is '
              'no longer an internal export:', file=sys.stderr)
        for n, (lib, text) in stale:
            print(f'  line {n}: {lib}  {text}', file=sys.stderr)
        print('       Delete the line(s).', file=sys.stderr)
    added = sorted((n, k) for k, n in allowlist.items() if base is not None and k not in base)
    if added:
        rc = 1
        print(f'ALLOWLIST GREW: {len(added)} entr(y/ies) the allowlist at the base revision does not hold:',
              file=sys.stderr)
        for n, (lib, text) in added:
            print(f'  line {n}: {lib}  {text}', file=sys.stderr)
        print('       The list only shrinks: an internal export is never added to it.', file=sys.stderr)
    if rc == 0:
        print(f'Every exported LibreSCRS symbol is declared in the installed headers '
              f'({len(rows)} exports judged; {len(allowlist)} allowlisted internal export(s) remain).')
    sys.exit(rc)


if __name__ == '__main__':
    main()

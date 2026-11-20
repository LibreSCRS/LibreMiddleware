#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# abi-flavour-imports.py -- helper of abi-snapshot.sh: what the shipped images
# would import if built with other compiler flags (the sanitizer flavour).
#
# A build with -fsanitize=undefined is not the plain build with checks added:
# gcc's vptr check makes every member access through a polymorphic object
# reference that class's typeinfo, which the plain build of the same source
# never does. An image whose plain build imports nothing internal can then
# import a typeinfo the library keeps hidden -- and a card plugin built that
# way fails to load, a test archive fails to link.
#
# Each shipped image (a core library, a card plugin, an installed test
# archive) is rebuilt object by object: its objects are read from its link
# (or archive) command in build.ninja, each object's compile command from
# compile_commands.json, run again with FLAGS appended. What the image's
# objects leave undefined, minus what they define, is printed as one import
# per line: "<image> built with <FLAGS>\t<mangled symbol>". Objects that no
# compile command produces (a vendored C library built outside CMake) are not
# LibreSCRS code and are left out; the count is printed.
#
# usage: abi-flavour-imports.py --build-dir D --flags F --out FILE IMAGE...
# Exit 0 on success, 2 when it cannot measure (no ninja, no compile database,
# an image ninja does not know, an object that does not compile).

import argparse
import concurrent.futures
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import sys
import tempfile


def fail(msg):
    print(f'FATAL: {msg}', file=sys.stderr)
    sys.exit(2)


def ninja_command(build_dir, target):
    """The last command ninja runs to produce target (its link or archive step)."""
    r = subprocess.run(['ninja', '-C', build_dir, '-t', 'commands', '-s', target],
                       capture_output=True, text=True)
    if r.returncode != 0 or not r.stdout.strip():
        return None
    return r.stdout.strip().splitlines()[-1]


def objects_of(build_dir, target, seen):
    """Object files on target's link or archive line, archives built in this tree followed."""
    cmd = ninja_command(build_dir, target)
    if cmd is None:
        return None
    objs = []
    for tok in shlex.split(cmd):
        if tok.endswith('.o'):
            objs.append(os.path.normpath(tok))
        elif tok.endswith('.a') and tok != target and tok not in seen:
            seen.add(tok)
            sub = objects_of(build_dir, tok, seen)
            if sub:
                objs.extend(sub)
    return objs


def symbols(path):
    undef = subprocess.run(['nm', '-u', path], capture_output=True, text=True).stdout.split()
    defined = subprocess.run(['nm', '--defined-only', path], capture_output=True, text=True).stdout.splitlines()
    return ({s for s in undef if s not in ('U', 'w')},
            {line.split()[-1] for line in defined if line.split()})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--build-dir', required=True)
    ap.add_argument('--flags', required=True)
    ap.add_argument('--out', required=True)
    ap.add_argument('images', nargs='+')
    args = ap.parse_args()

    build_dir = os.path.abspath(args.build_dir)
    if shutil.which('ninja') is None:
        fail('ninja not found on PATH -- cannot read the link lines of the shipped images')
    if not os.path.isfile(os.path.join(build_dir, 'build.ninja')):
        fail(f'{build_dir} is not a Ninja build -- cannot read the link lines of the shipped images')
    db_path = os.path.join(build_dir, 'compile_commands.json')
    if not os.path.isfile(db_path):
        fail(f'{db_path} is missing -- configure with CMAKE_EXPORT_COMPILE_COMMANDS=ON')
    by_output = {}
    for e in json.load(open(db_path)):
        out = e.get('output')
        if out:
            by_output[os.path.normpath(os.path.relpath(os.path.join(e['directory'], out), build_dir))] = e

    image_objs = {}
    skipped = 0
    for image in args.images:
        rel = os.path.relpath(os.path.abspath(image), build_dir)
        objs = objects_of(build_dir, rel, set())
        if objs is None:
            fail(f'ninja has no rule for {rel} -- cannot read which objects it is built from')
        known = [o for o in objs if o in by_output]
        skipped += len(objs) - len(known)
        if not known:
            fail(f'no object of {rel} has a compile command -- cannot rebuild it with {args.flags}')
        image_objs[image] = known

    scratch = tempfile.mkdtemp(prefix='abi-flavour.', dir=os.environ.get('TMPDIR_FLAVOUR', None))
    flags = shlex.split(args.flags)

    def build(obj):
        e = by_output[obj]
        argv = list(e['arguments']) if 'arguments' in e else shlex.split(e['command'])
        target = os.path.join(scratch, hashlib.sha1(obj.encode()).hexdigest() + '.o')
        argv[argv.index('-o') + 1] = target
        # No dependency file: the original rule's stays where it was.
        kept, skip = [], False
        for a in argv:
            if skip:
                skip = False
            elif a in ('-MF', '-MT', '-MQ'):
                skip = True
            elif a not in ('-MD', '-MMD'):
                kept.append(a)
        argv = kept
        r = subprocess.run(argv + flags, cwd=e['directory'], capture_output=True, text=True)
        if r.returncode != 0:
            return obj, None, r.stderr[-2000:]
        return obj, symbols(target), None

    unique = sorted({o for objs in image_objs.values() for o in objs})
    syms = {}
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ.get('ABI_FLAVOUR_JOBS', '4'))) as ex:
            for obj, result, err in ex.map(build, unique):
                if result is None:
                    fail(f'{obj} does not compile with {args.flags}:\n{err}')
                syms[obj] = result
    finally:
        shutil.rmtree(scratch, ignore_errors=True)

    with open(args.out, 'a') as out:
        for image, objs in image_objs.items():
            undef, defined = set(), set()
            for o in objs:
                undef |= syms[o][0]
                defined |= syms[o][1]
            label = f'{os.path.basename(image)} built with {args.flags}'
            for s in sorted(undef - defined):
                out.write(f'{label}\t{s}\n')
    print(f'sanitizer flavour: {len(unique)} object(s) of {len(image_objs)} shipped image(s) rebuilt with '
          f'{args.flags}; {skipped} object(s) without a compile command left out')


if __name__ == '__main__':
    main()

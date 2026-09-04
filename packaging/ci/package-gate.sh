#!/usr/bin/env bash
# package-gate.sh <image-ref-or-digest> [artefact-root]
#
# G1  a packaging recipe exists at all
# G2  it builds, and builds the right thing
# G3  the built packages install, land on the paths a system reads, and leave
#     nothing behind
# G4  exactly one PKCS#11 provider is registered, whatever the install order
# G5  the build dependency the manifest tool needs is declared, consistently
#
# Exit code is 0 only if every gate passes. Each assertion is a separate test so
# a failure names itself. Nothing here is measured through a pipe: a pipeline's
# status is the last command's, and a gate whose exit code is not read is not a
# gate.
#
# The artefact root is keyed by IMAGE as well as repository. Debian 13 and
# Ubuntu 26.04 produce identically named .deb files, so one shared directory
# would mean the second pass silently overwrites the first and the final count
# comes out right *because* of the collision.
set -uo pipefail

IMAGE="${1:?usage: package-gate.sh <image> [artefact-root]}"
ART="${2:-/var/tmp/librescrs-packages/out}"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPO_NAME="$(basename "$REPO_ROOT")"
WORKROOT="${P4B_WORK:-$(dirname "$ART")}"

fail=0
note() { printf '%-6s %s\n' "$1" "$2"; }
check() { # check <name> <rc>
  if [ "$2" -eq 0 ]; then note PASS "$1"; else note FAIL "$1"; fail=1; fi
}

img_slug() {
  case "$1" in
    *debian*)  echo debian13   ;;
    *ubuntu*)  echo ubuntu2604 ;;
    *fedora*)  echo fedora43   ;;
    *) echo "UNKNOWN IMAGE: $1" >&2; return 1 ;;
  esac
}
SLUG="$(img_slug "$IMAGE")" || exit 2
case "$SLUG" in fedora43) FAMILY=rpm ;; *) FAMILY=deb ;; esac

OUT="$ART/$SLUG/$REPO_NAME/$FAMILY"
SRC="$WORKROOT/gate-src/$SLUG/$REPO_NAME"
LOG="$WORKROOT/log"
mkdir -p "$LOG"

# Deleting through a container, because a container built it as root. rm -rf as
# an ordinary user fails with Permission denied, the tree survives, and the next
# build silently reuses a stale artefact.
purge() {
  case "$1" in "$WORKROOT"/*|/var/tmp/*) : ;; *) echo "purge refused: $1" >&2; return 1 ;; esac
  # The parent has to exist and be ours before the container touches it:
  # `docker run -v <missing path>` creates it as root, and then every later
  # mkdir by the ordinary user fails with Permission denied.
  mkdir -p "$(dirname "$1")" 2>/dev/null
  [ -e "$1" ] || return 0
  docker run --rm -v "$(dirname "$1"):/w" "$IMAGE" rm -rf "/w/$(basename "$1")" >/dev/null 2>&1
  test ! -e "$1"
}

# ── G5 ────────────────────────────────────────────────────────────────────
# One definition, and the same text in every repository. `recipes < 2` is
# NO_RECIPES rather than a pass: a repository with no deb+rpm pair is exactly
# the state this work removes, and staying quiet about it would let G5 pass
# over a repository that has nothing in it. The measurement is always printed,
# so green and red differ by numbers and not only by a word.
g5_repo() {   # g5_repo <absolute repo root>
              #   -> DECLARED | MISSING | INCONSISTENT | NO_RECIPES
  local r="$1" recipes=0 hits=0 f need=0
  grep -rqs "manifest2header" "$r/CMakeLists.txt" "$r/tools" && need=1
  for f in "$r/packaging/debian/control" "$r"/packaging/rpm/*.spec \
           "$r/packaging/arch/PKGBUILD"; do
    [ -f "$f" ] || continue
    recipes=$((recipes+1))
    grep -q "jsonschema" "$f" && hits=$((hits+1))
  done
  printf 'need=%s recipes=%s hits=%s ' "$need" "$recipes" "$hits"
  if [ "$recipes" -lt 2 ]; then echo NO_RECIPES; return 1; fi
  if [ "$need" -eq 1 ]; then
    if [ "$hits" -eq "$recipes" ]; then echo DECLARED; return 0; else echo MISSING; return 1; fi
  fi
  if [ "$hits" -eq 0 ] || [ "$hits" -eq "$recipes" ]; then echo DECLARED; return 0; fi
  echo INCONSISTENT; return 1
}

echo "== package-gate $REPO_NAME on $SLUG ($FAMILY)"
echo "   image     $IMAGE"
echo "   artefacts $OUT"

# ── G1 ────────────────────────────────────────────────────────────────────
if [ "$FAMILY" = deb ]; then
  test -f "$REPO_ROOT/packaging/debian/changelog" -a -f "$REPO_ROOT/packaging/debian/control"
  check "G1 debian recipe present" $?
else
  ls "$REPO_ROOT"/packaging/rpm/*.spec >/dev/null 2>&1
  check "G1 rpm recipe present" $?
fi

# ── G2 ────────────────────────────────────────────────────────────────────
# The work copy comes from the committed tree, never from the working tree, so
# an uncommitted fix cannot make a gate pass that will fail for anyone else.
purge "$SRC" || exit 2
mkdir -p "$SRC"
if [ -e "$REPO_ROOT/.gitmodules" ]; then
  git clone --quiet --recurse-submodules "$REPO_ROOT" "$SRC" >/dev/null 2>&1
  rc=$?
  rm -rf "$SRC/.git"
else
  git -C "$REPO_ROOT" archive --format=tar HEAD | tar -x -C "$SRC"
  rc=$?
fi
check "G2a work copy from HEAD" $rc

# Anything the release tarball carries but the repository does not -- a
# FetchContent dependency pinned by commit, say -- is placed here, by the same
# script the tarball uses. A build that reaches the network is not a build of a
# package, so this happens before the container starts, not inside it.
if [ -x "$REPO_ROOT/packaging/ci/prepare-source.sh" ]; then
  ( cd "$SRC" && bash "$REPO_ROOT/packaging/ci/prepare-source.sh" ) >"$LOG/gate-prepare-$REPO_NAME-$SLUG.txt" 2>&1
  check "G2b source prepared (vendored fetch-time dependencies)" $?
fi

MOUNTS=()
for up in $(cat "$REPO_ROOT/packaging/ci/upstream.txt" 2>/dev/null); do
  updir="$ART/$SLUG/$up/$FAMILY"
  if ! ls "$updir"/*."$FAMILY" >/dev/null 2>&1; then
    note FAIL "G2 upstream packages for $up missing under $updir"
    note INFO "the packaging job is enabled from the bottom up: build $up first"
    fail=1
  fi
  MOUNTS+=(-v "$updir:/upstream/$up:ro")
done

purge "$OUT" >/dev/null 2>&1
mkdir -p "$OUT"
BUILDLOG="$LOG/gate-build-$REPO_NAME-$SLUG.txt"
docker run --rm -v "$SRC:/s" -v "$OUT:/out" "${MOUNTS[@]}" -w /s "$IMAGE" \
  bash "packaging/ci/build-$FAMILY.sh" > "$BUILDLOG" 2>&1
rc=$?
check "G2 build ($BUILDLOG)" $rc
[ "$rc" -eq 0 ] || { tail -n 30 "$BUILDLOG"; }

# Anything this repository alone has to assert about its own build lives in a
# hook next to the fix it guards, not in this shared text. A repository-specific
# assertion carried in a file that is copied into five repositories reads, to
# anything counting where a gate lives, as a gate duplicated into four
# repositories that do not own it.
if [ -x "$REPO_ROOT/packaging/ci/extra-build-checks.sh" ] && [ "$rc" -eq 0 ]; then
  BUILDLOG="$BUILDLOG" SRC="$SRC" OUT="$OUT" FAMILY="$FAMILY" \
    bash "$REPO_ROOT/packaging/ci/extra-build-checks.sh"
  check "G2 repository-specific build assertions" $?
fi

if [ "$rc" -eq 0 ]; then
  n=$(ls -1 "$OUT"/*."$FAMILY" 2>/dev/null | wc -l)
  echo "   built $n $FAMILY package(s):"
  ls -1 "$OUT" | sed 's/^/     /'
fi

# ── G3 + G4 ───────────────────────────────────────────────────────────────
# Building a package proves less than installing one. Everything below runs in
# a container that never had a source tree.
if [ "$rc" -eq 0 ]; then
  VLOG="$LOG/gate-verify-$REPO_NAME-$SLUG.txt"
  VMOUNTS=(-v "$OUT:/pkg:ro")
  for up in $(cat "$REPO_ROOT/packaging/ci/upstream.txt" 2>/dev/null); do
    VMOUNTS+=(-v "$ART/$SLUG/$up/$FAMILY:/pkg-$up:ro")
  done
  docker run --rm "${VMOUNTS[@]}" \
    -v "$REPO_ROOT/packaging/ci/verify-installed.sh:/verify.sh:ro" \
    -e "FAMILY=$FAMILY" "$IMAGE" bash /verify.sh > "$VLOG" 2>&1
  vrc=$?
  check "G3+G4 installed-state assertions ($VLOG)" $vrc
  [ "$vrc" -eq 0 ] || tail -n 40 "$VLOG"
  grep -E '^(PASS|FAIL) ' "$VLOG" | sed 's/^/   /'
else
  note SKIP "G3+G4 not run: the build failed, and asserting over a stale package is worse than not asserting"
  fail=1
fi

# ── G5 ────────────────────────────────────────────────────────────────────
printf '%-6s %s ' INFO "G5 $REPO_NAME:"
g5_repo "$REPO_ROOT"
check "G5 jsonschema build dependency" $?

echo "== package-gate $REPO_NAME on $SLUG: $([ $fail -eq 0 ] && echo GREEN || echo RED)"
exit $fail

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-recipe.sh [--online]
#
# The Arch recipe must fetch the tarball THIS project publishes, and must say
# true things about it. Four arms; every arm prints what it measured, a skip
# included, because a silent skip is a vacuum and not a pass.
#
#   1  source= fetches the release asset this project uploads: from THIS
#      repository, under the name ci/scripts/make-source-tarball.sh gives it.
#      GitHub's auto-generated archive/refs/tags tarball is refused -- its bytes
#      are not ours to assert and it omits submodule trees -- and so is the
#      v-prefixed spelling it used to ask for, which is not how any tag in this
#      stack is written.
#   2  pkgver equals the first line of VERSION. pkgver only labels the package;
#      the installed CMake version file is generated from VERSION, so a bump
#      that misses one of them ships a package whose own metadata disagrees.
#   3  every submodule gitlink is pinned verbatim in the recipe; and a
#      FetchContent pin carried by the recipe equals the pin in the cmake module
#      the build would otherwise fetch with.
#   4  once the tag exists, no sha256sums entry may still be SKIP.
#
# Arm 4 asks the LOCAL repository whether the tag exists, so it is INERT in a
# clone that carries no tags: it prints its skip and passes. That is why the
# workflow step that runs this gate checks out with fetch-tags -- without it the
# arm could never fire, and a placeholder checksum would outlive the release it
# waits for. It deliberately does not contact the remote by default: measured on the maintainer's machine,
# `git ls-remote` against these SSH remotes hangs (rc=124 under `timeout 15`,
# even with GIT_TERMINAL_PROMPT=0), and a gate that can hang is worse than one
# that can fail -- an unbounded job holds a runner for six hours and refuses to
# serve its log while it does. --online adds the probe under an explicit
# timeout and treats a timeout as a printed skip, never as a red.
#
# Threat model. This reads the recipe as TEXT rather than sourcing it, so it
# guards against the honest regression: someone edits source=, bumps a version
# or refreshes a pin in the shapes this repository actually writes, and gets one
# of them wrong. It does not resist a recipe written to conceal intent, and
# these doors are left open knowingly: a URL assembled from variables or
# concatenated pieces rather than written out in the entry; an architecture
# array (source_x86_64=()) instead of source=; a source=( or its closing ) not
# at column 0, which the range match needs; a pin that appears in the recipe
# only inside a comment, because arm 3 asks whether the sha is present, not
# where. Arm 1 reads the asset name out of the URL and compares it with the one
# make-source-tarball.sh builds, but it cannot know whether the release workflow
# actually uploaded it: a workflow that stopped uploading leaves this green and
# 404s at the first makepkg. Code review, not this gate, is what catches a
# recipe written to mislead.
set -u

online=0
case "${1:-}" in
  --online) online=1 ;;
  '') ;;
  *) echo "usage: check-recipe.sh [--online]" >&2; exit 2 ;;
esac

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$here/../.." && pwd)
recipe="$here/PKGBUILD"

rc=0
note() { printf '%-6s %s\n' "$1" "$2"; }
bad()  { note FAIL "$1"; rc=1; }

[ -f "$recipe" ] || { note FAIL "no PKGBUILD next to this script ($recipe)"; exit 2; }

pkgver=$(sed -nE 's/^pkgver=([^[:space:]#]+).*/\1/p' "$recipe" | head -1)
[ -n "$pkgver" ] || bad "no pkgver= in $recipe"

# --- arm 1 -----------------------------------------------------------------
block=$(sed -n '/^source=(/,/^)/p' "$recipe")
if [ -z "$block" ]; then
  bad "arm1: no 'source=(' ... ')' array in the recipe -- the pattern matches nothing, which is a vacuum and not a pass"
else
  mapfile -t entries < <(printf '%s\n' "$block" | sed -e '1d' -e '$d' \
                          | grep -vE '^[[:space:]]*(#|$)')
  n=${#entries[@]}
  if [ "$n" -eq 0 ]; then
    bad "arm1: the source=() array holds no entries"
  else
    # The asset name is not free-form: make-source-tarball.sh maps this
    # repository to a source name and writes <src>_<version>.orig.tar.gz. The
    # mapping is read out of that script instead of being repeated here, so a
    # rename cannot leave the recipe and the workflow naming different files --
    # the recipe would 404 at the first makepkg and nothing would have said so.
    reponame=$(basename "$root")
    maker="$root/ci/scripts/make-source-tarball.sh"
    srcname=""
    if [ -f "$maker" ]; then
      srcname=$(sed -nE "s/^[[:space:]]*$reponame\)[[:space:]]+src=([A-Za-z0-9._-]+).*/\1/p" "$maker" | head -1)
    fi
    own=0
    for e in "${entries[@]}"; do
      url=${e##*::}; url=${url%\"}
      case "$e" in
        *archive/refs/tags*)
          bad "arm1: fetches GitHub's auto-generated archive, whose bytes this project does not produce: $url" ;;
      esac
      case "$e" in
        *'/v$pkgver'*|*'/v${pkgver}'*)
          bad "arm1: asks for a v-prefixed tag; every tag this project publishes is unprefixed: $url" ;;
      esac
      case "$e" in
        *github.com/LibreSCRS/*/releases/download/*)
          own=$((own + 1))
          rest=${url#*github.com/LibreSCRS/}
          erepo=${rest%%/*}
          [ "$erepo" = "$reponame" ] || bad "arm1: the release asset is fetched from LibreSCRS/$erepo while this repository is $reponame -- a recipe copied between siblings packages the other one's sources"
          asset=${url##*/}
          asset=${asset//'${pkgver}'/$pkgver}
          asset=${asset//'$pkgver'/$pkgver}
          if [ -z "$srcname" ]; then
            bad "arm1: ci/scripts/make-source-tarball.sh names no source for $reponame, so the asset name $asset cannot be checked against the one the release workflow uploads"
          elif [ "$asset" != "${srcname}_${pkgver}.orig.tar.gz" ]; then
            bad "arm1: the recipe fetches $asset, but the release workflow uploads ${srcname}_${pkgver}.orig.tar.gz"
          fi ;;
      esac
    done
    printf 'arm1: %d source entr%s, %d fetching this repository'"'"'s own release asset%s\n' \
      "$n" "$([ "$n" -eq 1 ] && echo y || echo ies)" "$own" \
      "$([ -n "$srcname" ] && echo " named ${srcname}_${pkgver}.orig.tar.gz")"
    [ "$own" -eq 1 ] || bad "arm1: expected exactly one .../releases/download/... entry, found $own"
  fi
fi

# --- arm 2 -----------------------------------------------------------------
vf="$root/VERSION"
if [ ! -f "$vf" ]; then
  bad "arm2: $vf is missing -- pkgver cannot be shown to agree with anything"
else
  declared=$(sed -n '1p' "$vf" | tr -d '[:space:]'); declared=${declared#v}
  if [ -z "$declared" ]; then
    bad "arm2: first line of VERSION is empty"
  elif [ "$declared" != "$pkgver" ]; then
    bad "arm2: version drift -- VERSION says $declared, the recipe says pkgver=$pkgver"
  else
    printf 'arm2: pkgver=%s equals the first line of VERSION\n' "$pkgver"
  fi
fi

# --- arm 2b (Debian changelog / RPM spec, packaged alongside the same VERSION) ---
dch="$root/packaging/debian/changelog"
if [ ! -f "$dch" ]; then
  printf 'arm2b: no packaging/debian/changelog -- nothing to compare against VERSION\n'
else
  dchver=$(sed -n '1p' "$dch" | sed -nE 's/^[^(]*\(([^)]*)\).*/\1/p')
  dchver=${dchver%-*}
  if [ -z "$dchver" ]; then
    bad "arm2b: could not parse a version out of the first line of $dch"
  elif [ "$dchver" != "$declared" ]; then
    bad "arm2b: version drift -- VERSION says $declared, packaging/debian/changelog says $dchver"
  else
    printf 'arm2b: packaging/debian/changelog head names %s, matching VERSION\n' "$dchver"
  fi
fi

spec="$root/packaging/rpm/librescrs-middleware.spec"
if [ ! -f "$spec" ]; then
  printf 'arm2c: no packaging/rpm/librescrs-middleware.spec -- nothing to compare against VERSION\n'
else
  specver=$(sed -nE 's/^Version:[[:space:]]+([^[:space:]]+).*/\1/p' "$spec" | head -1)
  if [ -z "$specver" ]; then
    bad "arm2c: no 'Version:' line in $spec"
  elif [ "$specver" != "$declared" ]; then
    bad "arm2c: version drift -- VERSION says $declared, $spec says Version: $specver"
  else
    printf 'arm2c: %s Version: %s matches VERSION\n' "$(basename "$spec")" "$specver"
  fi
fi

# --- arm 3 -----------------------------------------------------------------
# Read from the index, not from HEAD: the gate judges the tree it is run over.
gl=0; ok=0
while read -r mode sha _stage path; do
  [ "$mode" = 160000 ] || continue
  gl=$((gl + 1))
  if grep -q "$sha" "$recipe"; then ok=$((ok + 1))
  else bad "arm3: submodule $path is pinned at $sha, which appears nowhere in the recipe"; fi
done < <(git -C "$root" ls-files -s 2>/dev/null)
printf 'arm3: %d submodule gitlink(s), %d pinned in the recipe\n' "$gl" "$ok"

fm="$root/cmake/FetchQCBOR.cmake"
rp=$(sed -nE 's/^_qcbor_commit=([0-9a-f]{40}).*/\1/p' "$recipe" | head -1)
if [ -n "$rp" ] && [ ! -f "$fm" ]; then
  bad "arm3b: the recipe pins _qcbor_commit=$rp but $fm is missing -- nothing to keep it in lockstep with"
elif [ -n "$rp" ]; then
  mapfile -t decl < <(sed -nE 's/^[[:space:]]*GIT_TAG[[:space:]]+([0-9a-f]{40})[[:space:]]*$/\1/p' "$fm")
  if [ "${#decl[@]}" -ne 1 ]; then
    bad "arm3b: cmake/FetchQCBOR.cmake must hold exactly one 'GIT_TAG <40-hex>' line; found ${#decl[@]}"
  elif [ "${decl[0]}" != "$rp" ]; then
    bad "arm3b: QCBOR pin drift -- cmake says ${decl[0]}, the recipe says $rp"
  else
    printf 'arm3b: QCBOR pin %s matches cmake/FetchQCBOR.cmake\n' "$rp"
  fi
else
  printf 'arm3b: the recipe carries no _qcbor_commit -- nothing to keep in lockstep\n'
fi

# --- arm 4 -----------------------------------------------------------------
where=""
git -C "$root" rev-parse -q --verify "refs/tags/$pkgver" >/dev/null 2>&1 && where="in this clone"
if [ -z "$where" ] && [ "$online" -eq 1 ]; then
  if out=$(GIT_TERMINAL_PROMPT=0 timeout 20 git -C "$root" ls-remote --tags origin "$pkgver" 2>/dev/null); then
    [ -n "$out" ] && where="on origin"
  else
    printf 'arm4: the remote probe timed out or failed; falling back to the local tag only\n'
  fi
fi
if [ -n "$where" ]; then
  sums=$(sed -n '/^sha256sums=(/,/)/p' "$recipe")
  mapfile -t vals < <(printf '%s\n' "$sums" | grep -oE "'[^']*'" | tr -d "'")
  if [ "${#vals[@]}" -eq 0 ]; then
    bad "arm4: no sha256sums entries found -- the pattern matches nothing, which is a vacuum and not a pass"
  else
    n_bad=0
    for v in "${vals[@]}"; do
      case "$v" in
        [0-9a-f]*) [ "${#v}" -eq 64 ] || n_bad=$((n_bad + 1)) ;;
        *) n_bad=$((n_bad + 1)) ;;
      esac
    done
    printf 'arm4: tag %s exists %s; %d sha256sums entr%s, %d not a real checksum\n' \
      "$pkgver" "$where" "${#vals[@]}" "$([ "${#vals[@]}" -eq 1 ] && echo y || echo ies)" "$n_bad"
    [ "$n_bad" -eq 0 ] || bad "arm4: $n_bad sha256sums entr$([ "$n_bad" -eq 1 ] && echo y || echo ies) still SKIP (or not 64 lowercase hex) while tag $pkgver exists"
  fi
else
  printf 'arm4: SKIPPED -- tag %s exists in neither this clone nor (unasked) the remote, so the release asset it names cannot be checksummed yet\n' "$pkgver"
fi

echo "check-recipe: $([ $rc -eq 0 ] && echo GREEN || echo RED)"
exit "$rc"

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-recipe.sh [--online]
#
# The Arch recipe must build THIS project's signed release, and must say true
# things about it. Five arms; every arm prints what it measured, because a
# silent skip is a vacuum and not a pass.
#
#   1  the project's own source is the signed release tag of THIS repository,
#      cloned with git:  git+https://github.com/LibreSCRS/<repo>.git#tag=$pkgver?signed
#      -- exactly one such entry. GitHub's auto-generated archive/refs/tags
#      tarball is refused (its bytes are not ours to assert and it omits
#      submodule trees), and so are an unsigned tag, a branch or commit, a
#      release-asset tarball (its checksum cannot exist before the tag, and the
#      recipe travels inside the tarball it would checksum), a sibling
#      repository, and the v-prefixed spelling no tag in this stack uses.
#   2  pkgver equals the first line of VERSION. pkgver only labels the package;
#      the installed CMake version file is generated from VERSION, so a bump
#      that misses one of them ships a package whose own metadata disagrees.
#   3  every submodule gitlink is pinned verbatim in the recipe; and a
#      FetchContent pin carried by the recipe equals the pin in the cmake module
#      the build would otherwise fetch with.
#   4  integrity without a tag: validpgpkeys is exactly the primary fingerprint
#      of the release key in KEYS, the signed tag is the only 'SKIP' checksum,
#      and every other source carries a real sha256. Before the tag and after
#      it, the same answer.
#   5  the recipe describes no p11-kit registration the build does not install.
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
# where. Code review, not this gate, is what catches a recipe written to
# mislead.
#
# It does not touch the network. Arm 4 reads KEYS with gpg in a throwaway home
# directory; no gpg is "cannot judge" (exit 2), never a pass.
set -u

[ "$#" -eq 0 ] || { echo "usage: check-recipe.sh" >&2; exit 2; }

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
reponame=$(basename "$root")
block=$(sed -n '/^source=(/,/^)/p' "$recipe")
entries=()
if [ -z "$block" ]; then
  bad "arm1: no 'source=(' ... ')' array in the recipe -- the pattern matches nothing, which is a vacuum and not a pass"
else
  mapfile -t entries < <(printf '%s\n' "$block" | sed -e '1d' -e '$d' \
                          | grep -vE '^[[:space:]]*(#|$)')
  n=${#entries[@]}
  if [ "$n" -eq 0 ]; then
    bad "arm1: the source=() array holds no entries"
  else
    want="git+https://github.com/LibreSCRS/$reponame.git#tag="
    own=0
    for e in "${entries[@]}"; do
      src=${e#"${e%%[![:space:]]*}"}; src=${src#\"}; src=${src%\"}
      url=${src#*::}
      case "$url" in
        *archive/refs/tags*)
          bad "arm1: fetches GitHub's auto-generated archive, whose bytes this project does not produce: $url" ;;
      esac
      # shellcheck disable=SC2016 # the recipe's literal $pkgver, not ours
      case "$url" in
        *'/v$pkgver'*|*'/v${pkgver}'*|*'tag=v$pkgver'*|*'tag=v${pkgver}'*)
          bad "arm1: asks for a v-prefixed tag; every tag this project publishes is unprefixed: $url" ;;
      esac
      case "$url" in
        *github.com/LibreSCRS/*)
          rest=${url#*github.com/LibreSCRS/}
          erepo=${rest%%[/.#]*}
          if [ "$erepo" != "$reponame" ]; then
            bad "arm1: the source is fetched from LibreSCRS/$erepo while this repository is $reponame -- a recipe copied between siblings packages the other one's sources"
            continue
          fi
          own=$((own + 1))
          # shellcheck disable=SC2016 # the recipe's literal $pkgver, not ours
          case "$url" in
            "$want"'$pkgver?signed'|"$want"'${pkgver}?signed') ;;
            *releases/download/*)
              bad "arm1: fetches a release-asset tarball ($url); the source is the signed tag, $want\$pkgver?signed -- a tarball checksum cannot exist before the tag, and the recipe travels inside the tarball it would checksum" ;;
            "$want"'$pkgver'|"$want"'${pkgver}')
              bad "arm1: the tag is cloned without ?signed, so makepkg would not verify its signature: $url" ;;
            *)
              bad "arm1: the project's own source must be $want\$pkgver?signed, not $url" ;;
          esac ;;
      esac
    done
    printf 'arm1: %d source entr%s, %d naming this repository\n' \
      "$n" "$([ "$n" -eq 1 ] && echo y || echo ies)" "$own"
    [ "$own" -eq 1 ] || bad "arm1: expected exactly one source naming LibreSCRS/$reponame (its signed tag), found $own"
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

# --- arm 5 -----------------------------------------------------------------
# The package must not describe a file it does not install. build() decides
# whether the p11-kit registration ships (LIBREMIDDLEWARE_INSTALL_P11KIT_MODULE,
# OFF by default); while it does not, neither the recipe nor its README may name
# the installed registration path or offer p11-kit as the thing that makes the
# cards discoverable. The README's manual registration under /etc is not a claim
# about the package and is not judged.
if [ -f "$root/CMakeLists.txt" ] && grep -q 'INSTALL_P11KIT_MODULE' "$root/CMakeLists.txt"; then
  buildfn=$(sed -n '/^build()/,/^}/p' "$recipe")
  if printf '%s\n' "$buildfn" | grep -q -- '-DLIBREMIDDLEWARE_INSTALL_P11KIT_MODULE=ON'; then
    printf 'arm5: build() installs the p11-kit registration; describing it is true\n'
  else
    claims=0
    readme="$(dirname "$recipe")/README.md"
    for f in "$recipe" "$readme"; do
      [ -f "$f" ] || continue
      while IFS= read -r hit; do
        bad "arm5: $(basename "$f"):${hit%%:*} names share/p11-kit/modules, which this package does not install (build() leaves LIBREMIDDLEWARE_INSTALL_P11KIT_MODULE off)"
        claims=$((claims + 1))
      done < <(grep -n 'share/p11-kit/modules' "$f")
    done
    if sed -n '/^optdepends=(/,/)/p' "$recipe" | grep -q "p11-kit"; then
      bad "arm5: optdepends offers p11-kit for card discovery, and this package installs no p11-kit registration"
      claims=$((claims + 1))
    fi
    [ "$claims" -eq 0 ] && printf 'arm5: no p11-kit registration installed, and none described\n'
  fi
fi

# --- arm 4 -----------------------------------------------------------------
# Integrity that does not wait for a tag. The signed tag is verified by
# makepkg against validpgpkeys; every other entry is a fixed upstream commit
# whose checksum is known today. So: validpgpkeys names exactly the primary
# key in KEYS, the tag is the one SKIP, and the rest are real sums.
# The text of a NAME=( ... ) array, one line or many, comments dropped.
array_text() {
  awk -v n="$1" 'index($0, n "=(") == 1 {f = 1} f {sub(/#.*/, ""); print} f && /\)/ {exit}' "$recipe"
}
keys="$root/KEYS"
if [ ! -f "$keys" ]; then
  bad "arm4: $keys is missing -- validpgpkeys cannot be shown to name the release key"
elif ! command -v gpg >/dev/null 2>&1; then
  note FAIL "arm4: gpg is not installed -- KEYS cannot be read (cannot judge)"
  exit 2
else
  gh=$(mktemp -d "/var/tmp/check-recipe-gpg.XXXXXX") || { note FAIL "arm4: no temporary directory (cannot judge)"; exit 2; }
  mapfile -t published < <(GNUPGHOME="$gh" gpg --batch --show-keys --with-colons "$keys" 2>/dev/null \
                           | awk -F: '$1=="pub"{p=1; next} p && $1=="fpr"{print $10; p=0}')
  rm -rf "$gh"
  mapfile -t declared < <(array_text validpgpkeys \
                          | grep -oE "[0-9A-Fa-f]{40}" | tr '[:lower:]' '[:upper:]')
  if [ "${#published[@]}" -ne 1 ]; then
    bad "arm4: KEYS holds ${#published[@]} primary key(s); expected exactly one release key"
  elif [ "${#declared[@]}" -ne 1 ] || [ "${declared[0]}" != "${published[0]}" ]; then
    bad "arm4: validpgpkeys must be exactly the release key in KEYS (${published[0]}), found: ${declared[*]:-none}"
  else
    printf 'arm4: validpgpkeys names the release key in KEYS (%s)\n' "${published[0]}"
  fi

  sums=$(array_text sha256sums)
  mapfile -t vals < <(printf '%s\n' "$sums" | grep -oE "'[^']*'" | tr -d "'")
  if [ "${#vals[@]}" -eq 0 ]; then
    bad "arm4: no sha256sums entries found -- the pattern matches nothing, which is a vacuum and not a pass"
  elif [ "${#vals[@]}" -ne "${#entries[@]}" ]; then
    bad "arm4: ${#entries[@]} source entr$([ "${#entries[@]}" -eq 1 ] && echo y || echo ies) but ${#vals[@]} sha256sums"
  else
    i=0; real=0
    for e in "${entries[@]}"; do
      v=${vals[$i]}; i=$((i + 1))
      case "$e" in
        *git+*'?signed'*)
          [ "$v" = SKIP ] || bad "arm4: the signed tag's checksum must be SKIP (git sources carry none; the signature is the check), found $v" ;;
        *)
          if [[ "$v" =~ ^[0-9a-f]{64}$ ]]; then real=$((real + 1))
          else bad "arm4: entry $i has checksum '$v', not a real sha256 -- it is a fixed upstream commit, so its sum is known now: $e"; fi ;;
      esac
    done
    printf 'arm4: %d sha256sums, %d real checksum(s), the signed tag SKIP\n' "${#vals[@]}" "$real"
  fi
fi

echo "check-recipe: $([ $rc -eq 0 ] && echo GREEN || echo RED)"
exit "$rc"

#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Selftest for check-recipe.sh. Ten shapes the recipe (or the tree around it)
# gets wrong, plus the real recipe as a control. One of the ten only applies to
# a repository whose recipe carries a FetchContent pin; where it does not, the
# file says so out loud and counts one case fewer, because a silently dropped
# case is indistinguishable from one that passed.
#
# Each case asserts three things, because two of them are not enough:
#   * the fixture actually differs from the control (a perturbation that
#     changed nothing passes for the wrong reason);
#   * the exit code is non-zero;
#   * the named arm appears in the output. An exit code alone cannot tell a
#     refusal that worked from a refusal that fired on something else.
#
# Every fixture is a throwaway git repository under /var/tmp -- never the
# working tree, and never /tmp, which is RAM on this machine. The fixture's top
# directory carries the REPOSITORY's name: arm 1 compares the owner segment of
# the source URL against it, so a fixture named anything else would fail every
# case for a reason the case is not about.
#
# Both git object-writing commands are run with signing turned off for the
# invocation. A maintainer with tag.gpgSign=true set globally does not get a
# lightweight tag from `git tag` but a signed annotated one, which asks for a
# message in an editor and a passphrase from pinentry: the case would either
# fail to create the tag -- leaving arm 4 to print SKIPPED, exit 0, and the case
# to report "expected a non-zero exit, got 0" -- or hang on the prompt. CI has
# no global configuration and would not have seen either, so the gate would have
# been green there and red or wedged on the machine that has to maintain it.
set -u

here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
subject="$here/check-recipe.sh"
control_recipe="$here/PKGBUILD"
root=$(CDPATH= cd -- "$here/../.." && pwd)
rname=$(basename "$root")

work="${TMPDIR_SELFTEST:-/var/tmp/check-recipe-selftest.$$}"
rm -rf "$work"; mkdir -p "$work"
trap 'rm -rf "$work"' EXIT

fails=0
cases=0
red=0

fx() { printf '%s/%s/%s\n' "$work" "$1" "$rname"; }

# fixture <name> -> builds $(fx <name>) as a minimal repository
fixture() {
    local c="$1" d
    d=$(fx "$c")
    mkdir -p "$d/packaging/arch" "$d/ci/scripts"
    cp "$control_recipe" "$d/packaging/arch/PKGBUILD"
    cp "$subject"        "$d/packaging/arch/check-recipe.sh"
    chmod +x "$d/packaging/arch/check-recipe.sh"
    cp "$root/VERSION"   "$d/VERSION"
    [ -f "$here/README.md" ] && cp "$here/README.md" "$d/packaging/arch/README.md"
    # arm 5 asks the top-level CMakeLists.txt which install options exist.
    [ -f "$root/CMakeLists.txt" ] && cp "$root/CMakeLists.txt" "$d/CMakeLists.txt"
    # arm 1 reads the source name out of this script; without it every case
    # would fail on a missing input rather than on what it perturbs.
    cp "$root/ci/scripts/make-source-tarball.sh" "$d/ci/scripts/"
    [ -f "$root/cmake/FetchQCBOR.cmake" ] && {
        mkdir -p "$d/cmake"
        cp "$root/cmake/FetchQCBOR.cmake" "$d/cmake/"
    }
    git -C "$d" init --quiet
    git -C "$d" add -A >/dev/null 2>&1
    git -C "$d" -c user.name=selftest -c user.email=selftest@invalid \
        -c commit.gpgsign=false \
        commit --quiet -m fixture >/dev/null 2>&1
}

run() {  # run <name> ; sets $out and $rc
    out=$(cd "$(fx "$1")" && bash packaging/arch/check-recipe.sh 2>&1)
    rc=$?
}

expect_red() {  # expect_red <name> <substring>
    local c="$1" want="$2" d
    d=$(fx "$c")
    cases=$((cases + 1))
    # every case here is a perturbation: a red one is the proof.
    red=$((red + 1))
    if cmp -s "$d/packaging/arch/PKGBUILD" "$control_recipe" \
       && cmp -s "$d/VERSION" "$root/VERSION" 2>/dev/null; then
        echo "CASE $c: the fixture is identical to the control -- the perturbation changed nothing"
        fails=$((fails + 1)); return
    fi
    run "$c"
    if [ "$rc" -eq 0 ]; then
        echo "CASE $c: expected a non-zero exit, got 0"; fails=$((fails + 1)); return
    fi
    case "$out" in
        *"$want"*) : ;;
        *) echo "CASE $c: exit was non-zero but no line mentions '$want'"
           printf '%s\n' "$out" | sed 's/^/    /'
           fails=$((fails + 1)) ;;
    esac
}

expect_red_out() {  # expect_red_out <name> <substring> -- for perturbations
                    # that touch the tree rather than the recipe text
    local c="$1" want="$2"
    cases=$((cases + 1))
    red=$((red + 1))
    run "$c"
    if [ "$rc" -eq 0 ]; then
        echo "CASE $c: expected a non-zero exit, got 0"
        printf '%s\n' "$out" | sed 's/^/    /'
        fails=$((fails + 1)); return
    fi
    case "$out" in
        *"$want"*) : ;;
        *) echo "CASE $c: exit was non-zero but no line mentions '$want'"
           printf '%s\n' "$out" | sed 's/^/    /'
           fails=$((fails + 1)) ;;
    esac
}

# 1 -- the v-prefixed auto archive: the shape every recipe carried before the
#      release workflow began publishing a tarball of its own.
fixture v_prefixed_archive
sed -i 's#releases/download/\$pkgver/[^"]*#archive/refs/tags/v$pkgver.tar.gz#' \
    "$(fx v_prefixed_archive)/packaging/arch/PKGBUILD"
expect_red v_prefixed_archive "arm1"

# 2 -- the UNPREFIXED auto archive. This one resolves for a repository that has
#      published a tag, so nothing at build time would complain; only the gate
#      can say the bytes are not ours.
fixture unprefixed_archive
sed -i 's#releases/download/\$pkgver/[^"]*#archive/refs/tags/$pkgver.tar.gz#' \
    "$(fx unprefixed_archive)/packaging/arch/PKGBUILD"
expect_red unprefixed_archive "auto-generated archive"

# 3 -- pkgver disagrees with VERSION.
fixture pkgver_drift
sed -i 's/^pkgver=.*/pkgver=4.2.0/' "$(fx pkgver_drift)/packaging/arch/PKGBUILD"
expect_red pkgver_drift "arm2"

# 4 -- VERSION missing entirely. A missing input is a failure, not a skip.
fixture no_version
rm -f "$(fx no_version)/VERSION"
expect_red no_version "arm2"

# 5 -- the vacuum: source=() renamed so the pattern matches nothing.
fixture vacuum_source
sed -i 's/^source=(/sources=(/' "$(fx vacuum_source)/packaging/arch/PKGBUILD"
expect_red vacuum_source "vacuum"

# 6 -- the asset name drifts from the one make-source-tarball.sh writes. The
#      URL is still a releases/download/ one, so shape alone cannot catch it;
#      the first makepkg would 404.
fixture asset_name_drift
sed -i 's#/\([a-z-]*\)_\$pkgver\.orig\.tar\.gz#/\1-sources_$pkgver.orig.tar.gz#' \
    "$(fx asset_name_drift)/packaging/arch/PKGBUILD"
expect_red asset_name_drift "the release workflow uploads"

# 7 -- the recipe fetches a SIBLING repository's asset. A recipe of this shape
#      is written by copying a near-identical one, so this is what a careless
#      copy produces.
fixture sibling_repo
sed -i "s#github.com/LibreSCRS/$rname/releases#github.com/LibreSCRS/NotThisRepo/releases#" \
    "$(fx sibling_repo)/packaging/arch/PKGBUILD"
expect_red sibling_repo "while this repository is"

# 8 -- a submodule gitlink the recipe does not pin. This is the drift that
#      actually ships a package built from the wrong upstream tree, and it is
#      invisible in the recipe text: the perturbation is in the INDEX.
fixture gitlink_drift
git -C "$(fx gitlink_drift)" update-index --add \
    --cacheinfo 160000,1111111111111111111111111111111111111111,thirdparty/not-pinned \
    >/dev/null 2>&1
if [ -z "$(git -C "$(fx gitlink_drift)" ls-files -s -- thirdparty/not-pinned)" ]; then
    echo "CASE gitlink_drift: the gitlink was not written -- the perturbation changed nothing"
    cases=$((cases + 1)); fails=$((fails + 1))
else
    expect_red_out gitlink_drift "arm3: submodule"
fi

# 9 -- the FetchContent pin drifts from the cmake module the build fetches
#      with. Only applies where the recipe carries one.
if grep -q '^_qcbor_commit=' "$control_recipe"; then
    fixture fetchcontent_drift
    sed -i -E 's/^([[:space:]]*GIT_TAG[[:space:]]+)[0-9a-f]{40}/\12222222222222222222222222222222222222222/' \
        "$(fx fetchcontent_drift)/cmake/FetchQCBOR.cmake"
    if cmp -s "$(fx fetchcontent_drift)/cmake/FetchQCBOR.cmake" "$root/cmake/FetchQCBOR.cmake"; then
        echo "CASE fetchcontent_drift: the pin was not rewritten -- the perturbation changed nothing"
        cases=$((cases + 1)); fails=$((fails + 1))
    else
        expect_red_out fetchcontent_drift "arm3b: QCBOR pin drift"
    fi
else
    echo "CASE fetchcontent_drift: not applicable -- this recipe carries no _qcbor_commit"
fi

# 10 -- the tag exists and sha256sums is still SKIP. The tag is created in the
#       throwaway fixture, never in a real clone.
fixture tag_with_skip
cases=$((cases + 1))
v=$(sed -n '1p' "$(fx tag_with_skip)/VERSION" | tr -d '[:space:]')
git -C "$(fx tag_with_skip)" -c tag.gpgSign=false tag "$v"
sed -i "s/^pkgver=.*/pkgver=$v/" "$(fx tag_with_skip)/packaging/arch/PKGBUILD"
sed -i "/^sha256sums=(/,/)/s/'[0-9a-f]\{64\}'/'SKIP'/g" \
    "$(fx tag_with_skip)/packaging/arch/PKGBUILD"
run tag_with_skip
if [ "$rc" -eq 0 ]; then
    echo "CASE tag_with_skip: expected a non-zero exit, got 0"; fails=$((fails + 1))
else
    case "$out" in *"arm4"*) : ;; *)
        echo "CASE tag_with_skip: exit was non-zero but no line mentions 'arm4'"
        printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1)) ;;
    esac
fi

# 12-15 -- the recipe and its README claim a p11-kit registration the build
#          does not install. Only in a recipe whose build() can install one.
if grep -q 'INSTALL_P11KIT_MODULE\|p11-kit registration' "$control_recipe"; then
    fixture readme_claim
    printf '%s\n' '- `share/p11-kit/modules/librescrs.module` — p11-kit auto-discovery drop-in' \
        >> "$(fx readme_claim)/packaging/arch/README.md"
    if cmp -s "$(fx readme_claim)/packaging/arch/README.md" "$here/README.md"; then
        echo "CASE readme_claim: the README did not change"; cases=$((cases + 1)); fails=$((fails + 1))
    else
        expect_red_out readme_claim "arm5"
    fi

    fixture recipe_claim
    sed -i 's|^    # /usr/share/librescrs/certificates/\*\*\.$|    # /usr/share/librescrs/certificates/**, /usr/share/p11-kit/modules/librescrs.module.|' \
        "$(fx recipe_claim)/packaging/arch/PKGBUILD"
    expect_red recipe_claim "arm5"

    fixture optdepends_claim
    sed -i "s|^options=|optdepends=('p11-kit: auto-discovery of LibreSCRS cards by PKCS#11-aware applications')\noptions=|" \
        "$(fx optdepends_claim)/packaging/arch/PKGBUILD"
    expect_red optdepends_claim "arm5"

    # The claim is true once build() installs the file: not a finding.
    fixture claim_with_option
    sed -i 's|^    # /usr/share/librescrs/certificates/\*\*\.$|    # /usr/share/librescrs/certificates/**, /usr/share/p11-kit/modules/librescrs.module.|' \
        "$(fx claim_with_option)/packaging/arch/PKGBUILD"
    sed -i 's|        -DINSTALL_GTEST=OFF$|        -DINSTALL_GTEST=OFF -DLIBREMIDDLEWARE_INSTALL_P11KIT_MODULE=ON|' \
        "$(fx claim_with_option)/packaging/arch/PKGBUILD"
    cases=$((cases + 1))
    run claim_with_option
    case "$out" in *"arm5: FAIL"*|*"FAIL"*"arm5"*)
        echo "CASE claim_with_option: arm 5 refused a claim build() makes true"
        printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1)) ;;
    esac
else
    echo "CASE p11kit_claims: not applicable -- this recipe installs no PKCS#11 registration"
fi

# 11 -- control: the real recipe, untouched, must pass, and arm 4 must SAY it is
#       skipped. A silent skip is the failure mode this whole file exists for.
fixture control
cases=$((cases + 1))
run control
if [ "$rc" -ne 0 ]; then
    echo "CASE control: the committed recipe does not pass its own gate (rc=$rc)"
    printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1))
fi
case "$out" in
    *"arm4: SKIPPED"*|*"arm4: tag"*) : ;;
    *) echo "CASE control: arm 4 said nothing about itself -- a silent arm is a vacuum"
       printf '%s\n' "$out" | sed 's/^/    /'; fails=$((fails + 1)) ;;
esac

if [ "$fails" -eq 0 ]; then
    echo "check-recipe selftest: all $cases cases passed"
    printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
    exit 0
fi
echo "check-recipe selftest: $fails of $cases case(s) failed"
printf 'selftest: %s cases, %s red-proved\n' "$cases" "$red"
exit 1

#!/usr/bin/env sh
# SPDX-License-Identifier: LGPL-2.1-or-later
# check-version-surfaces.sh
#
# Every surface that states this repo's version must state the one in VERSION.
#
# check-release-lockstep.sh already proves the CHANGELOG and VERSION agree, but
# both of its sides read the same file, so it cannot prove the BUILD agrees.
# It did not: LibreKDE's VERSION, CHANGELOG, PKGBUILD, debian/changelog and rpm
# spec all said 5.0.0 while project() stamped 0.1.0, and the About window, the
# --version output and the plasmoid's applet information all showed 0.1.0. A
# package labelled 5.0.0 installed a binary that said it was 0.1.0.
#
# The surfaces are listed in ci/version-surfaces.txt so this script stays
# byte-identical across repos, the way check-release-lockstep.sh is.
#
# Three kinds read packaging rather than the build: the Debian changelog and
# the RPM spec, which label the packages, and a shell helper the packaging
# scripts source to name the artefacts they build. Nothing else compared any
# of them with VERSION.
#
# Two surface kinds accept a configure_file() template in place of a literal,
# and they differ in how strict that acceptance is. plasma-metadata is listed
# as the plain metadata.json; when that file is absent the script reads
# metadata.json.in instead and requires it to take "Version" from
# @PROJECT_VERSION@, with no further condition -- the plasmoid package is
# installed from the configured copy, so the template is the source of truth
# for that kind. plist-short-version is listed as the .plist.in itself, and
# is accepted as a template only when the list also carries a cmake-project
# row: a plist has no installer step that vouches for a configured copy
# standing in for it, so a template with nothing else in the list measuring
# the stamped number would state no number at all. The two shapes are
# deliberately different in strictness for that reason, and a plain
# (non-.in) plist holding the placeholder is still a mismatch, not a
# template.
#
# Exit: 0 all surfaces agree, 1 one does not, 2 could not be measured.
set -u

VERSION_FILE=${VERSION_FILE:-VERSION}
SURFACE_LIST=${SURFACE_LIST:-ci/version-surfaces.txt}
CMAKE=${CMAKE:-cmake}

undecidable() {   # rc=2 is "I could not judge" -- never "pass"
    echo "::error::check-version-surfaces: $1"
    exit 2
}

[ -f "$VERSION_FILE" ] || undecidable "no $VERSION_FILE to check against"
WANT="$(head -n1 "$VERSION_FILE" | tr -d '[:space:]')"
WANT=${WANT#v}
[ -n "$WANT" ] || undecidable "$VERSION_FILE is empty"
[ -f "$SURFACE_LIST" ] || undecidable "no $SURFACE_LIST -- nothing says which surfaces to check"

WORK="$(mktemp -d)" || undecidable "mktemp failed"
trap 'rm -rf "$WORK"' EXIT

FAIL=0
CHECKED=0
TEMPLATED=0

report() {   # report <surface> <found>
    if [ "$2" = "$WANT" ]; then
        echo "  -> $1 states $WANT"
    else
        echo "::error::$1 states '$2' but $VERSION_FILE says '$WANT' -- a package labelled $WANT would ship something that calls itself $2."
        FAIL=1
    fi
}

# --- kind: cmake-project ----------------------------------------------------
# Measures the number project() actually stamps, by configuring the REAL
# CMakeLists.txt with CMAKE_PROJECT_INCLUDE -- a file CMake evaluates the
# moment project() returns. The probe writes the version out and aborts, so no
# find_package() runs and this needs none of the project's dependencies.
# Reading the number out of a hand-written mock would measure the mock.
#
# GIT_EXECUTABLE is defined-but-empty on purpose: GitVersion.cmake then takes
# the VERSION-file path, which is the path a release tarball takes and the one
# packagers build. With git left on, `git describe` wins, and between a release
# and the next code freeze the newest tag legitimately differs from VERSION --
# the check would go red on a tree with nothing wrong with it.
check_cmake_project() {
    dir=$1
    command -v "$CMAKE" >/dev/null 2>&1 || undecidable "no cmake on PATH (set CMAKE=) -- cannot measure what project() stamps"
    cat > "$WORK/probe.cmake" <<'PROBE'
file(WRITE "$ENV{VERSION_SURFACE_OUT}" "${PROJECT_NAME} ${PROJECT_VERSION}\n")
message(FATAL_ERROR "check-version-surfaces: probe done, stopping before find_package()")
PROBE
    VERSION_SURFACE_OUT="$WORK/stamp"
    export VERSION_SURFACE_OUT
    rm -rf "$WORK/build" "$VERSION_SURFACE_OUT"
    "$CMAKE" -S "$dir" -B "$WORK/build" -DGIT_EXECUTABLE= \
        -DCMAKE_PROJECT_INCLUDE="$WORK/probe.cmake" > "$WORK/configure.log" 2>&1
    if [ ! -s "$VERSION_SURFACE_OUT" ]; then
        sed 's/^/    /' "$WORK/configure.log" >&2
        undecidable "the configure of '$dir' died before project() reported anything (log above)"
    fi
    name="$(cut -d' ' -f1 "$VERSION_SURFACE_OUT")"
    got="$(cut -d' ' -f2 "$VERSION_SURFACE_OUT")"
    # An empty stamp is a failure to measure, not a mismatch: a CMakeLists.txt
    # with no project() call still fires this hook, because CMake supplies an
    # implicit project(Project) carrying no version. Calling that a mismatch
    # would blame the tree for this check's own blind spot.
    [ -n "$got" ] || undecidable "project($name) in '$dir' carries no VERSION to measure"
    report "project($name) in $dir" "$got"
}

# --- kind: plasma-metadata --------------------------------------------------
# KPlugin.Version in a Plasma package metadata.json. The package directory is
# installed verbatim by plasma_install_package(), so whatever stands here is
# what Plasma shows in the widget's information.
#
# Two shapes are accepted: a literal, which must equal VERSION; or a
# metadata.json.in template carrying @PROJECT_VERSION@ and no literal beside
# it, for a tree that has moved to configure_file(). A literal @PROJECT_VERSION@
# inside an installed metadata.json is neither -- that is a configure_file()
# that never ran, and Plasma would show the placeholder itself.
check_plasma_metadata() {
    f=$1
    if [ -f "$f" ]; then
        got="$(sed -n 's/^[[:space:]]*"Version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$f" | head -n1)"
        if [ -z "$got" ]; then
            echo "::error::$f has no \"Version\" key -- Plasma would show no version for the applet."
            FAIL=1
        elif [ "$got" = '@PROJECT_VERSION@' ]; then
            echo "::error::$f still holds the literal @PROJECT_VERSION@ -- it is installed verbatim, so configure_file() must write it into the build dir and plasma_install_package() must point there."
            FAIL=1
        else
            report "$f (KPlugin.Version)" "$got"
        fi
    elif [ -f "$f.in" ]; then
        if grep -q '"Version"[[:space:]]*:[[:space:]]*"@PROJECT_VERSION@"' "$f.in"; then
            TEMPLATED=$((TEMPLATED + 1))
            echo "  -> $f.in takes Version from @PROJECT_VERSION@"
        else
            echo "::error::$f.in does not take \"Version\" from @PROJECT_VERSION@."
            FAIL=1
        fi
    else
        undecidable "neither $f nor $f.in exists"
    fi
}

# --- kind: plist-short-version ----------------------------------------------
# CFBundleShortVersionString in an XML plist -- the embedded __info_plist of a
# bare Mach-O, or a bundle's Info.plist. This is the number Finder, `mdls`,
# About windows and anything reading Bundle.main.infoDictionary report.
#
# A listed path ending in .in is a configure_file() template, and the same two
# shapes apply as for the plugin metadata: @PROJECT_VERSION@ is what a tree
# that has stopped hand-typing the number looks like, while a literal inside a
# template is still a hand-typed number and is still compared against VERSION.
# The difference from the metadata kind is the extra condition: a template
# states no number of its own, so it is accepted only when the list also names
# a cmake-project surface -- that one measures what the build really stamps,
# which is the number configure_file() fills in here. With no such surface the
# whole list could become templates and the gate would have nothing left to
# compare, which is a vacuum, not a pass.
check_plist_short_version() {
    f=$1
    [ -f "$f" ] || undecidable "$f does not exist"
    is_template=0
    case "$f" in *.in) is_template=1 ;; esac
    got="$(awk '/<key>CFBundleShortVersionString<\/key>/ {
                    getline
                    if (match($0, /<string>[^<]*<\/string>/)) {
                        print substr($0, RSTART + 8, RLENGTH - 17); exit
                    }
                }' "$f")"
    if [ -z "$got" ]; then
        echo "::error::$f has no CFBundleShortVersionString."
        FAIL=1
    elif [ "$is_template" -eq 1 ] && [ "$got" = '@PROJECT_VERSION@' ]; then
        [ "$HAS_CMAKE_PROJECT" -eq 1 ] || undecidable "$f takes CFBundleShortVersionString from @PROJECT_VERSION@, but $SURFACE_LIST names no cmake-project surface -- nothing measures the number the build would fill in here."
        TEMPLATED=$((TEMPLATED + 1))
        echo "  -> $f takes CFBundleShortVersionString from @PROJECT_VERSION@"
    else
        report "$f (CFBundleShortVersionString)" "$got"
    fi
}

# --- kind: yaml-short-version -----------------------------------------------
# CFBundleShortVersionString in an xcodegen project spec. This one is upstream
# of the generated Info.plist: editing the plist alone is undone by the next
# `xcodegen generate`.
check_yaml_short_version() {
    f=$1
    [ -f "$f" ] || undecidable "$f does not exist"
    got="$(sed -n 's/^[[:space:]]*CFBundleShortVersionString:[[:space:]]*"\{0,1\}\([^"[:space:]]*\)"\{0,1\}[[:space:]]*$/\1/p' "$f" | head -n1)"
    if [ -z "$got" ]; then
        echo "::error::$f has no CFBundleShortVersionString."
        FAIL=1
    else
        report "$f (CFBundleShortVersionString)" "$got"
    fi
}

# --- kind: debian-changelog -------------------------------------------------
# The first entry of a Debian changelog names the version dpkg stamps on every
# package built from the tree. Only the upstream part is compared: a leading
# epoch ("1:") and the trailing Debian revision ("-1") belong to the packaging,
# not to the release.
check_debian_changelog() {
    f=$1
    [ -f "$f" ] || undecidable "$f does not exist"
    got="$(head -n1 "$f" | sed -n 's/^[^ ]* (\([^)]*\)).*/\1/p')"
    if [ -z "$got" ]; then
        echo "::error::$f does not open with a '<source> (<version>) ...' entry."
        FAIL=1
        return
    fi
    got=${got#*:}
    got=${got%-*}
    report "$f (Debian version)" "$got"
    # The file is generated, never edited by hand: say which generator.
    [ "$got" = "$WANT" ] \
        || echo "::error::regenerate $f with ci/scripts/changelog-to-debian.sh <source-package> $f"
}

# --- kind: rpm-spec-version --------------------------------------------------
# The spec's Version: tag, which rpmbuild stamps on the package name.
check_rpm_spec_version() {
    f=$1
    [ -f "$f" ] || undecidable "$f does not exist"
    got="$(sed -n 's/^Version:[[:space:]]*\([^[:space:]]*\).*/\1/p' "$f" | head -n1)"
    if [ -z "$got" ]; then
        echo "::error::$f has no Version: tag."
        FAIL=1
    else
        report "$f (Version:)" "$got"
    fi
}

# --- kind: shell-version-helper ----------------------------------------------
# A helper other scripts source to name the artefacts they build: it defines
# project_version <root>. It is asked with the ABSOLUTE, physical root, as its
# production callers ask it. That is not style: a helper that consults git only
# when its argument equals git's toplevel never matches a relative ".", falls
# through to the VERSION file, and prints the right number for the wrong
# reason -- the check would then be measuring the guard, not the surface.
check_shell_version_helper() {
    f=$1
    [ -f "$f" ] || undecidable "$f does not exist"
    command -v bash >/dev/null 2>&1 || undecidable "no bash on PATH -- cannot run $f"
    root="$(cd . && pwd -P)"
    got="$(bash -c '. "$1" && project_version "$2"' _ "$root/$f" "$root" 2>"$WORK/helper.err")" \
        || { sed 's/^/    /' "$WORK/helper.err" >&2; undecidable "$f could not be sourced, or project_version failed"; }
    [ -n "$got" ] || undecidable "$f: project_version printed nothing"
    report "$f (project_version)" "$got"
}

# Pre-scan for the surface that measures what the build stamps. A template is
# only judgeable through that one, and the list is read in file order, so a
# cmake-project row standing AFTER the rows it vouches for would otherwise be
# invisible to them -- the gate would then depend on how the list is sorted.
HAS_CMAKE_PROJECT=0
while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    [ "${line%%[ 	]*}" = cmake-project ] && HAS_CMAKE_PROJECT=1
done < "$SURFACE_LIST"

while IFS= read -r line; do
    case "$line" in ''|'#'*) continue ;; esac
    kind=${line%%[ 	]*}
    path=${line#"$kind"}
    path=$(printf '%s' "$path" | sed 's/^[[:space:]]*//; s/[[:space:]]*$//')
    [ -n "$path" ] || undecidable "$SURFACE_LIST: '$line' names a kind but no path"
    CHECKED=$((CHECKED + 1))
    case "$kind" in
        cmake-project)       check_cmake_project "$path" ;;
        plasma-metadata)     check_plasma_metadata "$path" ;;
        plist-short-version) check_plist_short_version "$path" ;;
        yaml-short-version)  check_yaml_short_version "$path" ;;
        debian-changelog)    check_debian_changelog "$path" ;;
        rpm-spec-version)    check_rpm_spec_version "$path" ;;
        shell-version-helper) check_shell_version_helper "$path" ;;
        *) undecidable "$SURFACE_LIST: unknown surface kind '$kind'" ;;
    esac
done < "$SURFACE_LIST"

# An empty list is the vacuum case: every surface agreed because none was
# named. A gate that cannot fail is not a gate.
[ "$CHECKED" -gt 0 ] || undecidable "$SURFACE_LIST names no surfaces"

if [ "$FAIL" -eq 0 ]; then
    if [ "$TEMPLATED" -gt 0 ]; then
        echo "  -> all $CHECKED version surface(s) agree with VERSION ($TEMPLATED read the number from a configure_file template)"
    else
        echo "  -> all $CHECKED version surface(s) state $WANT"
    fi
fi
exit "$FAIL"

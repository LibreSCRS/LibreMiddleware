# SPDX-License-Identifier: LGPL-2.1-or-later
# GitVersion
#
# Version derived from the repository's own git tags (https://semver.org/).
# Every LibreSCRS repository carries a byte-identical copy in its cmake/ (the
# check-version gate compares the two): six copies used to answer this one
# question six ways, and a second resolver beside one of them had to be told
# that "the two used to differ".
#
# GIT_VERSION_FULL   - The full, honest version string: a MAJOR.MINOR.PATCH
#                      triple, plus the commit distance and abbreviated hash
#                      when the tree is past the tag that distance is measured
#                      from (`5.0.0-38-gda5a00c`), plus `-dirty` when the
#                      working tree has uncommitted changes. Exactly a bare
#                      triple ONLY on a tagged commit with a clean tree.
#
#                      The triple is the NEWER of the nearest release tag and
#                      the VERSION file (see the note further down), so during
#                      a development cycle it is VERSION's while the distance
#                      and hash still count from the older tag. That pairing is
#                      the point: the number says which release this tree is
#                      heading for, and the suffix says it has not arrived.
# GIT_VERSION_MAJOR  - Major component of the leading numeric triple
# GIT_VERSION_MINOR  - Minor component
# GIT_VERSION_PATCH  - Patch component
#
# The numeric triple is the *only* thing that may feed `project(VERSION ...)`,
# CMake's own version comparisons, SOVERSION and the macOS bundle version keys:
# all of them reject a suffix. The full string is what user-facing banners show, because a
# development build that prints a bare release number is claiming to be a
# release it is not.
#
# "The repository's OWN tags" is load-bearing and is checked rather than assumed
# — see the ownership test below. Nothing here is allowed to fail the configure:
# every way of answering the question degrades to the next one and the last
# resort is a constant, because a version string is a label on the build, never
# a precondition for producing it.
#
# The stamp is refreshed by re-running configure, and the git state that feeds it
# is registered in CMAKE_CONFIGURE_DEPENDS so that happens on its own when the
# commit or the working tree moves. Without that registration the FIRST configure
# of a build tree froze the answer: the build stayed up to date, the generator
# reported no work to do, and the banner went on naming a commit the tree had
# long left behind — `-dirty` marker and all, on a clean checkout.

if(NOT DEFINED GIT_EXECUTABLE)
    find_package(Git QUIET REQUIRED)
endif()

# The repo root relative to THIS module (cmake/), not CMAKE_SOURCE_DIR and not
# PROJECT_VERSION: the module must describe its own repository no matter which
# directory the top-level build starts from, and a repository consumed through
# FetchContent or add_subdirectory() sees the ENCLOSING project's
# PROJECT_VERSION before its own project() call. REALPATH collapses the `/..` and
# resolves symlinks on the way, because the ownership test below compares this
# against a path git prints already normalised — `<root>/cmake/..` is the same
# directory as `<root>` but never the same string.
get_filename_component(GIT_VERSION_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/.." REALPATH)

# Empty until something answers for it. Each source below fills it only with a
# string it has already checked carries a numeric triple, so the parse at the
# bottom cannot be handed a value that fails.
set(GIT_VERSION_FULL "")
set(GIT_VERSION_OWN_REPO FALSE)
set(GIT_VERSION_GIT_DIR "")
set(GIT_VERSION_REFS_DIR "")

if(GIT_EXECUTABLE)
    # WHOSE repository is answering? git searches from the working directory
    # UPWARDS, so a source tree carrying no `.git` of its own — a release
    # tarball unpacked into an AUR `$srcdir`, a gbp build area, a Nix sandbox,
    # a vendored copy inside somebody else's checkout — is answered by whatever
    # repository happens to ENCLOSE it. `describe` then succeeds against a
    # completely unrelated project's tags and stamps that project's version
    # onto this build; and because it succeeded, the VERSION file that would
    # have given the right answer is never reached. The tags may only be
    # believed when the repository git found is this source tree itself.
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --show-toplevel
        WORKING_DIRECTORY ${GIT_VERSION_SRC_DIR}
        OUTPUT_VARIABLE GIT_VERSION_TOPLEVEL
        RESULT_VARIABLE GIT_VERSION_TOPLEVEL_ERROR_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET # "not a git repository" is an ordinary answer here
        )
    if(NOT GIT_VERSION_TOPLEVEL_ERROR_CODE AND GIT_VERSION_TOPLEVEL)
        get_filename_component(GIT_VERSION_TOPLEVEL "${GIT_VERSION_TOPLEVEL}" REALPATH)
        if(GIT_VERSION_TOPLEVEL STREQUAL GIT_VERSION_SRC_DIR)
            set(GIT_VERSION_OWN_REPO TRUE)
        endif()
    endif()
endif()

if(GIT_VERSION_OWN_REPO)
    # Two deliberate departures from the plain `describe --tags`:
    #
    #  * NO `--abbrev=0`. That flag prints the bare tag name and nothing else,
    #    which is precisely what made every between-tags build advertise itself
    #    as the last release. Without it, describe appends `-<commits>-g<sha>`
    #    off-tag and prints the bare tag on a tagged commit.
    #  * `--match` restricted to VERSION-SHAPED tags: a leading digit and two
    #    further dot-separated groups that each start with one. A clone may
    #    carry local rollback/bookkeeping tags, and that none of them begins
    #    with a digit is a property of the names chosen so far, not a rule
    #    anyone enforces: a date-stamped bookkeeping tag would satisfy a bare
    #    `[0-9]*` glob on the day someone makes one.
    execute_process(
        COMMAND ${GIT_EXECUTABLE} describe --tags --dirty
                --match "[0-9]*.[0-9]*.[0-9]*" --match "v[0-9]*.[0-9]*.[0-9]*"
        WORKING_DIRECTORY ${GIT_VERSION_SRC_DIR}
        OUTPUT_VARIABLE GIT_DESCRIBE_VERSION
        RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET # silence git's "fatal: No names found" on a tagless clone
        )
    if(NOT GIT_DESCRIBE_ERROR_CODE AND GIT_DESCRIBE_VERSION)
        string(REGEX REPLACE "^v" "" GIT_DESCRIBE_VERSION "${GIT_DESCRIBE_VERSION}")
        # `--match` is an fnmatch glob, not a version grammar: `1a.2.3` passes
        # it and carries no triple. A tag nobody can parse is a bookkeeping
        # mistake in ONE clone, and it must not brick configure for everyone
        # who fetched it — name it and let the VERSION file answer instead.
        if(GIT_DESCRIBE_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+")
            set(GIT_VERSION_FULL "${GIT_DESCRIBE_VERSION}")
        else()
            message(WARNING "Nearest git tag \"${GIT_DESCRIBE_VERSION}\" carries no MAJOR.MINOR.PATCH triple; "
                            "falling back to the VERSION file.")
        endif()
    endif()

    # `.git` is a FILE, not a directory, in a worktree and in a submodule, so
    # the state to watch has to be asked for rather than assumed to sit at
    # `${GIT_VERSION_SRC_DIR}/.git`.
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --absolute-git-dir
        WORKING_DIRECTORY ${GIT_VERSION_SRC_DIR}
        OUTPUT_VARIABLE GIT_VERSION_GIT_DIR
        RESULT_VARIABLE GIT_VERSION_GIT_DIR_ERROR_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        )
    if(GIT_VERSION_GIT_DIR_ERROR_CODE)
        set(GIT_VERSION_GIT_DIR "")
    endif()

    # The COMMON dir, as opposed to the absolute one above: in a linked
    # worktree, --absolute-git-dir answers with the worktree's PRIVATE
    # gitdir (HEAD, index, logs — nothing else), which carries no refs/tags
    # and no packed-refs at all; those live only in the dir every worktree
    # shares. In an ordinary checkout the two answers coincide, so this is
    # never wrong to ask, only sometimes redundant.
    execute_process(
        COMMAND ${GIT_EXECUTABLE} rev-parse --path-format=absolute --git-common-dir
        WORKING_DIRECTORY ${GIT_VERSION_SRC_DIR}
        OUTPUT_VARIABLE GIT_VERSION_REFS_DIR
        RESULT_VARIABLE GIT_VERSION_REFS_DIR_ERROR_CODE
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET
        )
    if(GIT_VERSION_REFS_DIR_ERROR_CODE)
        set(GIT_VERSION_REFS_DIR "")
    endif()
endif()

if(GIT_VERSION_GIT_DIR)
    # HEAD moves on a checkout, a branch switch and a detach; the index is
    # rewritten by every commit and every `git add`, which is what makes a
    # `-dirty` marker go stale. Touching either re-runs configure, and the
    # stamp is derived again from the tree that is actually there. Both are
    # PER-WORKTREE state, so both are watched at the worktree-private gitdir
    # — never at the common one, which has neither.
    foreach(GIT_VERSION_STAMP_INPUT IN ITEMS HEAD index)
        if(EXISTS "${GIT_VERSION_GIT_DIR}/${GIT_VERSION_STAMP_INPUT}")
            set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
                                                  "${GIT_VERSION_GIT_DIR}/${GIT_VERSION_STAMP_INPUT}")
        endif()
    endforeach()
    unset(GIT_VERSION_STAMP_INPUT)
endif()

if(GIT_VERSION_REFS_DIR)
    # Neither HEAD nor the index moves on the event that actually changes what
    # `describe --tags` answers on an otherwise unmoved HEAD: creating a
    # release tag. A tag is repository-wide, not per-worktree, so it has to be
    # watched at the COMMON dir (see above) rather than at the worktree's own
    # — in a linked worktree the private gitdir carries neither packed-refs
    # nor a refs/tags directory at all, so watching it there is silently inert.
    #
    # packed-refs is watched the same way index is: `git pack-refs` can fold a
    # loose tag into it and rewrite it without touching HEAD or the index.
    if(EXISTS "${GIT_VERSION_REFS_DIR}/packed-refs")
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS "${GIT_VERSION_REFS_DIR}/packed-refs")
    endif()

    # A newly created loose tag lands under refs/tags instead, touching
    # neither HEAD, the index, nor packed-refs. Re-globbing the directory at
    # build time and comparing the matched file set (CONFIGURE_DEPENDS)
    # notices an added or removed file rather than trusting the directory's
    # raw mtime.
    file(GLOB_RECURSE GIT_VERSION_TAG_REFS CONFIGURE_DEPENDS "${GIT_VERSION_REFS_DIR}/refs/tags/*")
    unset(GIT_VERSION_TAG_REFS)
endif()

# The VERSION file is read UNCONDITIONALLY, and the NEWER of the two triples
# wins.
#
# Two callers used to be conflated here. Release tarballs and GitHub source
# archives ship no .git tree, a shallow/tagless clone has no tag to describe
# against, and a source drop inside a foreign repository is refused the
# enclosing repo's tags above — for all of them `git describe` cannot answer
# and the committed VERSION file is the only version there is. A DEVELOPMENT
# checkout has the opposite problem: describe answers with the PREVIOUS release
# for the whole cycle, so between code freeze (VERSION bumped) and the tag the
# build stamps the OLD major while VERSION, the CHANGELOG and the packaging all
# state the new one. Measured: VERSION, the deb/rpm metadata and the changelog
# said 5.0.0 while project(), the About window and the macOS bundle keys said
# 4.2.0; an installed CONFIG package advertised the old major, so
# `find_package(LibreMiddleware 5.0 CONFIG)` refused it in three repositories
# at once -- on every push, before any tag.
#
# So VERSION is not a fallback, it is a floor: it carries the version this tree
# is heading for and is bumped at code freeze. The tag still wins on the
# release commit (equal) and on any checkout whose tag is ahead of VERSION.
# Only the leading triple is taken from it, and of what describe appended only
# what still describes THIS tree: the commit distance, the abbreviated hash and
# the dirty marker are kept, so a development build goes on saying it is one
# instead of introducing itself as the release. A pre-release LABEL is dropped,
# because it belonged to the older tag: carrying `4.0.0-rc2` across a 5.0.0
# VERSION would announce a release candidate of a version that never had one.
set(GIT_VERSION_FILE "")
if(EXISTS "${GIT_VERSION_SRC_DIR}/VERSION")
    file(STRINGS "${GIT_VERSION_SRC_DIR}/VERSION" GIT_VERSION_FILE LIMIT_COUNT 1)
    string(STRIP "${GIT_VERSION_FILE}" GIT_VERSION_FILE)
    string(REGEX REPLACE "^v" "" GIT_VERSION_FILE "${GIT_VERSION_FILE}")
    if(NOT GIT_VERSION_FILE MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+")
        message(WARNING "VERSION file holds \"${GIT_VERSION_FILE}\", which carries no MAJOR.MINOR.PATCH triple; "
                        "ignoring it.")
        set(GIT_VERSION_FILE "")
    endif()
endif()

if(GIT_VERSION_FULL STREQUAL "")
    set(GIT_VERSION_FULL "${GIT_VERSION_FILE}")
elseif(NOT GIT_VERSION_FILE STREQUAL "")
    # Numeric triples only: a pre-release label on the tag (5.0.0-rc2) must not
    # decide the comparison against a plain VERSION.
    string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" GIT_VERSION_TAG_TRIPLE "${GIT_VERSION_FULL}")
    string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" GIT_VERSION_FILE_TRIPLE "${GIT_VERSION_FILE}")
    if(GIT_VERSION_FILE_TRIPLE VERSION_GREATER GIT_VERSION_TAG_TRIPLE)
        # Rebuilt from the parts that are still true rather than substituted in
        # place: a substitution keeps whatever sat between the old triple and
        # the distance, and on a tree whose nearest tag is a pre-release that is
        # the rc label.
        set(GIT_VERSION_KEPT "")
        if(GIT_VERSION_FULL MATCHES "(-[0-9]+-g[0-9a-f]+)")
            string(APPEND GIT_VERSION_KEPT "${CMAKE_MATCH_1}")
        endif()
        if(GIT_VERSION_FULL MATCHES "-dirty$")
            string(APPEND GIT_VERSION_KEPT "-dirty")
        endif()
        set(GIT_VERSION_FULL "${GIT_VERSION_FILE_TRIPLE}${GIT_VERSION_KEPT}")
        unset(GIT_VERSION_KEPT)
    endif()
endif()

if(GIT_VERSION_FULL STREQUAL "")
    set(GIT_VERSION_FULL 0.0.1)
    message(WARNING "Failed to determine the version from git tags or the VERSION file. "
                    "Using default version \"${GIT_VERSION_FULL}\".")
endif()

# The leading numeric triple, and only that. Anything the version string carries
# beyond it (pre-release label, commit distance, hash, dirty marker) belongs to
# GIT_VERSION_FULL alone — every consumer of the triple rejects a suffix.
string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)" GIT_VERSION_NUMERIC_MATCH "${GIT_VERSION_FULL}")
if(NOT GIT_VERSION_NUMERIC_MATCH)
    # Not reachable from any input: every branch above either checked this same
    # pattern before assigning or assigned the constant. It stays as the guard
    # that keeps it that way — a future source of version strings that forgets
    # the check would otherwise leave the three components silently empty.
    message(FATAL_ERROR "Version string \"${GIT_VERSION_FULL}\" does not start with a MAJOR.MINOR.PATCH triple")
endif()
set(GIT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(GIT_VERSION_MINOR ${CMAKE_MATCH_2})
set(GIT_VERSION_PATCH ${CMAKE_MATCH_3})

unset(GIT_VERSION_NUMERIC_MATCH)
unset(GIT_VERSION_FILE)
unset(GIT_VERSION_FILE_TRIPLE)
unset(GIT_VERSION_TAG_TRIPLE)
unset(GIT_VERSION_SRC_DIR)
unset(GIT_VERSION_OWN_REPO)
unset(GIT_VERSION_TOPLEVEL)
unset(GIT_VERSION_TOPLEVEL_ERROR_CODE)
unset(GIT_VERSION_GIT_DIR)
unset(GIT_VERSION_GIT_DIR_ERROR_CODE)
unset(GIT_VERSION_REFS_DIR)
unset(GIT_VERSION_REFS_DIR_ERROR_CODE)
unset(GIT_DESCRIBE_VERSION)
unset(GIT_DESCRIBE_ERROR_CODE)

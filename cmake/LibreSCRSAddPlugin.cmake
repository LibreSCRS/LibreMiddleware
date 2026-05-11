# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# librescrs_add_plugin(<name>
#     MANIFEST <path-to-manifest.json>
#     SOURCES <src1> [<src2> ...]
#     [INCLUDE_DIRS <dir1> [<dir2> ...]]
#     [LINK_LIBRARIES <lib1> [<lib2> ...]]
#     [COMPILE_DEFINITIONS <def1> [<def2> ...]]
# )
#
# A5 (4.0 hardening). Wraps the previous boilerplate (add_library SHARED +
# LIBRESCRS_INTERNAL_BUILD define + LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR + the
# manifest.json -> manifest.h codegen). The generated header is placed at
#   ${CMAKE_CURRENT_BINARY_DIR}/generated/manifest.h
# and added to the target's PRIVATE include path. Plugin sources can
#   #include "manifest.h"
# and consume kPluginId, kDisplayName, kCapabilities, kPreReadAuth, kAtrs
# from the LibreSCRS::Plugin::generated::<id> namespace.
#
# A global CMake property LIBRESCRS_PLUGIN_MANIFESTS records every manifest
# path so downstream aggregators (manifests2plist for Apple Info.plist,
# manifests2desktop for KDE) can read them without re-parsing per-plugin
# sources.

function(librescrs_add_plugin name)
    set(options)
    set(oneValueArgs MANIFEST)
    set(multiValueArgs SOURCES INCLUDE_DIRS LINK_LIBRARIES COMPILE_DEFINITIONS)
    cmake_parse_arguments(LRS_PLUGIN "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN})

    if(NOT LRS_PLUGIN_MANIFEST)
        message(FATAL_ERROR "librescrs_add_plugin(${name}): MANIFEST is required")
    endif()
    if(NOT LRS_PLUGIN_SOURCES)
        message(FATAL_ERROR "librescrs_add_plugin(${name}): SOURCES is required")
    endif()
    if(NOT EXISTS "${LRS_PLUGIN_MANIFEST}")
        message(FATAL_ERROR "librescrs_add_plugin(${name}): manifest not found at ${LRS_PLUGIN_MANIFEST}")
    endif()

    # Codegen
    #
    # Use CMAKE_CURRENT_FUNCTION_LIST_DIR (CMake 3.17+) so the tool/schema
    # locations follow this .cmake module's residence, not the consuming
    # project's CMAKE_SOURCE_DIR. This is what makes LibreMiddleware build
    # correctly when consumed via FetchContent from LibreCelik (where
    # CMAKE_SOURCE_DIR points at LibreCelik, not LM).
    set(_lrs_lm_root "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/..")
    set(_generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")
    set(_generated_header "${_generated_dir}/manifest.h")
    set(_codegen_tool "${_lrs_lm_root}/tools/manifest2header/manifest2header.py")
    set(_schema "${_lrs_lm_root}/cmake/schemas/plugin-manifest.schema.json")
    file(MAKE_DIRECTORY "${_generated_dir}")

    add_custom_command(
        OUTPUT "${_generated_header}"
        COMMAND ${Python3_EXECUTABLE} "${_codegen_tool}"
                --input  "${LRS_PLUGIN_MANIFEST}"
                --output "${_generated_header}"
                --schema "${_schema}"
        DEPENDS "${LRS_PLUGIN_MANIFEST}" "${_codegen_tool}" "${_schema}"
        COMMENT "Generating ${_generated_header} from ${LRS_PLUGIN_MANIFEST}"
        VERBATIM
    )
    add_custom_target(${name}_manifest DEPENDS "${_generated_header}")

    # Library
    add_library(${name} SHARED ${LRS_PLUGIN_SOURCES})
    add_dependencies(${name} ${name}_manifest)
    target_compile_definitions(${name} PRIVATE LIBRESCRS_INTERNAL_BUILD)
    target_include_directories(${name} PRIVATE
        "${_generated_dir}"
        ${LRS_PLUGIN_INCLUDE_DIRS}
    )
    target_link_libraries(${name} PRIVATE
        CardPlugin_Impl
        ${LRS_PLUGIN_LINK_LIBRARIES}
    )
    if(LRS_PLUGIN_COMPILE_DEFINITIONS)
        target_compile_definitions(${name} PRIVATE ${LRS_PLUGIN_COMPILE_DEFINITIONS})
    endif()
    set_target_properties(${name} PROPERTIES
        PREFIX "lib"
        OUTPUT_NAME "${name}"
        LIBRARY_OUTPUT_DIRECTORY "${LIBREMIDDLEWARE_PLUGIN_OUTPUT_DIR}"
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN ON
    )

    # Restrict the plugin shared object's exported symbol set to the
    # three C entry points the host's CardPluginRegistry resolves via
    # dlsym (create_card_plugin / destroy_card_plugin /
    # card_plugin_abi_version). The visibility presets above hide
    # LibreSCRS-built static-archive symbols, but they do NOT hide
    # bundled OpenSSL or other PRIVATE-linked third-party static archives
    # whose own object files were compiled with default visibility. The
    # allowlist below covers both classes and makes the plugin's dynamic
    # export table exactly what the host contracts on, no more.
    #
    # Apple ld(1): -exported_symbols_list <file>  (bare-name list with `_`
    #                                              prefix per Apple convention)
    # GNU ld(1):   --version-script <file>        (version-tagged sections)
    if(APPLE)
        target_link_options(${name} PRIVATE
            "LINKER:-exported_symbols_list,${CMAKE_CURRENT_FUNCTION_LIST_DIR}/plugin-exports.list"
        )
    elseif(UNIX)
        target_link_options(${name} PRIVATE
            "LINKER:--version-script=${CMAKE_CURRENT_FUNCTION_LIST_DIR}/plugin-exports.map"
        )
    endif()

    # Track for downstream aggregation (e.g. a future manifests2plist tool).
    set_property(GLOBAL APPEND PROPERTY LIBRESCRS_PLUGIN_MANIFESTS "${LRS_PLUGIN_MANIFEST}")

    # Install rule for card plugins.
    #
    # Active only when LIBREMIDDLEWARE_BUILD_SHARED=ON, mirroring the public
    # LibreSCRS_*.so install rule. The plugin .so files land under
    # `${CMAKE_INSTALL_LIBDIR}/librescrs/plugins/` — a standard, predictable
    # path that distros and consumers can probe at runtime by:
    #
    #   1. honouring the LIBRESCRS_PLUGIN_PATH environment variable
    #      (intended override for development / per-user installs), or
    #   2. falling back to the install-tree convention
    #      ${CMAKE_INSTALL_FULL_LIBDIR}/librescrs/plugins/, or
    #   3. falling back to ${LIBREMIDDLEWARE_PLUGIN_DIR} (the build-tree
    #      cache var, for in-tree FetchContent consumers like LibreCelik).
    #
    # The contract is documented in docs/SHARED-LIBRARY-CONSUMERS.md.
    if(LIBREMIDDLEWARE_BUILD_SHARED)
        include(GNUInstallDirs)
        install(TARGETS ${name}
            LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}/librescrs/plugins
        )
        install(FILES ${LRS_PLUGIN_MANIFEST}
            DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/librescrs/plugins/${name}
        )
    endif()
endfunction()

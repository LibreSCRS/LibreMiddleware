# SPDX-License-Identifier: LGPL-2.1-or-later
# SPDX-FileCopyrightText: 2026 hirashix0

# embed_binary(VAR <cpp_symbol> INPUT <binary_file> OUTPUT <generated_cpp>)
#
# Generates a .cpp file defining:
#   const unsigned char <cpp_symbol>[];
#   const size_t        <cpp_symbol>Size;
# containing the byte contents of <binary_file>. Generated file is attached
# to the calling target's sources via target_sources() after this function
# returns; callers do the attachment themselves.
#
# Re-runs only when the input file changes.
function(embed_binary)
    cmake_parse_arguments(EB "" "VAR;INPUT;OUTPUT" "" ${ARGN})
    if(NOT EB_VAR OR NOT EB_INPUT OR NOT EB_OUTPUT)
        message(FATAL_ERROR "embed_binary: VAR, INPUT, OUTPUT all required")
    endif()
    add_custom_command(
        OUTPUT  "${EB_OUTPUT}"
        COMMAND ${CMAKE_COMMAND}
                -DIN_FILE=${EB_INPUT}
                -DOUT_FILE=${EB_OUTPUT}
                -DSYMBOL=${EB_VAR}
                -P ${CMAKE_CURRENT_FUNCTION_LIST_DIR}/EmbedBinaryRun.cmake
        DEPENDS "${EB_INPUT}"
                "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/EmbedBinaryRun.cmake"
        COMMENT "Embedding ${EB_INPUT} as C array ${EB_VAR}"
        VERBATIM
    )
endfunction()

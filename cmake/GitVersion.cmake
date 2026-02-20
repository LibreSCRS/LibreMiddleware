# GitVersion
#
# Version from git tag according to https://semver.org/
#
# GIT_VERSION_MAJOR         - Major version
# GIT_VERSION_MINOR         - Minor version
# GIT_VERSION_PATCH         - Patch version
# GIT_VERSION_COMMIT_NUM    - Commit number
# GIT_VERSION_COMMIT_SHA    - Hash

if(NOT DEFINED GIT_EXECUTABLE)
    find_package(Git QUIET REQUIRED)
endif()

if(GIT_EXECUTABLE)
  set(SRC_DIR "${CMAKE_SOURCE_DIR}") 

  execute_process(
    COMMAND ${GIT_EXECUTABLE} describe --tags --abbrev=0
    WORKING_DIRECTORY ${SRC_DIR}
    OUTPUT_VARIABLE GIT_DESCRIBE_VERSION
    RESULT_VARIABLE GIT_DESCRIBE_ERROR_CODE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if(NOT GIT_DESCRIBE_ERROR_CODE)
    set(PROJECT_VERSION ${GIT_DESCRIBE_VERSION})
  endif()
endif()

if(NOT DEFINED PROJECT_VERSION)
  set(PROJECT_VERSION 0.0.1)
  message(WARNING "Failed to determine PROJECT_VERSION from Git tags. Using default version \"${PROJECT_VERSION}\".")
endif()

string(REGEX MATCH "^([0-9]+)\\.([0-9]+)\\.([0-9]+)(-([0-9]+)-([a-z0-9]+))?" GITVERSIONDETECT_VERSION_MATCH ${PROJECT_VERSION})
set(GIT_VERSION_MAJOR ${CMAKE_MATCH_1})
set(GIT_VERSION_MINOR ${CMAKE_MATCH_2})
set(GIT_VERSION_PATCH ${CMAKE_MATCH_3})
set(GIT_VERSION_COMMIT_NUM ${CMAKE_MATCH_5})
set(GIT_VERSION_COMMIT_SHA ${CMAKE_MATCH_6})

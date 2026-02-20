# Find uuid
#
# UUID_FOUND        - system has uuid
# UUID_INCLUDE_DIRS - uuid include directories
# UUID_LIBRARIES    - libraries needed to use uuid
#
# and the following imported target
#
# UUID::UUID

# On Mac OS X the uuid functions are in the System library.
if(APPLE)
  set(UUID_LIBRARY_VAR System)
else()
  # Linux type:
  set(UUID_LIBRARY_VAR uuid)
endif()

find_package(PkgConfig)
pkg_check_modules(PC_UUID QUIET uuid)
set(UUID_VERSION ${PC_UUID_VERSION})

find_path(UUID_INCLUDE_DIR
  NAMES uuid.h
  HINTS ${UUID_ROOT} ${PC_UUID_INCLUDEDIR} ${PC_UUID_INCLUDE_DIRS}
  PATH_SUFFIXES include uuid)

find_library(UUID_LIBRARY
  NAMES ${UUID_LIBRARY_VAR}
  HINTS ${UUID_ROOT} ${PC_UUID_LIBDIR} ${PC_UUID_LIBRARY_DIRS}
  PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(UUID
  REQUIRED_VARS UUID_LIBRARY UUID_INCLUDE_DIR
  VERSION_VAR UUID_VERSION)

if (UUID_FOUND AND NOT TARGET UUID::UUID)
  mark_as_advanced(UUID_FOUND UUID_INCLUDE_DIR UUID_LIBRARY)
  add_library(UUID::UUID UNKNOWN IMPORTED GLOBAL)
  set_target_properties(UUID::UUID PROPERTIES
    IMPORTED_LOCATION "${UUID_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${UUID_INCLUDE_DIR}")
endif()

set(UUID_INCLUDE_DIRS ${UUID_INCLUDE_DIR})
set(UUID_LIBRARIES ${UUID_LIBRARY})
unset(UUID_INCLUDE_DIR)
unset(UUID_LIBRARY)

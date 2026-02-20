# Find pcsc
#
# PCSC_FOUND        - system has pcsc
# PCSC_INCLUDE_DIRS - pcsc include directories
# PCSC_LIBRARIES    - libraries needed to use pcsc
#
# and the following imported target
#
# PCSC::PCSC

find_package (PkgConfig)
pkg_check_modules(PC_PCSC libpcsclite)
set(PCSC_VERSION ${PC_PCSC_VERSION})

find_path(PCSC_INCLUDE_DIR
  NAMES WinSCard.h winscard.h
  HINTS ${PCSC_ROOT} ${PC_PCSC_INCLUDEDIR} ${PC_PCSC_INCLUDE_DIRS} ${PCSC_INCLUDE_DIRS}
  PATH_SUFFIXES include pcsc)

find_library(PCSC_LIBRARY
  NAMES PCSC libwinscard libpcsclite pcsclite
  HINTS ${PCSC_ROOT} ${PC_PCSC_LIBDIR} ${PC_PCSC_LIBRARY_DIRS}
  PATH_SUFFIXES ${CMAKE_INSTALL_LIBDIR})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(PCSC
  REQUIRED_VARS PCSC_LIBRARY PCSC_INCLUDE_DIR
  VERSION_VAR PCSC_VERSION)

if (PCSC_FOUND AND NOT TARGET PCSC::PCSC)
  mark_as_advanced(PCSC_FOUND PCSC_INCLUDE_DIR PCSC_LIBRARY)
  
  if(PCSC_LIBRARY MATCHES "/([^/]+)\\.framework$")
    add_library(PCSC::PCSC INTERFACE IMPORTED GLOBAL)
    set_target_properties(PCSC::PCSC PROPERTIES
      INTERFACE_LINK_LIBRARIES "${PCSC_LIBRARY}")
  else()
    add_library(PCSC::PCSC UNKNOWN IMPORTED GLOBAL)
    set_target_properties(PCSC::PCSC PROPERTIES
    IMPORTED_LOCATION "${PCSC_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${PCSC_INCLUDE_DIR}")
  endif()
endif()

set(PCSC_INCLUDE_DIRS ${PCSC_INCLUDE_DIR})
set(PCSC_LIBRARIES ${PCSC_LIBRARY})
unset(PCSC_INCLUDE_DIR)
unset(PCSC_LIBRARY)

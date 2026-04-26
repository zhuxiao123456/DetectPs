#----------------------------------------------------------------
# Generated CMake target import file for configuration "RelWithDebInfo".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "pcre2::pcre2-8-static" for configuration "RelWithDebInfo"
set_property(TARGET pcre2::pcre2-8-static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(pcre2::pcre2-8-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "C"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/pcre2-8-static.lib"
  )

list(APPEND _cmake_import_check_targets pcre2::pcre2-8-static )
list(APPEND _cmake_import_check_files_for_pcre2::pcre2-8-static "${_IMPORT_PREFIX}/lib/pcre2-8-static.lib" )

# Import target "pcre2::pcre2-posix-static" for configuration "RelWithDebInfo"
set_property(TARGET pcre2::pcre2-posix-static APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(pcre2::pcre2-posix-static PROPERTIES
  IMPORTED_LINK_INTERFACE_LANGUAGES_RELWITHDEBINFO "C"
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/lib/pcre2-posix-static.lib"
  )

list(APPEND _cmake_import_check_targets pcre2::pcre2-posix-static )
list(APPEND _cmake_import_check_files_for_pcre2::pcre2-posix-static "${_IMPORT_PREFIX}/lib/pcre2-posix-static.lib" )

# Import target "pcre2::pcre2grep" for configuration "RelWithDebInfo"
set_property(TARGET pcre2::pcre2grep APPEND PROPERTY IMPORTED_CONFIGURATIONS RELWITHDEBINFO)
set_target_properties(pcre2::pcre2grep PROPERTIES
  IMPORTED_LOCATION_RELWITHDEBINFO "${_IMPORT_PREFIX}/bin/pcre2grep.exe"
  )

list(APPEND _cmake_import_check_targets pcre2::pcre2grep )
list(APPEND _cmake_import_check_files_for_pcre2::pcre2grep "${_IMPORT_PREFIX}/bin/pcre2grep.exe" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)

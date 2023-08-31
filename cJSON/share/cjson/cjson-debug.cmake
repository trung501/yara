get_filename_component(VCPKG_IMPORT_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../../" ABSOLUTE)
#----------------------------------------------------------------
# Generated CMake target import file for configuration "Debug".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "cjson" for configuration "Debug"
set_property(TARGET cjson APPEND PROPERTY IMPORTED_CONFIGURATIONS DEBUG)
set_target_properties(cjson PROPERTIES
  IMPORTED_IMPLIB_DEBUG "${VCPKG_IMPORT_PREFIX}/debug/lib/cjson.lib"
  IMPORTED_LOCATION_DEBUG "${VCPKG_IMPORT_PREFIX}/debug/bin/cjson.dll"
  )

list(APPEND _cmake_import_check_targets cjson )
list(APPEND _cmake_import_check_files_for_cjson "${VCPKG_IMPORT_PREFIX}/debug/lib/cjson.lib" "${VCPKG_IMPORT_PREFIX}/debug/bin/cjson.dll" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)

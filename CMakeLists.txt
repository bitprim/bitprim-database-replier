cmake_minimum_required(VERSION 3.4)

# bitprim-database-replier
#==============================================================================
project(bitprim-database-replier
  VERSION 3.0.0
  LANGUAGES CXX C)
set_property(GLOBAL PROPERTY USE_FOLDERS ON)

# Check for baseline language coverage in the compiler for the C++11 standard.
#------------------------------------------------------------------------------
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Process options.data_base.hpp
#==============================================================================

# Implement --with-litecoin.
#------------------------------------------------------------------------------
option(WITH_LITECOIN "Compile with Litecoin support." OFF)
if (WITH_LITECOIN)
  add_definitions(-DLITECOIN)
endif()

# Implement --with-tests and declare WITH_TESTS.
#------------------------------------------------------------------------------
option(WITH_TESTS "Compile with unit tests." ON)

# Implement --with-tools and declare WITH_TOOLS.
#------------------------------------------------------------------------------
option(WITH_TOOLS "Compile with tools." ON)

# Inherit --enable-shared and define BOOST_TEST_DYN_LINK.
#------------------------------------------------------------------------------
option(ENABLE_SHARED "" OFF)



# Check dependencies.
#==============================================================================
# Require Boost of at least version 1.56.0 and output ${boost_CPPFLAGS/LDFLAGS}.
#------------------------------------------------------------------------------
if (NOT ENABLE_SHARED)
  set(Boost_USE_STATIC_LIBS ON)
endif()
find_package(
  Boost 1.56.0 REQUIRED
  COMPONENTS unit_test_framework)

## Require protobuf of at least version 3.0.0 and output ${protobuf_CPPFLAGS/LIBS/PKG}.
##------------------------------------------------------------------------------
#if (DEFINED Protobuf_ROOT_DIR)
#  set(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${Protobuf_ROOT_DIR})
#endif()
#find_package(Protobuf 3 REQUIRED)
#
## Require zmq of at least version 4.1.1 and output ${zmq_CPPFLAGS/LIBS/PKG}.
##------------------------------------------------------------------------------
#set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/cmake)
#find_package(ZeroMQ 4.1.1 REQUIRED)


## Require bitprim-database of at least version 3.0.0 and output ${bitprim_database_CPPFLAGS/LIBS/PKG}.
#------------------------------------------------------------------------------
if (NOT TARGET bitprim-database)
  find_package(bitprim-database 3.0.0 REQUIRED)
endif()

# Require bitprim-protocol of at least version 3.0.0 and output ${bitprim_protocol_CPPFLAGS/LIBS/PKG}.
#------------------------------------------------------------------------------
if (NOT TARGET bitprim-protocol)
  find_package(bitprim-protocol 3.0.0 REQUIRED)
endif()


## Require bitprim-core of at least version 3.0.0 and output ${bitprim_core_CPPFLAGS/LIBS/PKG}.
##------------------------------------------------------------------------------
#if (NOT TARGET bitprim-core)
#  find_package(bitprim-core 3.0.0 REQUIRED)
#endif()

# Require bitprim-network of at least version 3.0.0 and output ${bitprim_network_CPPFLAGS/LIBS/PKG}.
#------------------------------------------------------------------------------
if (NOT TARGET bitprim-network)
  find_package(bitprim-network 3.0.0 REQUIRED)
endif()



# Set flags.
#==============================================================================
include(CheckCXXCompilerFlag)

function(_add_c_compile_flag _Flag _Var)
  check_cxx_compiler_flag(${_Flag} ${_Var})
  if (${_Var})
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${_Flag}" )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_Flag}" )
  endif()
endfunction()

function(_add_cxx_compile_flag _Flag _Var)
  check_cxx_compiler_flag(${_Flag} ${_Var})
  if (${_Var})
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${_Flag}" )
  endif()
endfunction()

function(_add_link_flag _Flag _Var)
  check_cxx_compiler_flag(${_Flag} ${_Var})
  if (${_Var})
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${_Flag}" )
    set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} ${_Flag}" )
  endif()
endfunction()

# Warn on all stuff.
#------------------------------------------------------------------------------
if (NOT MSVC)
  _add_c_compile_flag(-Wall _has_all_warning_flag)
else()
  _add_c_compile_flag(-W4 _has_all_warning_flag)
  add_definitions(-D_SCL_SECURE_NO_WARNINGS)
endif()

# Warn on extra stuff.
#------------------------------------------------------------------------------
if (NOT MSVC)
  _add_c_compile_flag(-Wextra _has_extra_warning_flag)
endif()

# Be really annoying.
#------------------------------------------------------------------------------
_add_c_compile_flag(-Wpedantic _has_pedantic_warning_flag)
if (_has_pedantic_warning_flag)
  _add_c_compile_flag(-pedantic _has_pedantic_flag)
endif()

# Conform to style.
#------------------------------------------------------------------------------
_add_cxx_compile_flag(-Wno-missing-braces _has_no_missing_braces_warning_flag)

# Conflict in stdlib under clang. Enabled in clang only.
#------------------------------------------------------------------------------
_add_cxx_compile_flag(-Wno-mismatched-tags _has_no_mismatched_tags_warning_flag)

# Clean up boost 1.55 headers. Enabled in gcc only.
#------------------------------------------------------------------------------
_add_c_compile_flag(-Wno-deprecated-declarations _has_no_deprecated_declarations_warning_flag)

# Protect stack.
#------------------------------------------------------------------------------
_add_link_flag(-fstack-protector _has_stack_protector_flag)

# Protect stack comprehensively.
#------------------------------------------------------------------------------
_add_link_flag(-fstack-protector-all _has_stack_protector_all_flag)

# Hide internal functions from external libs. Enabled in gcc only.
#------------------------------------------------------------------------------
_add_cxx_compile_flag(-fvisibility-hidden _has_visibility_hidden_flag)

# Hide inlines from external libs. Enabled in gcc only.
#------------------------------------------------------------------------------
_add_cxx_compile_flag(-fvisibility-inlines-hidden _has_visibility_inlines_hidden_flag)

# Target Windows Vista. Enabled in msvc only.
#------------------------------------------------------------------------------
if (MSVC)
  add_definitions(-D_WIN32_WINNT=0x0600)
endif()

# Build
#==============================================================================
function(_group_sources target sources_dir)
  file(GLOB_RECURSE _headers
    ${sources_dir}/include/*.h ${sources_dir}/include/*.hpp)
  target_sources(${target} PRIVATE ${_headers})

  get_target_property(sources ${target} SOURCES)
  foreach (source ${sources})
    get_filename_component(group ${source} ABSOLUTE)
    get_filename_component(group ${group} DIRECTORY)
    file(RELATIVE_PATH group "${sources_dir}" "${group}")
    if (group)
      if (MSVC)
        string(REPLACE "/" "\\" group "${group}")
      endif()
      source_group("${group}" FILES "${source}")
    endif()
  endforeach()

  set_target_properties(${target} PROPERTIES FOLDER "database")
endfunction()

# # src/bitprim-database.la => ${libdir}
# #------------------------------------------------------------------------------
# set(MODE STATIC)
# if (ENABLE_SHARED)
#   set(MODE SHARED)
# endif()


# src/bitprim-database-replier => ${bindir}
#------------------------------------------------------------------------------
add_executable(bitprim-database-replier
  src/database_replier.cpp
  src/configuration.cpp
  src/main.cpp
  src/parser.cpp
  src/settings_replier.cpp)

target_include_directories(bitprim-database-replier PUBLIC
   $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
   $<INSTALL_INTERFACE:include>)


if (NOT MSVC)
  target_compile_definitions(bitprim-database-replier PUBLIC -DSYSCONFDIR=\"${SYSCONFDIR}\")
endif()

#target_link_libraries(bitprim-database-replier bitprim-protocol bitprim-database bitprim-core)
#target_link_libraries(bitprim-database-replier ${Protobuf_LIBRARY})
#target_link_libraries(bitprim-database-replier ${ZeroMQ_LIBRARIES})

target_link_libraries(bitprim-database-replier bitprim-protocol bitprim-database bitprim-network)

target_include_directories(bitprim-database-replier PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/replier/include)

_group_sources(bitprim-database-replier "${CMAKE_CURRENT_LIST_DIR}/replier")



# Tests
#==============================================================================
function(_add_tests target)
  if (ENABLE_SHARED)
    target_compile_definitions(${target} PRIVATE -DBOOST_TEST_DYN_LINK)
  endif()
  target_include_directories(${target} SYSTEM PUBLIC ${Boost_INCLUDE_DIR})
  target_link_libraries(${target} PUBLIC ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY})

  foreach (_test_name ${ARGN})
    add_test(
      NAME test.database.${_test_name}
      COMMAND ${target}
        --run_test=${_test_name}
        --show_progress=no
        --detect_memory_leak=0
        --report_level=no
        --build_info=yes)
  endforeach()
endfunction()

if (WITH_TESTS)
  enable_testing()
endif()

# local: test/bitprim_database_test
#------------------------------------------------------------------------------
# if (WITH_TESTS)
#     add_executable(bitprim_database_test
#         test/block_database.cpp
#         test/data_base.cpp
#         test/hash_table.cpp
#         test/history_database.cpp
#         test/main.cpp
#         test/spend_database.cpp
#         test/structure.cpp
#         test/transaction_database.cpp
# #        test/unspent_database.cpp
#     )
# 
#   target_link_libraries(bitprim_database_test PUBLIC bitprim-database)
#   _group_sources(bitprim_database_test "${CMAKE_CURRENT_LIST_DIR}/test")
# 
#   _add_tests(bitprim_database_test
#     database_tests
#     hash_table_tests
#     structure_tests
#     data_base_tests)
# endif()




# Install
#==============================================================================

install(TARGETS bitprim-database-replier
  EXPORT bitprim-database-replier
  ARCHIVE DESTINATION lib
  RUNTIME DESTINATION bin)


set(_bitprim_headers
    # bitcoin/database/data_base.hpp
)

foreach (_header ${_bitprim_headers})
  get_filename_component(_directory "${_header}" DIRECTORY)
  install(FILES "include/${_header}" DESTINATION "include/${_directory}")
endforeach()



# Export
#==============================================================================
include(CMakePackageConfigHelpers)

if (UNIX)
  set(_config_package_location "lib/cmake")
elseif (WIN32)
  set(_config_package_location "cmake")
endif()

configure_file(bitprim-database-replierConfig.cmake.in
  "${CMAKE_CURRENT_BINARY_DIR}/bitprim-database-replierConfig.cmake"
  @ONLY)

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/bitprim-database-replierConfigVersion.cmake"
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY AnyNewerVersion)

install(
  FILES
    "${CMAKE_CURRENT_BINARY_DIR}/bitprim-database-replierConfig.cmake"
    "${CMAKE_CURRENT_BINARY_DIR}/bitprim-database-replierConfigVersion.cmake"
  DESTINATION ${_config_package_location})

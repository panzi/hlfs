cmake_minimum_required(VERSION 2.8)

project(hlfs)

# ---- dependencies -----------------------------------------------------------
find_package(Boost COMPONENTS system filesystem REQUIRED)

find_package(PkgConfig)
pkg_check_modules(HLLIB HLLib REQUIRED)
pkg_check_modules(FUSE fuse REQUIRED)

find_path(XATTR_INCLUDE_DIR attr/xattr.h)

if(XATTR_INCLUDE_DIR)
	message(STATUS "Found attr/xattr.h")
else()
	message(FATAL_ERROR "Could not find attr/xattr.h")
endif()

# ---- compiler flags ---------------------------------------------------------
if(MSVC)
	# Force to always compile with W4
	if(CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
		string(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
	else()
		set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
	endif()
elseif(CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++0x -Wall -Wextra -pedantic -Werror -O3")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=c99 -Wall -Wextra -pedantic -Werror -O3")
endif()

if(FUSE_VERSION VERSION_LESS 2.9)
	add_definitions("-DFUSE_USE_VERSION=26")
else()
	add_definitions("-DFUSE_USE_VERSION=29")
endif()

add_definitions(${FUSE_CFLAGS_OTHER})
include_directories(${HLLIB_INCLUDE_DIRS} ${XATTR_INCLUDE_DIR})

# ---- build targets ----------------------------------------------------------
add_subdirectory(src)

# ---- uninstall target -------------------------------------------------------
configure_file(
	"${CMAKE_CURRENT_SOURCE_DIR}/cmake_uninstall.cmake.in"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake"
	IMMEDIATE @ONLY)

add_custom_target(uninstall
	COMMAND ${CMAKE_COMMAND} -P "${CMAKE_CURRENT_BINARY_DIR}/cmake_uninstall.cmake")

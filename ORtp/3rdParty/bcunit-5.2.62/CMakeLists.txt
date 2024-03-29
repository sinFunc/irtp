############################################################################
# CMakeLists.txt
# Copyright (C) 2010-2021 Belledonne Communications, Grenoble France
#
############################################################################
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
############################################################################

cmake_minimum_required(VERSION 3.1)

# CMP0077 policy is required by Flexisip build. Remove it once the CMake required
# version is higer or equal to 3.13.
if(NOT CMAKE_VERSION VERSION_LESS 3.13)
	cmake_policy(SET CMP0077 NEW)
endif()

project(BCunit C)

set(PACKAGE "BCUnit")
set(PACKAGE_NAME "${PACKAGE}")
set(PROJECT_VERSION_MAJOR 3)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 2)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}")
set(VERSION "${PROJECT_VERSION}")
set(RELEASE "${PROJECT_VERSION_PATCH}")
set(PACKAGE_VERSION "${VERSION}-${RELEASE}")
set(PACKAGE_STRING "${PACKAGE_NAME} ${PACKAGE_VERSION}")
set(PACKAGE_BUGREPORT "")
set(PACKAGE_TARNAME "bcunit")
set(PACKAGE_URL "")


option(ENABLE_SHARED "Build shared library." NO)
option(ENABLE_STATIC "Build static library." YES)

option(ENABLE_AUTOMATED "Compile BCUnit automated interface" ON)
option(ENABLE_BASIC "Compile BCUnit basic interface" ON)
option(ENABLE_CONSOLE "Compile BCUnit console interface" ON)
option(ENABLE_CURSES "Compile BCUnit curses interface" OFF)
option(ENABLE_DOC "Install BCUnit documentation" OFF)
option(ENABLE_EXAMPLES "Compile BCUnit example programs" OFF)
option(ENABLE_TEST "Compile BCUnit internal test program" OFF)
option(ENABLE_MEMTRACE "Enable BCUnit internal memory tracking" OFF)
option(ENABLE_DEPRECATED "Enable use of deprecated v1.1 names" OFF)

set(CMAKE_REQUIRED_FLAGS "${CMAKE_C_FLAGS_${CMAKE_BUILD_TYPE}}")
set(CMAKE_REQUIRED_LINK_OPTIONS "${CMAKE_EXE_LINKER_FLAGS_${CMAKE_BUILD_TYPE}}")

include(GNUInstallDirs)

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/config.h)


set(exec_prefix ${CMAKE_INSTALL_BINDIR})
set(libdir ${CMAKE_INSTALL_LIBDIR})
set(includedir ${CMAKE_INSTALL_INCLUDEDIR})
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/bcunit.pc.in ${CMAKE_CURRENT_BINARY_DIR}/bcunit.pc)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/bcunit.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)


if(MSVC)
	add_definitions("/W3")
else()
	add_definitions("-Wall -W -pedantic -Wshadow -ansi -std=c99")
endif()

if(ENABLE_MEMTRACE)
	add_definitions(-DMEMTRACE)
endif()
if(ENABLE_DEPRECATED)
	add_definitions(-DUSE_DEPRECATED_BCUNIT_NAMES)
endif()
if(ENABLE_CURSES)
	set(CURSES_NEED_NCURSES 1)
	find_package(Curses)
	if(NOT CURSES_FOUND)
		message("Disabling curses as it has not been found!")
		set(ENABLE_CURSES 0)
	endif()
endif()

add_subdirectory(build)

include_directories(
 	${CMAKE_CURRENT_BINARY_DIR}
)

add_subdirectory(BCUnit)
if(ENABLE_DOC)
	add_subdirectory(doc)
	add_subdirectory(Man)
endif()
add_subdirectory(Share)
if(ENABLE_EXAMPLES)
	add_subdirectory(Examples)
endif()


include(CMakePackageConfigHelpers)
set(CONFIG_PACKAGE_LOCATION "${CMAKE_INSTALL_DATADIR}/${PROJECT_NAME}/cmake")
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/BcUnitConfigVersion.cmake"
	VERSION ${PACKAGE_VERSION}
	COMPATIBILITY AnyNewerVersion
)
export(EXPORT BcUnitTargets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/BcUnitTargets.cmake"
)

configure_package_config_file(BcUnitConfig.cmake.in
	"${CMAKE_CURRENT_BINARY_DIR}/BcUnitConfig.cmake"
  	INSTALL_DESTINATION ${CONFIG_PACKAGE_LOCATION}
	NO_SET_AND_CHECK_MACRO
)

install(EXPORT BcUnitTargets
	FILE BcUnitTargets.cmake
	DESTINATION ${CONFIG_PACKAGE_LOCATION}
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/BcUnitConfig.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/BcUnitConfigVersion.cmake"
	DESTINATION ${CONFIG_PACKAGE_LOCATION}
)

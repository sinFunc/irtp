############################################################################
# Copyright (c) 2010-2022 Belledonne Communications SARL.
#
# This file is part of oRTP 
# (see https://gitlab.linphone.org/BC/public/ortp).
#
############################################################################
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
############################################################################

cmake_minimum_required(VERSION 3.1)

set(ORTP_MAJOR_VERSION 5)
set(ORTP_MINOR_VERSION 2)
set(ORTP_MICRO_VERSION 64)
set(ORTP_VERSION 5.2.64)
set(ORTP_SO_VERSION "15") # incremented for 4.4.0 version.

include(CheckIncludeFile)
include(CheckFunctionExists)
include(GNUInstallDirs)
include(CheckCSourceCompiles)
include(CheckCXXSourceCompiles)
include(CheckSymbolExists)

find_package(Threads)
find_library(LIBM NAMES m)

if(NOT DISABLE_BC_PACKAGE_SEARCH)
	message(STATUS "Find_package(bctoolbox 0.2.0 REQUIRED)")
	find_package(bctoolbox 0.2.0 REQUIRED)
endif()

check_include_file(sys/uio.h HAVE_SYS_UIO_H)
check_include_file(sys/audio.h HAVE_SYS_AUDIO_H)
if(NOT ANDROID)
	message(STATUS "check_include_file(sys/shm.h HAVE_SYS_SHM_H)")
	check_include_file(sys/shm.h HAVE_SYS_SHM_H)
endif()

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")# need this for check_cxx_source_compiles because CMAKE_CXX_STANDARD doesn't work.
check_cxx_source_compiles("#include <atomic>
using namespace std;
int main(int argc, char *argv[]) {
atomic_int current_ref;
atomic_init(&current_ref, 1);
atomic_int previous_ref(atomic_fetch_sub_explicit(&current_ref, 1, memory_order_release));
return 0;
}"
	HAVE_ATOMIC)
if(NOT HAVE_ATOMIC)
	message(FATAL_ERROR "Atomic(C++) libraries have not been found for ORTP.")
endif()

check_function_exists(arc4random HAVE_ARC4RANDOM)
check_symbol_exists(recvmsg "sys/socket.h" HAVE_RECVMSG)
check_symbol_exists(sendmsg "sys/socket.h" HAVE_SENDMSG)

include(TestBigEndian)
test_big_endian(WORDS_BIGENDIAN)
if(WORDS_BIGENDIAN)
	set(ORTP_BIGENDIAN 1)
endif()

#message(STATUS "CMAKE_CURRENT_SOURCE_DIR=${CMAKE_CURRENT_BINARY_DIR}")
set(ORTP_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/include ${CMAKE_CURRENT_SOURCE_DIR}/src ${CMAKE_CURRENT_BINARY_DIR})
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
#include_directories(${CMAKE_CURRENT_SOURCE_DIR}/src)
#include_directories(${CMAKE_CURRENT_BINARY_DIR}) #cmake build dir


set(POSIXTIMER_INTERVAL 10000)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/ortp-config.h.cmake ${CMAKE_CURRENT_BINARY_DIR}/ortp-config.h)#make header file
set_source_files_properties(${CMAKE_CURRENT_BINARY_DIR}/ortp-config.h PROPERTIES GENERATED ON)#tell cmake header file is build
##add_definitions(-DHAVE_CONFIG_H)


add_subdirectory(include) #import header file

#--------------------------------SOURCE---------------------------------
set(SRC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/src)

set(ORTP_SOURCE_FILES_C
		${SRC_DIR}/avprofile.c
		${SRC_DIR}/b64.c
		${SRC_DIR}/congestiondetector.c
		${SRC_DIR}/event.c
		${SRC_DIR}/extremum.c
		${SRC_DIR}/fecstream.c
		${SRC_DIR}/jitterctl.c
		${SRC_DIR}/kalmanrls.c
		${SRC_DIR}/logging.c
		${SRC_DIR}/nack.c
		${SRC_DIR}/netsim.c
		${SRC_DIR}/ortp.c
		${SRC_DIR}/payloadtype.c
		${SRC_DIR}/port.c
		${SRC_DIR}/posixtimer.c
		${SRC_DIR}/rtcp.c
		${SRC_DIR}/rtcp_fb.c
		${SRC_DIR}/rtcp_xr.c
		${SRC_DIR}/rtcpparse.c
		${SRC_DIR}/rtpaudiolevel.c
		${SRC_DIR}/rtpframemarking.c
		${SRC_DIR}/rtpparse.c
		${SRC_DIR}/rtpprofile.c
		${SRC_DIR}/rtpsession.c
		${SRC_DIR}/rtpsession_inet.c
		${SRC_DIR}/rtpsignaltable.c
		${SRC_DIR}/rtptimer.c
		${SRC_DIR}/scheduler.c
		${SRC_DIR}/sessionset.c
		${SRC_DIR}/str_utils.c
		${SRC_DIR}/telephonyevents.c
		${SRC_DIR}/videobandwidthestimator.c
		${SRC_DIR}/utils.c
		)
set(ORTP_SOURCE_FILES_CXX
		${SRC_DIR}/dblk.cc	#HAVE_ATOMIC is mandatory
		${SRC_DIR}/rtpbundle.cc
		)

add_definitions(
		-DBCTBX_LOG_DOMAIN="ortp"
)

set(ORTP_SRCS ${ORTP_SOURCE_FILES_C} ${ORTP_SOURCE_FILES_CXX})
set(ORTP_SRCS ${ORTP_SRCS} PARENT_SCOPE) #make parent cmake can visit

set(ORTP_HEADERS ${ORTP_HEADERS} PARENT_SCOPE)









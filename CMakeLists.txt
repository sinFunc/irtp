cmake_minimum_required(VERSION 3.19)
project(IRtp)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread")
set(CMAKE_LIBRARY_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -Wl,--no-as-needed")
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

option(LIB_MODE "build a library" ON)
option(ENABLE_TESTER "run tester" ON)

message(STATUS "INSTALL_INCLUDE_DIR=${CMAKE_INSTALL_INCLUDEDIR}")

#-------------------------compile ortp---------------------------
find_package(BcUnit QUIET)
if(NOT BcUnit_FOUND)
    message(STATUS "compiling bcuint static lib")
    set(SHELL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/ORtp/script/build_bcuint.sh")
    execute_process(
            COMMAND bash "${SHELL_PATH}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/ORtp/3rdParty/bcunit-5.2.62"
            RESULT_VARIABLE result
            OUTPUT_VARIABLE output
    )
    if(result EQUAL 0)
        message(STATUS "Executive ${SHELL_PATH} successfully.output=${output}")
    else()
        message(STATUS "Executive ${SHELL_PATH} unsuccessfully.output=${output},result=${result}")
    endif()
endif()


find_package(MbedTLS QUIET)
if(NOT MbedTLS_FOUND)
    message(STATUS "compiling MbedTLS static lib")
    set(SHELL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/ORtp/script/build_mbedtls.sh")
    execute_process(
            COMMAND bash "${SHELL_PATH}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/ORtp/3rdParty/mbedtls-2.28.3"
            RESULT_VARIABLE result
            OUTPUT_VARIABLE output
    )
    if(result EQUAL 0)
        message(STATUS "Executive ${SHELL_PATH} successfully.output=${output}")
    else()
        message(STATUS "Executive ${SHELL_PATH} unsuccessfully.output=${output},result=${result}")
    endif()
endif()

find_package(bctoolbox QUIET)
if(NOT bctoolbox_FOUND)
    message(STATUS "compiling bctoolbox static lib")
    set(SHELL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/ORtp/script/build_bctoolbox.sh")
    execute_process(
            COMMAND bash "${SHELL_PATH}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/ORtp/3rdParty/bctoolbox-5.2.64"
            RESULT_VARIABLE result
            OUTPUT_VARIABLE output
    )
    if(result EQUAL 0)
        message(STATUS "Executive ${SHELL_PATH} successfully.output=${output}")
    else()
        message(STATUS "Executive ${SHELL_PATH} unsuccessfully.output=${output},result=${result}")
    endif()
endif()

set(ORTP ORtp)
add_subdirectory(${ORTP})
add_definitions(-DHAVE_CONFIG_H)
include_directories(${ORTP_HEADERS})


#--------------------IRtp-------------------------
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/irtp)
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/irtp IRTP_SRCS)

#----------------------------compile jrtplib--------------------------------
find_package(JThread QUIET)
if(NOT JThread_FOUND)
    message(STATUS "compiling jthread static lib")
    set(SHELL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/JRtplib/script/build_jthread.sh")
    execute_process(
            COMMAND bash "${SHELL_PATH}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/JRtplib/JThread-1.3.3"
            RESULT_VARIABLE result
            OUTPUT_VARIABLE output
    )
    if(result EQUAL 0)
        message(STATUS "Executive ${SHELL_PATH} successfully.output=${output}")
    else()
        message(STATUS "Executive ${SHELL_PATH} unsuccessfully.output=${output},result=${result}")
    endif()
endif()

find_package(JRTPLIB QUIET)
if(NOT JRTPLIB_FOUND)
    message(STATUS "compiling jrtplib static lib")
    set(SHELL_PATH "${CMAKE_CURRENT_SOURCE_DIR}/JRtplib/script/build_jrtplib.sh")
    execute_process(
            COMMAND bash "${SHELL_PATH}"
            WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/JRtplib/JRTPLIB-3.11.2"
            RESULT_VARIABLE result
            OUTPUT_VARIABLE output
    )
    if(result EQUAL 0)
        message(STATUS "Executive ${SHELL_PATH} successfully.output=${output}")
    else()
        message(STATUS "Executive ${SHELL_PATH} unsuccessfully.output=${output},result=${result}")
    endif()
endif()


set(JRTP_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/JRtplib/JRTPLIB-3.11.2/src)
include_directories(${JRTP_INCLUDE_DIR})


set(ALL_SRCS ${IRTP_SRCS} ${ORTP_SRCS})
#SET(CMAKE_POSITION_INDEPENDENT_CODE ON)


function(run_tester)
    MESSAGE(STATUS "run_tester")
    add_library(irtp_a STATIC IMPORTED GLOBAL)
    set_target_properties(irtp_a PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/libIRtp-static.a")
    set(IRTP_LIBS irtp_a)

    add_executable(${CMAKE_PROJECT_NAME} main.cpp)
    target_link_libraries(${CMAKE_PROJECT_NAME}  PUBLIC ${IRTP_LIBS})
#    target_link_libraries(${CMAKE_PROJECT_NAME}  PUBLIC bcunit  mbedtls bctoolbox)
#    target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC jrtp jthread)
    add_dependencies(${CMAKE_PROJECT_NAME} ${IRTP_PUBLIC_TARGET})
endfunction(run_tester)


if(LIB_MODE)
    MESSAGE(STATUS "enable lib mode")
    set(IRTP_PUBLIC_TARGET "IRtp-static")
    set(IRTP_PRIVATE_TARGET "temp_IRtp-static")
    add_library(${IRTP_PRIVATE_TARGET} STATIC ${ALL_SRCS})
    set_target_properties(${IRTP_PRIVATE_TARGET} PROPERTIES OUTPUT_NAME ${IRTP_PRIVATE_TARGET})
#    #    set_target_properties(${LIB_TARGET} PROPERTIES CLEAN_DIRECT_OUTPUT 1)
#    #    set_target_properties(${LIB_TARGET} PROPERTIES VERSION 1.0)
    set_target_properties(${IRTP_PRIVATE_TARGET} PROPERTIES IMPORTED TRUE INTERFACE_LINK_LIBRARIES "")
    set_target_properties(${IRTP_PRIVATE_TARGET} PROPERTIES POSITION_INDEPENDENT_CODE ON)
#    target_link_libraries(${LIB_TARGET} PRIVATE bcunit  mbedtls bctoolbox)
#    target_link_libraries(${LIB_TARGET}  PRIVATE jrtp jthread)


    #-------------------------get lib whole path-----------------------
    find_library(BCUNIT_LIBRARY NAMES bcunit)
    if(NOT BCUNIT_LIBRARY)
        message(FATAL_ERROR "it can not find bcunit lib")
    else()
        message(STATUS "found ${BCUNIT_LIBRARY}")
    endif()

    find_library(MBEDTLS_LIBRARY NAMES mbedtls)
    if(NOT MBEDTLS_LIBRARY)
        message(FATAL_ERROR "it can not find mbedtls lib")
        else()
        message(STATUS "found ${MBEDTLS_LIBRARY}")
    endif()

    find_library(BCTOOLBOX_LIBRARY NAMES bctoolbox)
    if(NOT BCTOOLBOX_LIBRARY)
        message(FATAL_ERROR "it can not find bctoolbox lib ")
    else()
        message(STATUS "found ${BCTOOLBOX_LIBRARY}")
    endif()

    find_library(JTHREAD_LIBRARY NAMES jthread)
    if(NOT JTHREAD_LIBRARY)
        message(FATAL_ERROR "it can not jthread lib")
    else()
        message(STATUS "found ${JTHREAD_LIBRARY}")
    endif()

    find_library(JRTP_LIBRARY NAMES jrtp)
    if(NOT JRTP_LIBRARY)
        message(FATAL_ERROR "it can not jrtp lib")
    else()
        message(STATUS "found ${JRTP_LIBRARY}")
    endif()


    add_library(bcunit_static STATIC IMPORTED GLOBAL)
    set_target_properties(bcunit_static PROPERTIES IMPORTED_LOCATION "${BCUNIT_LIBRARY}")

    add_library(mbedtls_static STATIC IMPORTED GLOBAL)
    set_target_properties(mbedtls_static PROPERTIES IMPORTED_LOCATION "${MBEDTLS_LIBRARY}")

    add_library(bctoolbox_static STATIC IMPORTED GLOBAL)
    set_target_properties(bctoolbox_static PROPERTIES IMPORTED_LOCATION "${BCTOOLBOX_LIBRARY}")

    add_library(jrtp_static STATIC IMPORTED GLOBAL)
    set_target_properties(jrtp_static PROPERTIES IMPORTED_LOCATION "${JRTP_LIBRARY}")

    add_library(jthread_static STATIC IMPORTED GLOBAL)
    set_target_properties(jthread_static PROPERTIES IMPORTED_LOCATION "${JTHREAD_LIBRARY}")

    add_custom_target(${IRTP_PUBLIC_TARGET} ALL DEPENDS lib${IRTP_PUBLIC_TARGET}.a)
    set_target_properties(${IRTP_PUBLIC_TARGET} PROPERTIES POSITION_INDEPENDENT_CODE ON)

    add_custom_command(
            OUTPUT lib${IRTP_PUBLIC_TARGET}.a
            COMMAND ar crsT lib${IRTP_PUBLIC_TARGET}.a $<TARGET_FILE:bcunit_static> $<TARGET_FILE:mbedtls_static>
            $<TARGET_FILE:bctoolbox_static> $<TARGET_FILE:${IRTP_PRIVATE_TARGET}> $<TARGET_FILE:jrtp_static>
            $<TARGET_FILE:jthread_static>
            DEPENDS bcunit_static mbedtls_static bctoolbox_static ${IRTP_PRIVATE_TARGET} jrtp_static jthread_static
    )
    
    IF(ENABLE_TESTER)
        run_tester()
    ENDIF()
ELSE()
    MESSAGE(STATUS "enable executive mode")
    add_executable(${CMAKE_PROJECT_NAME} main.cpp ${ALL_SRCS})
    target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC bcunit  mbedtls bctoolbox)
    target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC jrtp jthread)
ENDIF()

#add_dependencies(IRtp ${ORTP})
cmake_minimum_required(VERSION 3.19)
project(IRtp)

set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -pthread")

option(LIB_MODE "build a library" OFF)
option(ENABLE_TESTER "run tester" ON)


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
SET(CMAKE_POSITION_INDEPENDENT_CODE ON)


function(run_tester)
    add_library(irtp_a STATIC IMPORTED)
    set_target_properties(irtp_a PROPERTIES IMPORTED_LOCATION "${CMAKE_CURRENT_BINARY_DIR}/libIRtp-static.a")
    set(IRTP_LIBS irtp_a)

    add_executable(${CMAKE_PROJECT_NAME} main.cpp)
    target_link_libraries(${CMAKE_PROJECT_NAME}  PUBLIC ${IRTP_LIBS})
    target_link_libraries(${CMAKE_PROJECT_NAME}  PUBLIC bcunit  mbedtls bctoolbox)
    target_link_libraries(${CMAKE_PROJECT_NAME} PUBLIC jrtp jthread)
    add_dependencies(${CMAKE_PROJECT_NAME} ${LIB_TARGET})
endfunction(run_tester)


if(LIB_MODE)
    MESSAGE(STATUS "enable lib mode")
    set(LIB_TARGET "IRtp-static")
    add_library(${LIB_TARGET} STATIC ${ALL_SRCS})
    set_target_properties(${LIB_TARGET} PROPERTIES OUTPUT_NAME ${LIB_TARGET})
    #    set_target_properties(${LIB_TARGET} PROPERTIES CLEAN_DIRECT_OUTPUT 1)
    #    set_target_properties(${LIB_TARGET} PROPERTIES VERSION 1.0)
    set_target_properties(${LIB_TARGET} PROPERTIES IMPORTED TRUE INTERFACE_LINK_LIBRARIES "")
    target_link_libraries(${LIB_TARGET} PRIVATE bcunit  mbedtls bctoolbox)
    target_link_libraries(${LIB_TARGET}  PRIVATE jrtp jthread)

#    add_dependencies(${LIB_TARGET} bcunit  mbedtls bctoolbox)
#    add_custom_command(
#            TARGET ${LIB_TARGET}
#            POST_BUILD
#            COMMAND ${CMAKE_AR} -x libbcunit.a
#            COMMAND ${CMAKE_AR} -x libmbedtls.a
#            COMMAND ${CMAKE_AR} -x libbctoolbox.a
#            COMMAND ${CMAKE_AR} -rcs $<TARGET_FILE:${LIB_TARGET}> $<TARGET_OBJECTS:bcunit> $<TARGET_OBJECTS:mbedtls> $<TARGET_OBJECTS:bctoolbox>
#    )
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
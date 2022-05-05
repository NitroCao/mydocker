cmake_minimum_required(VERSION 3.0)

project(mydocker)

set(CMAKE_CXX_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

find_package(CLI11 CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h"
)
include_directories("${CMAKE_CURRENT_BINARY_DIR}")


enable_testing()

option(ENABLE_TESTS "Build tests")
if(ENABLE_TESTS)
    add_subdirectory(tests)
endif()

add_subdirectory(src)

cmake_minimum_required(VERSION 3.0)

project(mydocker)

set(CMAKE_CXX_STANDARD 11)
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

find_package(CLI11 CONFIG REQUIRED)

add_subdirectory(src)

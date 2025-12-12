cmake_minimum_required(VERSION 3.10)
project(az_lib_snmp CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS_DEBUG "-g")

add_subdirectory(examples)

add_subdirectory(tests)

# Copyright (c) 2023 The MITRE Corporation.
# ALL RIGHTS RESERVED. This copyright notice must
# not be removed from this software, absent MITRE's
# express written permission.

cmake_minimum_required(VERSION 3.10)

# Project name and version
project(SysmonXMLToILF VERSION 1.0)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# # Compiler flags
# if(MSVC)
#     add_compile_options(/W4 /WX /std:c++17 /wd4100)
# else()
#     add_compile_options(-Wall -Wextra -g -std=c++17 -O2 -Wno-unused-parameter)
# endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/pugixml-1.14)
include_directories(${CMAKE_SOURCE_DIR}/libilf/ILF)

# Source files
set(SRC_DIR ${CMAKE_SOURCE_DIR}/src)
set(LIB_DIR ${CMAKE_SOURCE_DIR}/lib)

set(SOURCES
    ${SRC_DIR}/main.cpp
    ${SRC_DIR}/xml_translator.cpp
    ${LIB_DIR}/pugixml-1.14/pugixml.cpp
    ${LIB_DIR}/libilf/ILF/ILF.cpp
)



# Add executable
add_executable(main ${SOURCES})

find_package(redis++ REQUIRED)
target_link_libraries(main PRIVATE redis++::redis++)

# Add pthread for all systems, including Windows
find_package(Threads REQUIRED)
target_link_libraries(main PRIVATE Threads::Threads)

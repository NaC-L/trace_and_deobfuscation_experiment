cmake_minimum_required(VERSION 3.12)
project(TAD-E)
set(CMAKE_CXX_STANDARD 11)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(SOURCES
    TAD-E/TAD.cpp
    TAD-E/TaintEngine.cpp
    TAD-E/RegisterStuff.cpp
)

set(HEADERS
    TAD-E/RegisterStuff.h
    TAD-E/Includes.h
)

set(EXECUTABLE_NAME TAD-E)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_executable(${EXECUTABLE_NAME} ${SOURCES} ${HEADERS})
target_include_directories(${EXECUTABLE_NAME} PRIVATE include)

include(FetchContent)

# Zydis
FetchContent_Declare(
    Zydis
    GIT_REPOSITORY https://github.com/zyantific/zydis.git
    GIT_TAG master
)
FetchContent_GetProperties(Zydis)
if(NOT Zydis_POPULATED)
    FetchContent_Populate(Zydis)
    add_subdirectory(${zydis_SOURCE_DIR} ${zydis_BINARY_DIR})
endif()

# Unicorn
FetchContent_Declare(
    Unicorn
    GIT_REPOSITORY https://github.com/unicorn-engine/unicorn.git
    GIT_TAG master
)
FetchContent_GetProperties(Unicorn)
if(NOT Unicorn_POPULATED)
    FetchContent_Populate(Unicorn)
    add_subdirectory(${unicorn_SOURCE_DIR} ${unicorn_BINARY_DIR})
endif()

# LIEF
FetchContent_Declare(
    LIEF
    GIT_REPOSITORY https://github.com/lief-project/LIEF.git
    GIT_TAG master
)
FetchContent_GetProperties(LIEF)
if(NOT LIEF_POPULATED)
    FetchContent_Populate(LIEF)
    add_subdirectory(${lief_SOURCE_DIR} ${lief_BINARY_DIR})
endif()
# ...

# After defining your targets
add_custom_command(TARGET ${EXECUTABLE_NAME} PRE_BUILD
                   COMMAND ${CMAKE_COMMAND} -E copy_directory
                   ${lief_BINARY_DIR}/include ${lief_SOURCE_DIR}/include)

# Link Libraries
target_include_directories(${EXECUTABLE_NAME} PRIVATE ${lief_SOURCE_DIR}/include)

target_include_directories(${EXECUTABLE_NAME} PRIVATE ${lief_SOURCE_DIR}/include/LIEF)

target_include_directories(${EXECUTABLE_NAME} PRIVATE ${lief_BUILD_DIR}/include/LIEF)

target_link_libraries(${EXECUTABLE_NAME} Zydis)
target_link_libraries(${EXECUTABLE_NAME} unicorn)
target_link_libraries(${EXECUTABLE_NAME} "_deps/lief-build/Release/LIEF")  # Absolute path to the LIEF.lib

add_dependencies(${EXECUTABLE_NAME} LIB_LIEF unicorn Zydis)

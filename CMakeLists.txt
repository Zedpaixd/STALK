cmake_minimum_required(VERSION 3.16)
project(edr LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBBPF REQUIRED libbpf)

set(FTXUI_DIR ${CMAKE_SOURCE_DIR}/external/ftxui)
if(NOT EXISTS ${FTXUI_DIR}/CMakeLists.txt)
    message(FATAL_ERROR "FTXUI not present at ${FTXUI_DIR}; run setup.sh first")
endif()
set(FTXUI_BUILD_EXAMPLES OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_DOCS OFF CACHE BOOL "" FORCE)
set(FTXUI_BUILD_TESTS OFF CACHE BOOL "" FORCE)
add_subdirectory(${FTXUI_DIR} ${CMAKE_BINARY_DIR}/ftxui EXCLUDE_FROM_ALL)

add_executable(edr
    src/main.cpp
    src/math_engine.cpp
    src/tracker.cpp
    src/ui.cpp
    src/ui_repman.cpp
    src/reputation.cpp
    src/sha256.cpp
    src/keymap.cpp
    src/seccomp_filter.cpp
    src/seccomp_supervisor.cpp
    src/hasher.cpp
)

target_include_directories(edr PRIVATE
    ${CMAKE_SOURCE_DIR}/include
    ${CMAKE_SOURCE_DIR}/src
    ${LIBBPF_INCLUDE_DIRS}
)
target_link_libraries(edr PRIVATE
    ftxui::screen ftxui::dom ftxui::component
    ${LIBBPF_LIBRARIES} elf z pthread util
)
target_link_directories(edr PRIVATE ${LIBBPF_LIBRARY_DIRS})
target_compile_options(edr PRIVATE ${LIBBPF_CFLAGS_OTHER} -fno-exceptions -fno-rtti)

add_executable(edr-run
    debug/edr_run.cpp
    src/seccomp_filter.cpp
)
target_include_directories(edr-run PRIVATE ${CMAKE_SOURCE_DIR}/src)
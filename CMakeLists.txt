cmake_minimum_required(VERSION 3.16)
project(SkyNet VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler flags
if(MSVC)
    add_compile_options(/W4 /EHsc)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

find_package(Threads REQUIRED)

# Includes
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/third_party
)

# Core library sources
set(SKYNET_CORE_SOURCES
    src/enricher.cpp
    src/correlator.cpp
    src/event_queue.cpp
    src/transport.cpp
    src/agent.cpp
    src/collectors/auth_collector.cpp
    src/collectors/process_collector.cpp
    src/collectors/network_collector.cpp
    src/collectors/file_collector.cpp
    src/collectors/usb_collector.cpp
    src/collectors/system_collector.cpp
    src/collectors/app_collector.cpp
    src/deep_scan.cpp
)

add_library(skynet_core STATIC ${SKYNET_CORE_SOURCES})
target_link_libraries(skynet_core PUBLIC Threads::Threads)

# Main executable
add_executable(skynet-agent src/main.cpp)
target_link_libraries(skynet-agent PRIVATE skynet_core)

# Tests
enable_testing()

add_executable(test_schema tests/test_schema.cpp)
target_link_libraries(test_schema PRIVATE Threads::Threads)
add_test(NAME test_schema COMMAND test_schema)

add_executable(test_correlator tests/test_correlator.cpp src/correlator.cpp)
target_link_libraries(test_correlator PRIVATE Threads::Threads)
add_test(NAME test_correlator COMMAND test_correlator)

add_executable(test_fixture_replay tests/test_fixture_replay.cpp src/correlator.cpp)
target_link_libraries(test_fixture_replay PRIVATE Threads::Threads)
add_test(NAME test_fixture_replay COMMAND test_fixture_replay)

add_executable(test_deep_scan tests/test_deep_scan.cpp src/deep_scan.cpp)
target_link_libraries(test_deep_scan PRIVATE Threads::Threads)
add_test(NAME test_deep_scan COMMAND test_deep_scan)


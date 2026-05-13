# =========================================================================
# CMakeLists.txt for rasp_sentry_native
#
# Native Win32 C++ port of the C# rasp_sentry coordination hub.
# Produces rasp_sentry.exe — self-contained, no .NET runtime dependency.
#
# Wire-protocol compatible with all existing C++ and C# RASP modules.
# JSON manipulation uses nlohmann/json (single-header, auto-fetched).
#
# Build:
#   cmake -S . -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#
# Output: build/Release/rasp_sentry.exe
# =========================================================================
cmake_minimum_required(VERSION 3.15)
project(rasp_sentry_native LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# ── nlohmann/json 3.11.3 — single header, vendored or auto-fetched ───────────
set(NLOHMANN_JSON_HEADER
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann/json.hpp"
    CACHE PATH "Path to nlohmann/json single-header (auto-fetched if absent)")

if(NOT EXISTS "${NLOHMANN_JSON_HEADER}")
    message(STATUS "rasp_sentry_native: nlohmann/json not vendored — fetching 3.11.3")
    FetchContent_Declare(
        nlohmann_json_single
        URL          https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
        DOWNLOAD_NO_EXTRACT TRUE
        DOWNLOAD_DIR "${CMAKE_CURRENT_SOURCE_DIR}/third_party/nlohmann"
    )
    FetchContent_Populate(nlohmann_json_single)
else()
    message(STATUS "rasp_sentry_native: using vendored nlohmann/json at ${NLOHMANN_JSON_HEADER}")
endif()

# ── rasp_sentry executable ────────────────────────────────────────────────────
add_executable(rasp_sentry
    src/main.cpp
    src/sentry_log.cpp
    src/pipe_security.cpp
    src/event_collector.cpp
    src/control_status_collector.cpp
    src/rule_server.cpp
    src/config_watcher.cpp
    src/amsi_staging_watcher.cpp
)

target_include_directories(rasp_sentry PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party"
)

target_compile_definitions(rasp_sentry PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    NOMINMAX
    _WIN32_WINNT=0x0601     # Windows 7+ — sufficient for named pipes + ReadDirectoryChangesW
)

target_link_libraries(rasp_sentry PRIVATE
    advapi32    # SID / ACL / registry
    kernel32
    shlwapi     # PathMatchSpecW
)

# Static CRT — no MSVCRT*.dll / msvcp*.dll dependency on deployment host
if(MSVC)
    target_compile_options(rasp_sentry PRIVATE /W3 /WX- /MP)
    set_property(TARGET rasp_sentry PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

set_target_properties(rasp_sentry PROPERTIES OUTPUT_NAME "rasp_sentry")

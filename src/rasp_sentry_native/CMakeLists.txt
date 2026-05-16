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
project(rasp_sentry_native LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# Lua 5.4 for sentry-side source-to-bytecode compilation.
# Reuse the vendored Lua source that is already shared with rasp_rule_engine.
get_filename_component(_lua_default_dir
    "${CMAKE_CURRENT_SOURCE_DIR}/../rasp_rule_engine/third_party/lua/src"
    ABSOLUTE)
set(LUA_SRC_DIR "${_lua_default_dir}"
    CACHE PATH "Lua 5.4 source directory (shared with rasp_rule_engine)")

if(NOT EXISTS "${LUA_SRC_DIR}/lua.h")
    message(STATUS "rasp_sentry_native: Lua not vendored at ${LUA_SRC_DIR} - fetching lua-5.4.7")
    FetchContent_Declare(
        lua54_src_sentry
        URL      https://www.lua.org/ftp/lua-5.4.7.tar.gz
        URL_HASH SHA256=9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30
    )
    FetchContent_Populate(lua54_src_sentry)
    set(LUA_SRC_DIR "${lua54_src_sentry_SOURCE_DIR}/src" CACHE PATH "" FORCE)
else()
    message(STATUS "rasp_sentry_native: using shared Lua source at ${LUA_SRC_DIR}")
endif()

file(GLOB LUA_SOURCES "${LUA_SRC_DIR}/*.c")
list(FILTER LUA_SOURCES EXCLUDE REGEX ".*(lua|luac)\\.c$")

add_library(lua54_static_sentry STATIC ${LUA_SOURCES})
target_include_directories(lua54_static_sentry PUBLIC "${LUA_SRC_DIR}")
target_compile_definitions(lua54_static_sentry PRIVATE LUA_BUILD_AS_DLL=0)
if(MSVC)
    target_compile_options(lua54_static_sentry PRIVATE /W0)
    set_property(TARGET lua54_static_sentry PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

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
    ../amsi_ipc_host/src/amsi_config_broadcaster.cpp
    ../amsi_ipc_host/src/named_pipe_server_pool.cpp
    ../amsi_ipc_host/src/amsi_rule_channel.cpp
    ../amsi_ipc_host/src/amsi_event_channel.cpp
    ../amsi_ipc_host/src/amsi_control_status_channel.cpp
    src/event_collector.cpp
    src/control_status_collector.cpp
    src/rule_server.cpp
    src/config_watcher.cpp
    src/amsi_staging_watcher.cpp
)

target_include_directories(rasp_sentry PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../amsi_ipc_host/include"
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
    lua54_static_sentry
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

add_executable(amsi_config_broadcaster_tests
    ../amsi_ipc_host/tests/amsi_config_broadcaster_tests.cpp
    ../amsi_ipc_host/src/amsi_config_broadcaster.cpp
)

target_include_directories(amsi_config_broadcaster_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../amsi_ipc_host/include"
)

target_compile_definitions(amsi_config_broadcaster_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    NOMINMAX
    _WIN32_WINNT=0x0601
)

target_link_libraries(amsi_config_broadcaster_tests PRIVATE
    kernel32
)

if(MSVC)
    target_compile_options(amsi_config_broadcaster_tests PRIVATE /W3 /WX- /MP)
    set_property(TARGET amsi_config_broadcaster_tests PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(amsi_rule_channel_tests
    ../amsi_ipc_host/tests/amsi_rule_channel_tests.cpp
    ../amsi_ipc_host/src/amsi_rule_channel.cpp
)

target_include_directories(amsi_rule_channel_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../amsi_ipc_host/include"
)

target_compile_definitions(amsi_rule_channel_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    NOMINMAX
    _WIN32_WINNT=0x0601
)

target_link_libraries(amsi_rule_channel_tests PRIVATE
    kernel32
)

if(MSVC)
    target_compile_options(amsi_rule_channel_tests PRIVATE /W3 /WX- /MP)
    set_property(TARGET amsi_rule_channel_tests PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(amsi_event_channel_tests
    ../amsi_ipc_host/tests/amsi_event_channel_tests.cpp
    ../amsi_ipc_host/src/amsi_event_channel.cpp
)

target_include_directories(amsi_event_channel_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../amsi_ipc_host/include"
)

target_compile_definitions(amsi_event_channel_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    NOMINMAX
    _WIN32_WINNT=0x0601
)

target_link_libraries(amsi_event_channel_tests PRIVATE
    kernel32
)

if(MSVC)
    target_compile_options(amsi_event_channel_tests PRIVATE /W3 /WX- /MP)
    set_property(TARGET amsi_event_channel_tests PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

add_executable(amsi_control_status_channel_tests
    ../amsi_ipc_host/tests/amsi_control_status_channel_tests.cpp
    ../amsi_ipc_host/src/amsi_control_status_channel.cpp
)

target_include_directories(amsi_control_status_channel_tests PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/../amsi_ipc_host/include"
)

target_compile_definitions(amsi_control_status_channel_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    NOMINMAX
    _WIN32_WINNT=0x0601
)

target_link_libraries(amsi_control_status_channel_tests PRIVATE
    kernel32
)

if(MSVC)
    target_compile_options(amsi_control_status_channel_tests PRIVATE /W3 /WX- /MP)
    set_property(TARGET amsi_control_status_channel_tests PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

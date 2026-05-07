# =========================================================================
# CMakeLists.txt for rasp_rule_engine (shared Lua sandbox static library)
#
# Provides:
#   - lua54_static     — Lua 5.4 build (vendored or auto-fetched)
#   - rasp_rule_engine — RaspLuaEngine class (Precompile/Run/SetLogFn/Reset)
#
# Consumers (rasp_mod_iis, rasp_mod_amsi) add this as a subdirectory:
#   add_subdirectory(../rasp_rule_engine ${CMAKE_CURRENT_BINARY_DIR}/rasp_rule_engine)
#   target_link_libraries(<target> PRIVATE rasp_rule_engine)
#
# Lua headers and lua54_static are transitively available via PUBLIC linkage.
#
# Third-party dependencies live under rasp_rule_engine/third_party/:
#   third_party/lua/   — Lua 5.4 source (git-tracked; auto-fetched if absent)
#   third_party/pcre2/ — PCRE2 source   (auto-fetched if absent)
# =========================================================================
cmake_minimum_required(VERSION 3.15)
project(rasp_rule_engine LANGUAGES C CXX)

# 强制 MSVC 编译器使用 UTF-8 编码读取源文件和执行字符集
if(MSVC)
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
    add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

# ── Lua 5.4 — vendored under third_party/lua/; auto-fetched if absent ────────
set(LUA_SRC_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/lua/src"
    CACHE PATH "Lua 5.4 source directory (leave at default to auto-fetch)")

if(NOT EXISTS "${LUA_SRC_DIR}/lua.h")
    message(STATUS "rasp_rule_engine: Lua not vendored — fetching lua-5.4.7 from lua.org")
    FetchContent_Declare(
        lua54_src
        URL      https://www.lua.org/ftp/lua-5.4.7.tar.gz
        URL_HASH SHA256=9fbf5e28ef86c69858f6d3d34eccc32e911c1a28b4120ff3e84aaa70cfbf1e30
    )
    FetchContent_Populate(lua54_src)   # Lua has no CMakeLists.txt — populate only
    set(LUA_SRC_DIR "${lua54_src_SOURCE_DIR}/src" CACHE PATH "" FORCE)
    message(STATUS "rasp_rule_engine: Lua source at ${LUA_SRC_DIR}")
else()
    message(STATUS "rasp_rule_engine: using vendored Lua at ${LUA_SRC_DIR}")
endif()

file(GLOB LUA_SOURCES "${LUA_SRC_DIR}/*.c")
list(FILTER LUA_SOURCES EXCLUDE REGEX ".*(lua|luac)\\.c$")

add_library(lua54_static STATIC ${LUA_SOURCES})
target_include_directories(lua54_static PUBLIC "${LUA_SRC_DIR}")
target_compile_definitions(lua54_static PRIVATE LUA_BUILD_AS_DLL=0)
if(MSVC)
    target_compile_options(lua54_static PRIVATE /W0)
endif()
set_target_properties(lua54_static PROPERTIES POSITION_INDEPENDENT_CODE ON)

# ── PCRE2 — vendored under third_party/pcre2/; auto-fetched if absent ─────────
# Preferred: vendor source under third_party/pcre2/ for air-gapped builds.
# When absent, CMake fetches it automatically from GitHub.
set(PCRE2_SRC_DIR
    "${CMAKE_CURRENT_SOURCE_DIR}/third_party/pcre2"
    CACHE PATH "PCRE2 source directory (leave at default to auto-fetch)")

set(PCRE2_BUILD_PCRE2_8      ON  CACHE BOOL "" FORCE)
set(PCRE2_BUILD_PCRE2_16     OFF CACHE BOOL "" FORCE)
set(PCRE2_BUILD_PCRE2_32     OFF CACHE BOOL "" FORCE)
set(PCRE2_SUPPORT_JIT        ON  CACHE BOOL "" FORCE)
set(PCRE2_BUILD_TESTS        OFF CACHE BOOL "" FORCE)
set(PCRE2_BUILD_PCRECPP      OFF CACHE BOOL "" FORCE)
set(PCRE2_STATIC             ON  CACHE BOOL "" FORCE)

if(EXISTS "${PCRE2_SRC_DIR}/CMakeLists.txt")
    message(STATUS "rasp_rule_engine: using vendored PCRE2 at ${PCRE2_SRC_DIR}")
    add_subdirectory("${PCRE2_SRC_DIR}"
                     "${CMAKE_CURRENT_BINARY_DIR}/pcre2" EXCLUDE_FROM_ALL)
else()
    message(STATUS "rasp_rule_engine: PCRE2 not vendored — fetching from GitHub")
    FetchContent_Declare(
        pcre2
        GIT_REPOSITORY https://github.com/PCRE2Project/pcre2.git
        GIT_TAG        pcre2-10.44          # latest stable as of 2024
        GIT_SHALLOW    TRUE
    )
    FetchContent_MakeAvailable(pcre2)
    # FetchContent places generated headers in the binary dir under _deps/pcre2-build/
    set(PCRE2_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/_deps/pcre2-build")
endif()

set(RASP_PCRE2_AVAILABLE TRUE)

# ── rasp_rule_engine static library ──────────────────────────────────────────
add_library(rasp_rule_engine STATIC
    src/async_event_queue.cpp
    src/event_submit_client.cpp
    src/event_worker_sender.cpp
    src/legacy_diag_json_builder.cpp
    src/legacy_pipe_event_transport.cpp
    src/rule_json_parser.cpp
    src/rasp_lua_engine.cpp
    src/rasp_sentry_base.cpp
)

target_include_directories(rasp_rule_engine PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${LUA_SRC_DIR}"
)

target_compile_definitions(rasp_rule_engine PRIVATE WIN32_LEAN_AND_MEAN)

if(RASP_PCRE2_AVAILABLE)
    # pcre2.h is generated into the build dir by PCRE2's cmake.
    # Resolve the correct generated-header path for vendored vs. FetchContent.
    if(EXISTS "${PCRE2_SRC_DIR}/CMakeLists.txt")
        set(_pcre2_inc "${CMAKE_CURRENT_BINARY_DIR}/pcre2")
    else()
        set(_pcre2_inc "${PCRE2_BINARY_DIR}")
    endif()
    # Expose publicly so consumers (rasp_mod_amsi, rasp_mod_iis) don't need extra includes.
    target_include_directories(rasp_rule_engine PUBLIC "${_pcre2_inc}")
    target_compile_definitions(rasp_rule_engine PUBLIC RASP_PCRE2_AVAILABLE)
    target_link_libraries(rasp_rule_engine PUBLIC lua54_static pcre2-8-static)
else()
    target_link_libraries(rasp_rule_engine PUBLIC lua54_static)
endif()

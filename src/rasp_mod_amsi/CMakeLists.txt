# =========================================================================
# CMakeLists.txt for rasp_mod_amsi (Windows AMSI Provider)
#
# Prerequisites:
#   - Windows 10 SDK >= 10.0.19041 (for amsi.h)
#   - Visual Studio 17 2022 with C++ workload
#   - Lua 5.4 source in rasp_rule_engine/third_party/lua/ (owned by rasp_rule_engine; auto-fetched if absent)
#
# Build:
#   cmake -S . -B build -G "Visual Studio 17 2022" -A x64
#   cmake --build build --config Release
#
# Register:
#   regsvr32 build\Release\rasp_mod_amsi.dll
#
# Output: build\Release\rasp_mod_amsi.dll
# =========================================================================
cmake_minimum_required(VERSION 3.20)
project(rasp_mod_amsi LANGUAGES C CXX)

if(MSVC)
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/utf-8>")
    add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/utf-8>")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# ── Shared Lua sandbox + RaspLuaEngine ───────────────────────────────────────
# lua54_static and rasp_rule_engine are both defined in rasp_rule_engine/.
# Lua 5.4 and PCRE2 source live in rasp_rule_engine/third_party/ — rasp_rule_engine
# owns those dependencies and auto-fetches them if not already vendored.
# Lua headers are available transitively via PUBLIC linkage on rasp_rule_engine.
add_subdirectory(../rasp_rule_engine ${CMAKE_CURRENT_BINARY_DIR}/rasp_rule_engine)

# ── rasp_mod_amsi DLL ──────────────────────────────────────────────────────
add_library(rasp_mod_amsi SHARED
    src/rasp_mod_amsi.cpp
    src/amsi_provider.cpp
    src/amsi_rule_engine.cpp
    src/engine_runtime.cpp
    src/script_input_normalizer.cpp
    src/script_session_context_cache.cpp
    src/rasp_mod_amsi.def
)

target_include_directories(rasp_mod_amsi PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(rasp_mod_amsi PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00   # Windows 10 — required for amsi.h
    INITGUID              # Emit GUID definitions in this TU
)

target_link_libraries(rasp_mod_amsi PRIVATE
    rasp_rule_engine
    bcrypt
    ole32
    oleaut32
)

if(MSVC)
    target_compile_options(rasp_mod_amsi PRIVATE /W3 /WX-)
endif()

set_target_properties(rasp_mod_amsi PROPERTIES
    PREFIX ""
    OUTPUT_NAME "rasp_mod_amsi"
)

add_executable(engine_runtime_tests
    tests/engine_runtime_tests.cpp
    src/amsi_rule_engine.cpp
    src/engine_runtime.cpp
    src/script_input_normalizer.cpp
    src/script_session_context_cache.cpp
)

target_include_directories(engine_runtime_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(engine_runtime_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
)

target_link_libraries(engine_runtime_tests PRIVATE
    rasp_rule_engine
    bcrypt
    ole32
    oleaut32
)

if(MSVC)
    target_compile_options(engine_runtime_tests PRIVATE /W3 /WX-)
endif()

add_executable(scan_budget_tests
    tests/scan_budget_tests.cpp
)

target_include_directories(scan_budget_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(scan_budget_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
)

target_link_libraries(scan_budget_tests PRIVATE
    rasp_rule_engine
)

if(MSVC)
    target_compile_options(scan_budget_tests PRIVATE /W3 /WX-)
endif()

add_executable(async_event_queue_tests
    tests/async_event_queue_tests.cpp
)

target_include_directories(async_event_queue_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(async_event_queue_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
)

target_link_libraries(async_event_queue_tests PRIVATE
    rasp_rule_engine
)

if(MSVC)
    target_compile_options(async_event_queue_tests PRIVATE /W3 /WX-)
endif()

add_executable(script_input_normalizer_tests
    tests/script_input_normalizer_tests.cpp
    src/script_input_normalizer.cpp
)

target_include_directories(script_input_normalizer_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(script_input_normalizer_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
)

target_link_libraries(script_input_normalizer_tests PRIVATE
    bcrypt
)

if(MSVC)
    target_compile_options(script_input_normalizer_tests PRIVATE /W3 /WX-)
endif()

add_executable(session_context_cache_tests
    tests/session_context_cache_tests.cpp
    src/script_session_context_cache.cpp
)

target_include_directories(session_context_cache_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

target_compile_definitions(session_context_cache_tests PRIVATE
    WIN32_LEAN_AND_MEAN
    UNICODE
    _UNICODE
    _WIN32_WINNT=0x0A00
)

if(MSVC)
    target_compile_options(session_context_cache_tests PRIVATE /W3 /WX-)
endif()

cmake_minimum_required(VERSION 3.15)
project(hostguard_demo LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

set(RASP_SENTRY_NATIVE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rasp_sentry_native")
set(AMSI_IPC_HOST_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../amsi_ipc_host")
set(LUA_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rasp_rule_engine/third_party/lua/src")

file(GLOB LUA_SOURCES "${LUA_SRC_DIR}/*.c")
list(FILTER LUA_SOURCES EXCLUDE REGEX ".*(lua|luac)\\.c$")

add_library(lua54_static_hostguard_demo STATIC ${LUA_SOURCES})
target_include_directories(lua54_static_hostguard_demo PUBLIC "${LUA_SRC_DIR}")
target_compile_definitions(lua54_static_hostguard_demo PRIVATE LUA_BUILD_AS_DLL=0)

set(HOSTGUARD_DEMO_SOURCES
    src/hostguard_demo_options.cpp
    src/hostguard_demo_app.cpp
    src/hostguard_file_rule_provider.cpp
    src/hostguard_jsonl_event_sink.cpp
    src/hostguard_jsonl_control_status_sink.cpp
    src/hostguard_command_loop.cpp
    src/hostguard_paths.cpp
)

set(HOSTGUARD_IPC_SOURCES
    "${RASP_SENTRY_NATIVE_DIR}/src/amsi_ipc_host.cpp"
    "${RASP_SENTRY_NATIVE_DIR}/src/sentry_log.cpp"
    src/hostguard_demo_pipe_security.cpp
    "${RASP_SENTRY_NATIVE_DIR}/src/event_collector.cpp"
    "${RASP_SENTRY_NATIVE_DIR}/src/control_status_collector.cpp"
    "${RASP_SENTRY_NATIVE_DIR}/src/demo_file_rule_provider.cpp"
    "${RASP_SENTRY_NATIVE_DIR}/src/rule_server.cpp"
    "${RASP_SENTRY_NATIVE_DIR}/src/config_watcher.cpp"
    "${RASP_SENTRY_NATIVE_DIR}/src/amsi_staging_watcher.cpp"
    "${AMSI_IPC_HOST_DIR}/src/amsi_config_broadcaster.cpp"
    "${AMSI_IPC_HOST_DIR}/src/named_pipe_server_pool.cpp"
    "${AMSI_IPC_HOST_DIR}/src/amsi_rule_channel.cpp"
    "${AMSI_IPC_HOST_DIR}/src/amsi_event_channel.cpp"
    "${AMSI_IPC_HOST_DIR}/src/amsi_control_status_channel.cpp"
)

add_library(hostguard_amsi_ipc_adapter STATIC
    src/hostguard_amsi_ipc_adapter.cpp
)

target_include_directories(hostguard_amsi_ipc_adapter PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
    "${AMSI_IPC_HOST_DIR}/include"
)

add_executable(hostguard_demo
    src/main.cpp
    ${HOSTGUARD_DEMO_SOURCES}
    ${HOSTGUARD_IPC_SOURCES}
)

add_executable(hostguard_demo_smoke_tests
    tests/hostguard_demo_smoke_tests.cpp
    ${HOSTGUARD_DEMO_SOURCES}
    ${HOSTGUARD_IPC_SOURCES}
)

add_executable(hostguard_demo_options_tests
    tests/hostguard_demo_options_tests.cpp
    src/hostguard_pipe_client.cpp
    ${HOSTGUARD_DEMO_SOURCES}
    ${HOSTGUARD_IPC_SOURCES}
)

add_executable(hostguard_amsi_ipc_adapter_tests
    tests/hostguard_amsi_ipc_adapter_tests.cpp
)

add_executable(hostguard_demo_pipe_client
    src/hostguard_demo_pipe_client.cpp
    src/hostguard_pipe_client.cpp
)

foreach(target hostguard_demo hostguard_demo_smoke_tests hostguard_demo_options_tests hostguard_amsi_ipc_adapter_tests hostguard_demo_pipe_client)
    target_include_directories(${target} PRIVATE
        "${CMAKE_CURRENT_SOURCE_DIR}/src"
        "${RASP_SENTRY_NATIVE_DIR}/include"
        "${AMSI_IPC_HOST_DIR}/include"
        "${RASP_SENTRY_NATIVE_DIR}/third_party"
        "${LUA_SRC_DIR}"
    )

    target_compile_definitions(${target} PRIVATE
        WIN32_LEAN_AND_MEAN
        UNICODE
        _UNICODE
        NOMINMAX
        _WIN32_WINNT=0x0601
    )

    target_link_libraries(${target} PRIVATE
        lua54_static_hostguard_demo
        advapi32
        kernel32
        shlwapi
    )

    if(MSVC)
        target_compile_options(${target} PRIVATE /W3 /WX- /MP)
        set_property(TARGET ${target} PROPERTY
            MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    endif()
endforeach()

foreach(target hostguard_demo hostguard_demo_smoke_tests hostguard_demo_options_tests hostguard_amsi_ipc_adapter_tests)
    target_link_libraries(${target} PRIVATE hostguard_amsi_ipc_adapter)
endforeach()

if(MSVC)
    target_compile_options(hostguard_amsi_ipc_adapter PRIVATE /W3 /WX- /MP)
    set_property(TARGET hostguard_amsi_ipc_adapter PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

    target_compile_options(lua54_static_hostguard_demo PRIVATE /W0)
    set_property(TARGET lua54_static_hostguard_demo PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
endif()

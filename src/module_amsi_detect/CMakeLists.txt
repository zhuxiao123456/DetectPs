project(amsi_detect_module)

set(TARGET ${PROJECT_NAME})

set(ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../)
setup_common_path(${PROJECT_NAME} ${ROOT_PATH})

add_library(${TARGET} SHARED
        src/AmsiDetectGlobalParam.cpp
        src/AmsiGlobalConf.cpp
        src/AmsiDetectModule.cpp
        src/AmsiDetectPolicy.cpp
        src/AmsiDetectTask.cpp
        src/AmsiDetectDllManager.cpp
        src/AmsiIpcRuntime.cpp
        src/AmsiPipeSecurity.cpp
        src/AmsiRuleSnapshot.cpp
        src/AmsiIpcPayloadClassifier.cpp
        src/AmsiIpcRuntimeQueue.cpp
        src/AmsiEventProcessor.cpp
        src/AmsiLuaPreCompiler.cpp
        amsi_ipc_host/src/AmsiConfigBroadcaster.cpp
        amsi_ipc_host/src/AmsiControlStatusChannel.cpp
        amsi_ipc_host/src/AmsiEventChannel.cpp
        amsi_ipc_host/src/AmsiRuleChannel.cpp
        amsi_ipc_host/src/NamedPipeServerPool.cpp
        ../../module_utils/src/ModuleUtils.cpp
)

target_compile_features(${TARGET} PRIVATE cxx_std_11)

target_include_directories(${TARGET} PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_SOURCE_DIR}/amsi_ipc_host/include
)

if (MSVC)
    target_compile_options(${TARGET} PRIVATE /utf-8)

    target_compile_definitions(${TARGET} PRIVATE
            WIN32_LEAN_AND_MEAN
            NOMINMAX
            UNICODE
            _UNICODE
    )
endif()
# 连接必要的库
target_link_libraries(
        ${TARGET}
        sdk
        framework
        feature_upgrade_module
        PocoNet
        PocoUtil
        PocoFoundation
        Advapi32
        lua54
)
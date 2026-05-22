project(amsi_detect_module)

set(ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../)
setup_common_path(${PROJECT_NAME} ${ROOT_PATH})


add_library(${TARGET} SHARED
        src/AmsiDetectGlobalParam.cpp
        src/AmsiIpcRuntime.cpp
        src/AmsiPipeSecurity.cpp
        src/AmsiDetectModule.cpp
        src/AmsiDetectPolicy.cpp
        src/AmsiRuleSnapshot.cpp
        src/AmsiDetectTask.cpp
        ../amsi_ipc_host/src/named_pipe_server_pool.cpp
        ../amsi_ipc_host/src/amsi_rule_channel.cpp
        ../amsi_ipc_host/src/amsi_event_channel.cpp
        ../amsi_ipc_host/src/amsi_control_status_channel.cpp
        ../amsi_ipc_host/src/amsi_config_broadcaster.cpp
        ../../module_utils/src/ModuleUtils.cpp)

target_include_directories(${TARGET} PRIVATE
        ../amsi_ipc_host/include)

# 连接必要的库
TARGET_LINK_LIBRARIES(
        ${TARGET}
        sdk
        framework
        feature_upgrade_module
        Advapi32
)

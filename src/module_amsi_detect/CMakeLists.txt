project(amsi_detect_module)

set(ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../)
setup_common_path(${PROJECT_NAME} ${ROOT_PATH})


add_library(${TARGET} SHARED
        src/AmsiDetectGlobalParam.cpp
        src/AmsiDetectModule.cpp
        src/AmsiDetectPolicy.cpp
        src/AmsiDetectTask.cpp
        ../../module_utils/src/ModuleUtils.cpp)

# 连接必要的库
TARGET_LINK_LIBRARIES(
        ${TARGET}
        sdk
        framework
        feature_upgrade_module
)

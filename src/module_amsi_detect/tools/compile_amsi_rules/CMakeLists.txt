project(compile_amsi_rules)

set(ROOT_PATH ${CMAKE_CURRENT_SOURCE_DIR}/../../)
setup_common_path(${PROJECT_NAME} ${ROOT_PATH})

if (WIN32)
    add_definitions(-D_AMD64_)
endif ()

add_executable(CompileAmsiRules
        src/CompileAmsiRules.cpp
        src/AmsiLuaPreCompiler)

TARGET_LINK_LIBRARIES(
        CompileAmsiRules
        sdk
        lua54)
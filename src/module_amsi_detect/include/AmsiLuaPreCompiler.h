#pragma once

#ifndef CSA_ENGINE_AMSI_LUA_PRE_COMPILER_H
#define CSA_ENGINE_AMSI_LUA_PRE_COMPILER_H

#include <string>

#include "JsonUtils.h"

namespace Engine {

    bool CompileScriptsInJson(SDK::JsonUtils::JsonValue &jsonRoot, std::string &error);

}

#endif // CSA_ENGINE_AMSI_LUA_PRE_COMPILER_H
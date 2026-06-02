#ifndef CSA_ENGINE_AMSI_LUA_PRE_COMPILER_H
#define CSA_ENGINE_AMSI_LUA_PRE_COMPILER_H

#include <string>

#include "JsonUtils.h"

namespace Engine {
    namespace CompileAmsiRules {

        bool CompileLuaScripts(const std::string &luaScriptContent, const char *chunkName, std::string &compileResult);

    }
}

#endif // CSA_ENGINE_AMSI_LUA_PRE_COMPILER_H

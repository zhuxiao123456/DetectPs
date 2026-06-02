//
// Created by y00969037 on 2026/5/27.
//

#include <iostream>
#include <string>

#include "PathUtils.h"
#include "FileUtils.h"
#include "JsonUtils.h"

#include "AmsiLuaPreCompiler.h"

using namespace std;
using namespace SDK;

namespace Engine {
    namespace CompileAmsiRules {

        bool GetAllGlobalLibrarySource(const SDK::JsonUtils::JsonValue &ruleJson, const std::string &curPath, std::string &globalLua)
        {
            JsonUtils::JsonValue libs;
            bool ret = JsonUtils::GetArrayValue(ruleJson, "globalLibraries", libs);
            if (!ret) {
                std::cout << "Get globalLibraries array failed." << std::endl;
                return false;
            }

            for (const auto &lib: libs) {
                if (!lib.isString()) {
                    std::cout << "GlobalLibraries contains non-string item." << std::endl;
                    return false;
                }

                std::string libPath = curPath + lib.asString();
                std::string libContent;
                int ret = FileUtils::ReadFile(libPath, libContent);
                if (ret != 0) {
                    std::cout << "Read lib file " << libPath << " failed." << std::endl;
                    return false;
                }
                if (libContent.empty()) {
                    std::cout << "Lib file " << libPath << " is empty." << std::endl;
                    return false;
                }

                globalLua.append(libContent);
                if (globalLua.back() != '\n') {
                    globalLua.push_back('\n');
                }
            }

            return true;
        }

        bool CompileInlineLuaScripts(SDK::JsonUtils::JsonValue &ruleJson, const std::string &curPath, const std::string &globalLua)
        {
            JsonUtils::JsonValue rules;
            if (!JsonUtils::GetArrayValue(ruleJson, "rules", rules)) {
                std::cout << "Get rules array failed." << std::endl;
                return false;
            }

            for (auto &rule: rules) {
                if (!rule.isObject()) {
                    std::cout << "Rules contains no-array failed." << std::endl;
                    return false;
                }
                if (!rule.isMember("script")) {
                    continue;
                }
                if (!rule["script"].isString()) {
                    std::cout << "Rules contains script not string." << std::endl;
                    return false;
                }

                std::string scriptRef = rule["script"].asString();
                if (scriptRef.empty()) {
                    std::cout << "Rules contains script string is empty." << std::endl;
                    return false;
                }

                std::string scriptPath = curPath + scriptRef;
                std::string scriptContent;
                if (FileUtils::ReadFile(scriptPath, scriptContent) != 0) {
                    std::cout << "Read script file " << scriptPath << " failed." << std::endl;
                    return false;
                }
                if (scriptContent.empty()) {
                    std::cout << "Script file " << scriptPath << " is empty." << std::endl;
                    return false;
                }

                std::string luaContent = globalLua;
                if (!luaContent.empty() && luaContent.back() != '\n') {
                    luaContent.push_back('\n');
                }
                luaContent.append(scriptContent);

                std::string chunkName = "=amsi_rule";
                if (rule.isMember("id") && rule["id"].isString() && !rule["id"].asString().empty()) {
                    chunkName = "=" + rule["id"].asString();
                }

                std::string compileResult;
                if (!CompileLuaScripts(luaContent, chunkName.c_str(), compileResult)) {
                    std::cout << "Compile script file " << scriptPath << " failed." << std::endl;
                    return false;
                }
                rule["scriptBodyBase64"] = compileResult;
                rule["scriptEncoding"] = "bytecode";
            }

            ruleJson["rules"] = rules;

            return true;
        }

        bool  CompileOriginalAmsiRules(const std::string &curPath)
        {
            string originalRulesPath = curPath + "\\original_amsi_rules.json";
            std::string ruleContent;
            if (FileUtils::ReadFile(originalRulesPath, ruleContent) != 0) {
                std::cout << "Read rule file " << originalRulesPath << " failed." << std::endl;
                return false;
            }
            if (ruleContent.empty()) {
                std::cout << "Rule file " << originalRulesPath << " is empty." << std::endl;
                return false;
            }

            SDK::JsonUtils::JsonValue ruleJson;
            if (SDK::JsonUtils::ParseJsonStr(ruleContent.c_str(), ruleContent.length(), ruleJson) != 0) {
                std::cout << "Parse rule file " << originalRulesPath << " failed." << std::endl;
                return false;
            }

            std::string globalLua;
            if (!GetAllGlobalLibrarySource(ruleJson, curPath, globalLua)) {
                std::cout << "Get globalLibraries failed." << std::endl;
                return false;
            }

            if (!CompileInlineLuaScripts(ruleJson, curPath, globalLua)) {
                std::cout << "Compile lua script failed." << std::endl;
                return false;
            }

            string rulesPath = curPath + "\\amsi_rules.json";
            std::string ruleJsonStr = JsonUtils::JsonToString(ruleJson);
            if (FileUtils::WriteFile(rulesPath, ruleJsonStr, false) != 0) {
                std::cout << "Write rule file " << rulesPath << " failed." << std::endl;
                return false;
            }
            return true;
        }

    }
}

using namespace Engine::CompileAmsiRules;

int main(int argc, char *argv[])
{
    std::string curPath;
    if (PathUtils::GetBinPath(curPath) == -1) {
        std::cout << "Get current path failed." << std::endl;
        system("pause");
        return -1;
    }

    if (!CompileOriginalAmsiRules(curPath)) {
        std::cout << "Compile amsi rule failed." << std::endl;
    } else {
        std::cout << "Compile amsi rule success, ." << std::endl;
    }

    system("pause");

    return 0;
}

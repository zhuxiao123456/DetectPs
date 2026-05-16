#include "demo_file_rule_provider.h"

#include "base64.h"
#include "nlohmann/json.hpp"
#include "sentry_log.h"

#include <algorithm>
#include <fstream>
#include <string>
#include <vector>

extern "C" {
#include "lauxlib.h"
#include "lua.h"
}

using json = nlohmann::json;

namespace {

std::string DirOf(const std::string& filePath)
{
    size_t pos = filePath.find_last_of("/\\");
    return (pos == std::string::npos) ? "." : filePath.substr(0, pos);
}

void InlineGlobalLibraries(json& root, const std::string& rulesDir)
{
    if (!root.contains("globalLibraries")) return;
    const auto& libs = root["globalLibraries"];
    if (!libs.is_array()) return;

    json b64Array = json::array();
    int count = 0;

    for (const auto& entry : libs)
    {
        if (!entry.is_string()) continue;
        std::string relPath = entry.get<std::string>();
        std::replace(relPath.begin(), relPath.end(), '/', '\\');
        std::string absPath = rulesDir + "\\" + relPath;

        std::ifstream fs(absPath, std::ios::binary);
        if (!fs.is_open())
        {
            SentryLog_Warn("DemoFileRuleProvider", "globalLibrary not found: %s", absPath.c_str());
            continue;
        }
        std::vector<uint8_t> bytes(
            (std::istreambuf_iterator<char>(fs)),
            std::istreambuf_iterator<char>());

        b64Array.push_back(base64_encode(bytes));
        ++count;
    }

    root.erase("globalLibraries");
    root["globalLibrariesBase64"] = std::move(b64Array);
    SentryLog_Info("DemoFileRuleProvider", "Inlined %d global library file(s) as globalLibrariesBase64", count);
}

void InlineScriptFiles(json& root, const std::string& rulesDir)
{
    if (!root.contains("rules") || !root["rules"].is_array()) return;

    int count = 0;
    for (auto& rule : root["rules"])
    {
        if (!rule.is_object() || !rule.contains("script")) continue;
        if (!rule["script"].is_string()) continue;

        std::string relPath = rule["script"].get<std::string>();
        std::replace(relPath.begin(), relPath.end(), '/', '\\');
        std::string absPath = rulesDir + "\\" + relPath;

        rule.erase("script");

        std::ifstream fs(absPath, std::ios::binary);
        if (!fs.is_open())
        {
            SentryLog_Warn("DemoFileRuleProvider", "Script not found: %s - rule gets empty scriptBodyBase64", absPath.c_str());
            rule["scriptBodyBase64"] = "";
            continue;
        }
        std::vector<uint8_t> bytes(
            (std::istreambuf_iterator<char>(fs)),
            std::istreambuf_iterator<char>());

        rule["scriptBodyBase64"] = base64_encode(bytes);
        ++count;
    }
    SentryLog_Info("DemoFileRuleProvider", "Inlined %d Lua script file(s) as scriptBodyBase64", count);
}

std::string ExtractGlobalLibPrefix(const json& root)
{
    if (!root.contains("globalLibrariesBase64")) return {};
    const auto& arr = root["globalLibrariesBase64"];
    if (!arr.is_array()) return {};

    std::string prefix;
    for (const auto& entry : arr)
    {
        if (!entry.is_string()) continue;
        std::string decoded = base64_decode_str(entry.get<std::string>());
        if (!decoded.empty())
        {
            prefix += decoded;
            prefix += '\n';
        }
    }
    return prefix;
}

struct LuaBytecodeWriter
{
    std::vector<uint8_t> bytes;
};

int LuaDumpWriter(lua_State*, const void* data, size_t size, void* userData)
{
    auto* writer = static_cast<LuaBytecodeWriter*>(userData);
    const auto* chunk = static_cast<const uint8_t*>(data);
    writer->bytes.insert(writer->bytes.end(), chunk, chunk + size);
    return 0;
}

std::vector<uint8_t> CompileToBytecode(const std::string& combinedSource,
                                       const char* chunkName)
{
    lua_State* L = luaL_newstate();
    if (!L)
        return {};

    int rc = luaL_loadbuffer(L, combinedSource.data(), combinedSource.size(), chunkName);
    if (rc != LUA_OK)
    {
        const char* err = lua_tostring(L, -1);
        SentryLog_Error("DemoFileRuleProvider",
                        "CompileToBytecode: luaL_loadbuffer failed for %s: %s",
                        chunkName,
                        err ? err : "(nil)");
        lua_close(L);
        return {};
    }

    LuaBytecodeWriter writer;
    rc = lua_dump(L, LuaDumpWriter, &writer, 0);
    lua_close(L);

    if (rc != 0 || writer.bytes.empty())
    {
        SentryLog_Error("DemoFileRuleProvider",
                        "CompileToBytecode: lua_dump failed for %s (rc=%d)",
                        chunkName,
                        rc);
        return {};
    }

    return writer.bytes;
}

void PrependLibToRuleScript(json& rule, const std::string& libPrefix)
{
    if (!rule.contains("scriptBodyBase64")) return;
    if (!rule["scriptBodyBase64"].is_string()) return;

    const std::string existingB64 = rule["scriptBodyBase64"].get<std::string>();
    std::string ruleScript;
    if (!existingB64.empty())
    {
        ruleScript = base64_decode_str(existingB64);
        if (ruleScript.empty()) return;
    }

    const std::string combined = libPrefix.empty() ? ruleScript : libPrefix + "\n" + ruleScript;
    std::string chunkName = "=rasp_rule";
    if (rule.contains("id") && rule["id"].is_string())
        chunkName = "=" + rule["id"].get<std::string>();

    std::vector<uint8_t> bytecode = CompileToBytecode(combined, chunkName.c_str());
    if (!bytecode.empty())
    {
        rule["scriptBodyBase64"] = base64_encode(bytecode.data(), bytecode.size());
        rule["scriptEncoding"] = "bytecode";
        SentryLog_Info("DemoFileRuleProvider",
                       "Compiled %s to bytecode (%zu bytes)",
                       chunkName.c_str(),
                       bytecode.size());
    }
    else
    {
        SentryLog_Warn("DemoFileRuleProvider",
                       "Bytecode compilation failed for %s - falling back to source text",
                       chunkName.c_str());
        rule["scriptBodyBase64"] = base64_encode(combined);
        rule.erase("scriptEncoding");
    }
}

void CompileAllRulesToBytecode(json& root)
{
    if (!root.contains("rules") || !root["rules"].is_array()) return;

    std::string libPrefix = ExtractGlobalLibPrefix(root);
    int compiled = 0;
    int skipped = 0;

    for (auto& rule : root["rules"])
    {
        if (!rule.is_object()) continue;
        if (rule.contains("scriptEncoding") &&
            rule["scriptEncoding"].is_string() &&
            rule["scriptEncoding"].get<std::string>() == "bytecode")
        {
            ++skipped;
            continue;
        }

        const bool hadScript = rule.contains("scriptBodyBase64") && rule["scriptBodyBase64"].is_string();
        PrependLibToRuleScript(rule, libPrefix);
        if (hadScript &&
            rule.contains("scriptEncoding") &&
            rule["scriptEncoding"].is_string() &&
            rule["scriptEncoding"].get<std::string>() == "bytecode")
        {
            ++compiled;
        }
    }

    SentryLog_Info("DemoFileRuleProvider",
                   "CompileAllRulesToBytecode: compiled=%d skipped=%d",
                   compiled,
                   skipped);
}

} // namespace

DemoFileRuleProvider::DemoFileRuleProvider(std::string rulesPath)
    : rulesPath_(std::move(rulesPath))
{
    InitializeCriticalSection(&cacheLock_);
}

DemoFileRuleProvider::~DemoFileRuleProvider()
{
    DeleteCriticalSection(&cacheLock_);
}

bool DemoFileRuleProvider::BuildRulesResponse(const std::string& command,
                                              amsi_ipc::AmsiRuleResponse& out,
                                              std::string& error)
{
    if (_stricmp(command.c_str(), "GET_ALL_RULES") == 0) {
        out.json = GetAssembledJson();
        return true;
    }
    if (_stricmp(command.c_str(), "GET_RULES") == 0) {
        out.json = GetAmsiRulesJson();
        return true;
    }

    error = "unknown command: " + command;
    SentryLog_Warn("DemoFileRuleProvider", "Unknown command: '%s'", command.c_str());
    return false;
}

void DemoFileRuleProvider::InvalidateRuleCache()
{
    SentryLog_Info("DemoFileRuleProvider", "Cache invalidated - next request will rebuild from disk");
    EnterCriticalSection(&cacheLock_);
    cachedAssembled_.clear();
    cachedAmsiRules_.clear();
    LeaveCriticalSection(&cacheLock_);
}

const std::string& DemoFileRuleProvider::GetAssembledJson()
{
    if (!cachedAssembled_.empty()) return cachedAssembled_;

    EnterCriticalSection(&cacheLock_);
    if (cachedAssembled_.empty())
    {
        SentryLog_Info("DemoFileRuleProvider", "Cache miss - building assembled JSON");
        cachedAssembled_ = BuildAssembledJson();
    }
    LeaveCriticalSection(&cacheLock_);
    return cachedAssembled_;
}

const std::string& DemoFileRuleProvider::GetAmsiRulesJson()
{
    GetAssembledJson();

    if (!cachedAmsiRules_.empty()) return cachedAmsiRules_;

    EnterCriticalSection(&cacheLock_);
    if (cachedAmsiRules_.empty())
    {
        SentryLog_Info("DemoFileRuleProvider", "Cache miss - building AMSI-filtered JSON");
        cachedAmsiRules_ = FilterAmsiProviderRules(cachedAssembled_);
    }
    LeaveCriticalSection(&cacheLock_);
    return cachedAmsiRules_;
}

std::string DemoFileRuleProvider::BuildAssembledJson()
{
    try
    {
        std::ifstream f(rulesPath_, std::ios::in);
        if (!f.is_open())
        {
            SentryLog_Error("DemoFileRuleProvider", "Cannot open rules file: %s", rulesPath_.c_str());
            return "[]";
        }

        json root;
        f >> root;

        std::string rulesDir = DirOf(rulesPath_);
        InlineGlobalLibraries(root, rulesDir);
        InlineScriptFiles(root, rulesDir);
        CompileAllRulesToBytecode(root);

        return root.dump();
    }
    catch (const std::exception& ex)
    {
        SentryLog_Error("DemoFileRuleProvider", "BuildAssembledJson failed: %s", ex.what());
        return "[]";
    }
}

std::string DemoFileRuleProvider::FilterAmsiProviderRules(const std::string& assembledJson)
{
    if (assembledJson.empty() || assembledJson == "[]") return "[]";
    try
    {
        json root = json::parse(assembledJson);
        std::string libPrefix = ExtractGlobalLibPrefix(root);

        if (!root.contains("rules") || !root["rules"].is_array()) return "[]";

        json result = json::array();
        for (auto rule : root["rules"])
        {
            if (!rule.is_object()) continue;
            if (!rule.contains("sensor") || !rule["sensor"].is_string()) continue;
            if (rule["sensor"].get<std::string>() != "AmsiProvider") continue;

            bool alreadyBytecode = rule.contains("scriptEncoding") &&
                                   rule["scriptEncoding"].is_string() &&
                                   rule["scriptEncoding"].get<std::string>() == "bytecode";
            if (!alreadyBytecode)
                PrependLibToRuleScript(rule, libPrefix);
            result.push_back(std::move(rule));
        }

        SentryLog_Info("DemoFileRuleProvider", "Filtered %zu AmsiProvider rule(s)", result.size());
        return result.dump();
    }
    catch (const std::exception& ex)
    {
        SentryLog_Error("DemoFileRuleProvider", "FilterAmsiProviderRules failed: %s", ex.what());
        return "[]";
    }
}

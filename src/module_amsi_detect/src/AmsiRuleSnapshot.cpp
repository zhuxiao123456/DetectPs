//
// Created by z00840245 on 2026/5/21.
//

#include "AmsiRuleSnapshot.h"
#include "AmsiLuaPreCompiler.h"
#include <iomanip>
#include <sstream>
#include <limits>
#include "AmsiDetectGlobalParam.h"
#include "DirUtils.h"
#include "FileUtils.h"
#include "JsonUtils.h"
#include "CryptoCodeUtils.h"

namespace Engine {
    using namespace SDK;
    using namespace AmsiDetect;
    namespace {

        std::string ComputeRuleHash(const std::string &content) {
            const unsigned long long fnvOffset = 1469598103934665603ULL;
            const unsigned long long fnvPrime = 1099511628211ULL;

            unsigned long long hash = fnvOffset;
            for (unsigned char ch: content) {
                hash ^= ch;
                hash *= fnvPrime;
            }

            std::ostringstream oss;
            oss << std::hex << std::setw(16) << std::setfill('0') << hash;
            return oss.str();
        }

        bool IsAbsolutePath(const std::string &path) {
            if (path.size() >= 2 && path[1] == ':') {
                return true;
            }
            return path.size() >= 2 && path[0] == '\\' && path[1] == '\\';
        }

        void NormalizeSlash(std::string &path) {
            for (char &ch: path) {
                if (ch == '/') {
                    ch = '\\';
                }
            }
        }

        std::string DirName(const std::string &path) {
            std::string normalized = path;
            NormalizeSlash(normalized);
            const std::string::size_type pos = normalized.find_last_of('\\');
            if (pos == std::string::npos) {
                return {};
            }
            return normalized.substr(0, pos + 1);
        }

        std::string ParentDir(const std::string &dir) {
            std::string normalized = dir;
            NormalizeSlash(normalized);
            while (!normalized.empty() && normalized.back() == '\\') {
                normalized.pop_back();
            }
            const std::string::size_type pos = normalized.find_last_of('\\');
            if (pos == std::string::npos) {
                return {};
            }
            return normalized.substr(0, pos + 1);
        }

        std::string JoinPath(const std::string &base, const std::string &relative) {
            if (relative.empty() || IsAbsolutePath(relative)) {
                std::string path = relative;
                NormalizeSlash(path);
                return path;
            }

            std::string path = base;
            NormalizeSlash(path);
            if (!path.empty() && path.back() != '\\') {
                path.push_back('\\');
            }
            std::string rel = relative;
            NormalizeSlash(rel);
            return path + rel;
        }

        bool ReadTextFile(const std::string &path, std::string &content, std::string &error) {
            if (!SDK::FileUtils::IsFile(path)) {
                error = "file not found: " + path;
                return false;
            }

            const int ret = SDK::FileUtils::ReadFile(path, content);
            if (ret != 0) {
                error = "read file failed: " + path;
                return false;
            }

            if (content.empty()) {
                error = "file is empty: " + path;
                return false;
            }
            return true;
        }

        bool ResolveRuleFile(const std::string &amsiRoot,
                             const std::string &ruleDir,
                             const std::string &jsonPath,
                             std::string &resolved) {
            if (jsonPath.empty()) {
                return false;
            }

            std::string candidate = JoinPath(amsiRoot, jsonPath);
            if (SDK::FileUtils::IsFile(candidate)) {
                resolved = candidate;
                return true;
            }

            candidate = JoinPath(ruleDir, jsonPath);
            if (SDK::FileUtils::IsFile(candidate)) {
                resolved = candidate;
                return true;
            }

            std::string normalized = jsonPath;
            NormalizeSlash(normalized);
            const std::string prefix = "rules\\";
            if (normalized.compare(0, prefix.size(), prefix) == 0) {
                candidate = JoinPath(ruleDir, normalized.substr(prefix.size()));
                if (SDK::FileUtils::IsFile(candidate)) {
                    resolved = candidate;
                    return true;
                }
            }

            return false;
        }

        bool BuildGlobalLibrarySource(const SDK::JsonUtils::JsonValue &root,
                                      const std::string &amsiRoot,
                                      const std::string &ruleDir,
                                      std::string &globalLua,
                                      std::string &error) {
            if (!root.isMember("globalLibraries")) {
                return true;
            }

            const SDK::JsonUtils::JsonValue &libs = root["globalLibraries"];
            if (!libs.isArray()) {
                error = "globalLibraries is not an array";
                return false;
            }

            for (const auto &lib: libs) {
                if (!lib.isString()) {
                    error = "globalLibraries contains non-string item";
                    return false;
                }

                std::string libPath;
                if (!ResolveRuleFile(amsiRoot, ruleDir, lib.asString(), libPath)) {
                    error = "global lua library not found: " + lib.asString();
                    return false;
                }

                std::string libContent;
                if (!ReadTextFile(libPath, libContent, error)) {
                    return false;
                }

                globalLua.append(libContent);
                if (globalLua.empty() || globalLua.back() != '\n') {
                    globalLua.push_back('\n');
                }
            }

            return true;
        }

        bool InlineLuaContent(SDK::JsonUtils::JsonValue &root,
                              const std::string &amsiRoot,
                              const std::string &ruleDir,
                              const std::string &globalLua,
                              std::string &error) {
            if (!root.isMember("rules") || !root["rules"].isArray()) {
                error = "rules is not an array";
                return false;
            }

            SDK::JsonUtils::JsonValue &rules = root["rules"];
            for (auto &rule: rules) {
                if (!rule.isObject()) {
                    continue;
                }
                if (!rule.isMember("script")) {
                    continue;
                }
                if (!rule["script"].isString()) {
                    error = "rule script is not a string";
                    return false;
                }

                const std::string scriptRef = rule["script"].asString();
                if (scriptRef.empty()) {
                    continue;
                }

                std::string scriptPath;
                if (!ResolveRuleFile(amsiRoot, ruleDir, scriptRef, scriptPath)) {
                    error = "lua rule script not found: " + scriptRef;
                    return false;
                }

                std::string scriptContent;
                if (!ReadTextFile(scriptPath, scriptContent, error)) {
                    return false;
                }

                std::string luaContent = globalLua;
                if (!luaContent.empty() && luaContent.back() != '\n') {
                    luaContent.push_back('\n');
                }
                luaContent.append(scriptContent);
                std::string base64EncodeValue;
                int encodeRes = CryptoCodeUtils::EnCodeDataBase64(luaContent, base64EncodeValue);
                if (encodeRes != 0) {
                    WarningLog(GetLoggerPtr(), "base64 encode error by sdk");
                }
                rule["lua_content_base64"] = base64EncodeValue;
            }

            return true;
        }

        bool ComputeSha256Text(const std::string &content, std::string &hash, std::string &error) {
            if (content.length() > static_cast<size_t>((std::numeric_limits<long>::max)())) {
                error = "Assembled rules size exceeds maximum limits of long type.";
                return false;
            }

            int res = CryptoCodeUtils::GetStrSha256(content, hash, static_cast<long>(content.length()));
            if (res != 0) {
                error = "compute hash error";
                return false;
            }

            return true;
        }

    }

    bool LoadRuleSnapshot(const std::string &rulePath,
                          const std::string &version,
                          AmsiRuleSnapshot &snapshot,
                          std::string &error) {
        if (rulePath.empty()) {
            error = "rule path is empty";
            return false;
        }

        std::string ruleContent;
        if (!ReadTextFile(rulePath, ruleContent, error)) {
            return false;
        }

        SDK::JsonUtils::JsonValue root;
        if (SDK::JsonUtils::ParseJsonStr(ruleContent.c_str(), ruleContent.length(), root) != 0) {
            error = "parse rule json failed: " + rulePath;
            return false;
        }

        if (version.empty()) {
            error = "rule version is empty";
            return false;
        }

        const std::string ruleDir = DirName(rulePath);
        const std::string amsiRoot = ParentDir(ruleDir);

        std::string globalLua;
        if (!BuildGlobalLibrarySource(root, amsiRoot, ruleDir, globalLua, error)) {
            return false;
        }

        if (!InlineLuaContent(root, amsiRoot, ruleDir, globalLua, error)) {
            return false;
        }

        if (!CompileScriptsInJson(root, error)) {
            return false;
        }

        std::string ruleHash;
        if (root.isMember("version")) {
            root.removeMember("version");
        }
        if (root.isMember("hash")) {
            root.removeMember("hash");
        }

        const std::string rulesForHash = SDK::JsonUtils::JsonToString(root);
        if (!ComputeSha256Text(rulesForHash, ruleHash, error)) {
            return false;
        }

        root["version"] = version;
        root["hash"] = ruleHash;

        const std::string assembledRules = SDK::JsonUtils::JsonToString(root);
        snapshot.allRulesJson = assembledRules;
        snapshot.amsiRulesJson = assembledRules;
        snapshot.version = version;
        snapshot.hash = ruleHash;
        return true;
    }

}

#include "../include/AmsiLuaPreCompiler.h"

#include "../include/AmsiDetectGlobalParam.h"

#include <cstdint>
#include <exception>
#include <string>
#include <vector>

#include "FileUtils.h"
#include "JsonUtils.h"
#include "CryptoCodeUtils.h"

extern "C" {
#include "lua54/lauxlib.h"
#include "lua54/lua.h"
}

namespace Engine {
    using namespace SDK;
    using namespace AmsiDetect;
    namespace {

        std::string Base64Encode(const uint8_t *data, size_t len) {
            static const char kAlpha[] =
                    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

            std::string out;
            out.reserve(((len + 2) / 3) * 4);

            for (size_t i = 0; i < len; i += 3) {
                uint32_t n = static_cast<uint32_t>(data[i]) << 16;
                if (i + 1 < len) {
                    n |= static_cast<uint32_t>(data[i + 1]) << 8;
                }
                if (i + 2 < len) {
                    n |= static_cast<uint32_t>(data[i + 2]);
                }

                out.push_back(kAlpha[(n >> 18) & 0x3F]);
                out.push_back(kAlpha[(n >> 12) & 0x3F]);
                out.push_back((i + 1 < len) ? kAlpha[(n >> 6) & 0x3F] : '=');
                out.push_back((i + 2 < len) ? kAlpha[n & 0x3F] : '=');
            }

            return out;
        }

        std::string Base64Encode(const std::vector<uint8_t> &bytes) {
            if (bytes.empty()) {
                return std::string();
            }
            return Base64Encode(bytes.data(), bytes.size());
        }

        bool Base64Decode(const std::string &input, std::string &output) {
            static const signed char kTable[256] = {
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -2, -1, -1, -2, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -2, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
                    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -3, -1, -1,
                    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
                    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
                    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
                    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
                    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1
            };

            std::vector<uint8_t> bytes;
            bytes.reserve((input.size() / 4) * 3 + 3);

            int value = 0;
            int bits = -8;
            for (unsigned char c: input) {
                signed char decoded = kTable[c];
                if (decoded == -2) {
                    continue;
                }
                if (decoded == -3) {
                    break;
                }
                if (decoded < 0) {
                    return false;
                }

                value = (value << 6) | decoded;
                bits += 6;
                if (bits >= 0) {
                    bytes.push_back(static_cast<uint8_t>((value >> bits) & 0xFF));
                    bits -= 8;
                }
            }

            output.assign(reinterpret_cast<const char *>(bytes.data()), bytes.size());
            return true;
        }

        std::vector<uint8_t> CompileToBytecode(const std::string &source,
                                               const char *chunkName,
                                               std::string &error) {
            lua_State *state = luaL_newstate();
            if (!state) {
                error = "luaL_newstate failed";
                return std::vector<uint8_t>();
            }

            int rc = luaL_loadbuffer(state, source.data(), source.size(), chunkName);
            if (rc != LUA_OK) {
                const char *luaError = lua_tostring(state, -1);
                error = luaError ? luaError : "luaL_loadbuffer failed";
                lua_close(state);
                return std::vector<uint8_t>();
            }

            struct Writer {
                std::vector<uint8_t> bytes;
            } writer;

            rc = lua_dump(state, [](lua_State *, const void *data, size_t size, void *userData) -> int {
                Writer *writer = static_cast<Writer *>(userData);
                const uint8_t *chunk = static_cast<const uint8_t *>(data);
                writer->bytes.insert(writer->bytes.end(), chunk, chunk + size);
                return 0;
            }, &writer, 0);

            lua_close(state);

            if (rc != 0 || writer.bytes.empty()) {
                error = "lua_dump failed";
                return std::vector<uint8_t>();
            }

            return writer.bytes;
        }

        bool CompileRuleScript(SDK::JsonUtils::JsonValue &rule, std::string &error, std::string &ruleId) {
            if (!rule.isMember("lua_content_base64") || !rule["lua_content_base64"].isString()) {
                return true;
            }

            const std::string luaContentBase64 = rule["lua_content_base64"].asString();
            if (luaContentBase64.empty()) {
                rule.removeMember("lua_content_base64");
                return true;
            }

            std::string ruleScript;
            int decodeRes = CryptoCodeUtils::DeCodeDataBase64(luaContentBase64, ruleScript);
            if (decodeRes != 0 || ruleScript.empty()) {
                error = "decode lua_content_base64 failed";
                return false;
            }

            std::string chunkName = "=amsi_rule";
            if (rule.isMember("id") && rule["id"].isString() && !rule["id"].asString().empty()) {
                chunkName = "=" + rule["id"].asString();
            }

            std::string compileError;
            const std::vector<uint8_t> bytecode = CompileToBytecode(ruleScript, chunkName.c_str(), compileError);
            if (bytecode.empty()) {
                error = "compile lua script failed: " + compileError;
                return false;
            }

            rule["scriptBodyBase64"] = Base64Encode(bytecode);
            rule["scriptEncoding"] = "bytecode";
            rule.removeMember("lua_content_base64");
            InfoLogf1(GetLoggerPtr(), "%s compiled success", ruleId);
            return true;
        }

    } // namespace

    bool CompileScriptsInJson(SDK::JsonUtils::JsonValue &jsonRoot, std::string &error) {
        try {
            if (!jsonRoot.isObject()) {
                error = "rule json root is not object";
                return false;
            }
            if (!jsonRoot.isMember("rules") || !jsonRoot["rules"].isArray()) {
                error = "rules is not an array";
                return false;
            }

            SDK::JsonUtils::JsonValue &rules = jsonRoot["rules"];
            for (auto &rule: rules) {
                if (!rule.isObject()) {
                    continue;
                }
                std::string ruleId;
                if (rule.isMember("id") && rule["id"].isString()) {
                    ruleId = rule["id"].asString();
                }
                if (!CompileRuleScript(rule, error, ruleId)) {
                    if (!ruleId.empty()) {
                        error = "rule=" + ruleId + ", " + error;
                    }
                    ErrorLogf1(AmsiDetect::GetLoggerPtr(), "Compile Lua scripts failed: %s.", error.c_str());
                    return false;
                }
            }

            return true;
        } catch (const std::exception &ex) {
            error = ex.what();
        } catch (...) {
            error = "unknown exception";
        }

        ErrorLogf1(AmsiDetect::GetLoggerPtr(), "Compile Lua scripts failed: %s.", error.c_str());
        return false;
    }

} // namespace Engine
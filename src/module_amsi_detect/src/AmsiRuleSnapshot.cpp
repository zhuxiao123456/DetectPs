//
// Created by Codex on 2026/5/21.
//

#include "AmsiRuleSnapshot.h"

#include <iomanip>
#include <sstream>

#include "DirUtils.h"
#include "FileUtils.h"
#include "JsonUtils.h"

namespace Engine {
    namespace {

        std::string ComputeRuleHash(const std::string &content)
        {
            const unsigned long long fnvOffset = 1469598103934665603ULL;
            const unsigned long long fnvPrime = 1099511628211ULL;

            unsigned long long hash = fnvOffset;
            for (unsigned char ch : content) {
                hash ^= ch;
                hash *= fnvPrime;
            }

            std::ostringstream oss;
            oss << std::hex << std::setw(16) << std::setfill('0') << hash;
            return oss.str();
        }

    }

    bool LoadRuleSnapshot(const std::string &rulePath,
                          const std::string &version,
                          AmsiRuleSnapshot &snapshot,
                          std::string &error)
    {
        if (rulePath.empty()) {
            error = "rule path is empty";
            return false;
        }

        if (!SDK::FileUtils::IsFile(rulePath)) {
            error = "rule file not found: " + rulePath;
            return false;
        }

        std::string ruleContent;
        int ret = SDK::FileUtils::ReadFile(rulePath, ruleContent);
        if (ret != 0) {
            error = "read rule file failed: " + rulePath;
            return false;
        }

        if (ruleContent.empty()) {
            error = "rule file is empty: " + rulePath;
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

        snapshot.allRulesJson = ruleContent;
        snapshot.amsiRulesJson = ruleContent;
        snapshot.version = version;
        snapshot.hash = ComputeRuleHash(ruleContent);
        return true;
    }

}

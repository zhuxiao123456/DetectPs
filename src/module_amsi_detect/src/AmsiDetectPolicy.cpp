//
// Created by y00969037 on 2026/5/19.
//

#include "AmsiDetectPolicy.h"

#include <algorithm>
#include <cctype>

#include "StrUtils.h"

#include "AmsiDetectGlobalParam.h"

namespace Engine {
    using namespace Framework;
    using namespace SDK;
    using namespace AmsiDetect;

    AmsiDetectPolicy::AmsiDetectPolicy(const std::string &featureName) : FeaturePolicy(featureName)
    {
    }

    AmsiDetectPolicy::~AmsiDetectPolicy() = default;

    bool AmsiDetectPolicy::Parse(const std::string &policyStr)
    {
        JsonUtils::JsonValue jValue;
        bool parseRight = (JsonUtils::ParseJsonStr(policyStr.c_str(), policyStr.length(), jValue) == 0);
        if (!parseRight) {
            ErrorLog(GetLoggerPtr(), "Parse policy failed.");
            return false;
        }

        JsonUtils::JsonValue contentValue;
        parseRight = JsonUtils::GetSubobjectValue(jValue, "content", contentValue);
        if (!parseRight) {
            ErrorLog(GetLoggerPtr(), "Get content failed.");
            return false;
        }

        std::string jsonStr = JsonUtils::JsonToString(contentValue);
        auto *taskPolicy = new AmsiDetectTaskPolicy(TASK_NAME_AMSI_DETECT);
        parseRight = taskPolicy->Parse(jsonStr);
        if (parseRight) {
            this->Add(taskPolicy);
        } else {
            delete taskPolicy;
            return false;
        }

        return true;
    }

    AmsiDetectTaskPolicy::AmsiDetectTaskPolicy(const std::string &name) : TaskPolicy(name)
    {
    }

    AmsiDetectTaskPolicy::~AmsiDetectTaskPolicy() = default;

    bool AmsiDetectTaskPolicy::Parse(const std::string &policyContent)
    {
        JsonUtils::JsonValue contentValue;
        bool parseRight = (JsonUtils::ParseJsonStr(policyContent.c_str(), policyContent.length(), contentValue) == 0);
        if (!parseRight) {
            ErrorLog(GetLoggerPtr(), "Parse amsi detect task policy failed.");
            return false;
        }

        m_autoBlock = JsonUtils::GetBoolValue(contentValue, "auto_block", false);
        JsonUtils::JsonValue trustProcessArray;
        parseRight = JsonUtils::GetArrayValue(contentValue, "trust_process", trustProcessArray);
        if (!parseRight) {
            ErrorLog(GetLoggerPtr(), "Parse amsi detect task policy trust process failed.");
            return false;
        }

        for (int i = 0; i < trustProcessArray.size(); ++i) {
            if (!trustProcessArray[i].isString()) {
                continue;
            }
            std::string processPath =  trustProcessArray[i].asString();
            StrUtils::Trim(processPath);
            if (processPath.empty()) {
                continue;
            }
            std::transform(processPath.begin(), processPath.end(), processPath.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            InfoLogf1(GetLoggerPtr(), "Get trust proc path(%s).", processPath);
            m_trustProcess.insert(processPath);
        }

        return true;
    }
}
//
// Created by z00840245 on 2026/5/26.
//

#include "../include/AmsiEventProcessor.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "../include/AmsiDetectGlobalParam.h"
#include "JsonUtils.h"
#include "CryptoCodeUtils.h"
#include "MsgIdDefine.h"
#include "ModuleUtils.h"

namespace Engine {
    using namespace SDK;
    using namespace AmsiDetect;
    namespace {

        bool ParseRawDetectionEvent(const std::string &rawJson,
                                    SDK::JsonUtils::JsonValue &raw,
                                    std::string &error) {
            if (rawJson.empty()) {
                error = "raw detection event is empty";
                return false;
            }

            if (SDK::JsonUtils::ParseJsonStr(rawJson.c_str(), rawJson.length(), raw) != 0) {
                error = "parse raw detection event json failed";
                return false;
            }

            return true;
        }

        std::string GetStringField(const SDK::JsonUtils::JsonValue &value,
                                   const std::string &name) {
            if (!value.isMember(name) || !value[name].isString()) {
                return "";
            }
            return value[name].asString();
        }

        int GetIntField(const SDK::JsonUtils::JsonValue &value,
                        const std::string &name,
                        int defaultValue) {
            if (!value.isMember(name)) {
                return defaultValue;
            }
            if (value[name].isInt()) {
                return value[name].asInt();
            }
            if (value[name].isUInt()) {
                const auto v = value[name].asUInt();
                if (v > static_cast<unsigned int>((std::numeric_limits<int>::max)())) {
                    return defaultValue;
                }
                return static_cast<int>(v);
            }
            return defaultValue;
        }

        std::string FirstNonEmpty(const std::string &first, const std::string &second) {
            return first.empty() ? second : first;
        }

        void MakeAmsiAlarmMsg(const SDK::JsonUtils::JsonValue &raw,
                              SDK::JsonUtils::JsonValue &jValue) {
            jValue["event_id"] = CryptoCodeUtils::GenerateUUID();
            jValue["event_classid"] = "amsi_0001";
            jValue["event_name"] = "Suspicious Powershell Command Execution";
            jValue["occur_time"] = TimeUtils::GetCurrentTimestampS();
            jValue["event_category"] = 3000;
            jValue["event_type"] = 3039;
            jValue["severity"] = GetIntField(raw, "severity", 2);
            jValue["event_count"] = 1;
            jValue["attack_phase"] = 5;
            jValue["attack_tag"] = 4;
            jValue["confidence"] = GetIntField(raw, "confidence", 100);
            jValue["detect_module"] = AmsiDetect::MODULE_NAME_AMSI_DETECT;

            SDK::JsonUtils::JsonValue processInfo;
            processInfo["process_pid"] = GetIntField(raw, "processId", 0);
            processInfo["process_path"] = GetStringField(raw, "processPath");
            processInfo["parent_process_pid"] = GetIntField(raw, "parentPid", 0);
            processInfo["parent_process_path"] = GetStringField(raw, "parentProcessPath");

            SDK::JsonUtils::JsonValue processInfoArray;
            processInfoArray.append(processInfo);
            jValue["process_info"] = processInfoArray;

            SDK::JsonUtils::JsonValue extendInfo;
            extendInfo["hit_rule"] = GetStringField(raw, "rule");
            extendInfo["description"] = GetStringField(raw, "desc");
            extendInfo["script_content"] = GetStringField(raw, "script_content");
            jValue["extend_info"] = extendInfo;
        }

        bool SendAmsiAlarmMsg(const SDK::JsonUtils::JsonValue &alarm) {
            std::string alarmJson = JsonUtils::JsonToString(alarm);
            bool ret = SendDataMessage(MSG_ALARM, alarmJson);
            InfoLogf2(GetLoggerPtr(), "Send amsi alarm (%s), ret(%s).", alarmJson, BOOL_TO_STR(ret));
            return true;
        }

    }

    bool AmsiEventProcessor::ProcessDetectionEvent(const std::string &rawJson,
                                                   std::string &error) {
        SDK::JsonUtils::JsonValue raw;
        if (!ParseRawDetectionEvent(rawJson, raw, error)) {
            return false;
        }

        SDK::JsonUtils::JsonValue alarm;
        MakeAmsiAlarmMsg(raw, alarm);
        return SendAmsiAlarmMsg(alarm);
    }

}
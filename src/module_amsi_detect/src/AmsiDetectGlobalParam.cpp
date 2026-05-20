//
// Created by y00969037 on 2026/5/19.
//

#include "AmsiDetectGlobalParam.h"

#include "JsonUtils.h"

#include "ModuleUtils.h"

namespace Engine
{
    namespace AmsiDetect
    {

        LoggerPtr GetLoggerPtr()
        {
            static LoggerPtr loggerPtr = nullptr;
            if (loggerPtr == nullptr) {
                loggerPtr = GET_MOD_LOGGER(MODULE_NAME_AMSI_DETECT);
            }
            return loggerPtr;
        }

        bool SendAmsiDownloadResponse(const std::string &version, bool isSuccess, const std::string &failReason)
        {
            SDK::JsonUtils::JsonValue jMsg;
            SDK::JsonUtils::JsonValue info;
            info["name"] = "HSS_AMSI";
            info["upgrade_version"] = version;
            info["success"] = isSuccess;
            if (!failReason.empty()) {
                info["fail_reason"] = failReason;
            }
            jMsg["feature_upgrade_result"] = info;
            std::string jsonStr =  SDK::JsonUtils::JsonToString(jMsg);

            bool ret = SendCmdMessage(AGENT_AMSI_LIB_RESPONSE, jsonStr);
            InfoLogf3(GetLoggerPtr(), "Send msg id=%s, content=(%s), ret(%s).", AGENT_AMSI_LIB_RESPONSE, jsonStr, BOOL_TO_STR(ret));

            return ret;
        }


    }
}

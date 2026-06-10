//
// Created by y00969037 on 2026/5/19.
//

#ifndef CSA_ENGINE_AMSI_DETECT_GLOBALPARAM_H
#define CSA_ENGINE_AMSI_DETECT_GLOBALPARAM_H

#include <string>

#include "LoggerDefine.h"

#include "CsaTask.h"

namespace Engine
{
    namespace AmsiDetect
    {
        struct AmsiRuleSnapshot {
            std::string amsiRulesJson;
            std::string version;
            std::string requiredDllHash;
        };

        // module name
        static const std::string MODULE_NAME_AMSI_DETECT = "amsi_detect_module";

        // feature name
        static const std::string FEATURE_NAME_AMSI_DETECT = "amsi_detect_feature";

        // task name
        static const std::string TASK_NAME_AMSI_DETECT = "amsi_detect_task";

        // agent上报AMSI特征库版本信息ID
        static const std::string AGENT_AMSI_LIB_VERSION = "feature_collect_1";

        // agent上报的AMSI 特征库版本消息号.
        static const std::string MASTER_CMD_DOWNLOAD_AMSI_LIB = "feature_upgrade_HSS_AMSI_10001";

        // master 发的AMSI 特征库下载消息号.
        static const std::string AGENT_AMSI_LIB_RESPONSE = "feature_upgrade_response_1";

        ////////////////////////////////////////////////////////////////////////////////////////////////////////////////
        // Get the log pointer of the module.
        LoggerPtr GetLoggerPtr();

        bool SendAmsiDownloadResponse(const std::string &version, bool isSuccess, const std::string &failReason);
    }

}

#endif //CSA_ENGINE_AMSI_DETECT_GLOBALPARAM_H

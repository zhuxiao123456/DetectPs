//
// Created by y00969037 on 2026/5/19.
//

#include "AmsiDetectModule.h"

#include "MsgIdDefine.h"

#include "AmsiDetectPolicy.h"
#include "AmsiDetectGlobalParam.h"

namespace Engine {
    using namespace Framework;
    using namespace AmsiDetect;

    AmsiDetectModule::AmsiDetectModule() : Module(MODULE_NAME_AMSI_DETECT)
    {
    }

    AmsiDetectModule::~AmsiDetectModule()
    {
        if (m_pDetectTask != nullptr) {
            delete m_pDetectTask;
            m_pDetectTask = nullptr;
        }
    }

    int AmsiDetectModule::Init()
    {
        InfoLogf1(GetLoggerPtr(), "Init module(%s).", MODULE_NAME_AMSI_DETECT);

        RegisterPolicyCallback(FEATURE_POLICY_REFRESH,
                               new PolicyCallback<AmsiDetectModule>(this, &AmsiDetectModule::RefreshFeaturePolicy, false));

        RegisterTaskletCallback(MASTER_CMD_DOWNLOAD_AMSI_LIB,
                                new TaskletCallback<AmsiDetectModule>(this, &AmsiDetectModule::DownloadAmsiFeatureLibrary, true));

        Module::Init();
        return 0;
    }

    void AmsiDetectModule::UnInit()
    {
        UnRegisterPolicyCallback(FEATURE_POLICY_REFRESH);
        UnRegisterTaskletCallback(MASTER_CMD_DOWNLOAD_AMSI_LIB);

        if (m_pDetectTask != nullptr) {
            UnRegisterTask(m_pDetectTask->name());
            InfoLogf1(GetLoggerPtr(), "Unregister task(%s) success.", m_pDetectTask->name());
        }

        Module::UnInit();
        InfoLogf1(GetLoggerPtr(), "UnInit module(%s).", MODULE_NAME_AMSI_DETECT);
    }

    Policy *AmsiDetectModule::RefreshFeaturePolicy(const std::string &featureName, const std::string &policyStr, Framework::Policy *&oldPolicy)
    {
        InfoLogf2(GetLoggerPtr(), "Start to refresh %s policy(%s).", featureName, policyStr);

        auto *featurePolicy = new(std::nothrow) AmsiDetectPolicy(FEATURE_NAME_AMSI_DETECT);
        if (featurePolicy == nullptr) {
            ErrorLog(GetLoggerPtr(), "New amsi policy failed.");
            return featurePolicy;
        }

        if (featurePolicy->Parse(policyStr)) {
            InfoLog(GetLoggerPtr(), "Parse amsi detect policy success.");
            if (FindTask(TASK_NAME_AMSI_DETECT) == nullptr) {
                if (m_pDetectTask == nullptr) {
                    m_pDetectTask = new AmsiDetectTask();
                    m_pDetectTask->duplicate();
                }
                int rv = RegisterTask(m_pDetectTask);
                InfoLogf(GetLoggerPtr(), "Register amsi_detect_task, rv = %d", rv);
            }
        } else {
            ErrorLog(GetLoggerPtr(), "Parse amsi detect policy failed, keep existing amsi task if it is running.");
            featurePolicy->SetRecursiveFree();
            delete featurePolicy;
            featurePolicy = nullptr;
            if (FindTask(TASK_NAME_AMSI_DETECT) != nullptr) {
                UnRegisterTask(m_pDetectTask->name());
                InfoLogf1(GetLoggerPtr(), "Unregister task(%s) success.", m_pDetectTask->name());
            }
        }

        if (oldPolicy != nullptr) {
            oldPolicy->SetRecursiveFree();
        }

        return featurePolicy;
    }

    int AmsiDetectModule::DownloadAmsiFeatureLibrary(const std::string &args)
    {
        InfoLogf1(GetLoggerPtr(), "Recv amsi download msg(%s).", args);

        if (!m_downloadLock.tryLock()) {
            WarningLog(GetLoggerPtr(), "Amsi package download is running, can not repeat.");
            return -1;
        }

        JsonUtils::JsonValue jValue;
        bool parseRight = (JsonUtils::ParseJsonStr(args.c_str(), args.length(), jValue) == 0);
        if (!parseRight) {
            ErrorLogf(GetLoggerPtr(), "Parse download amsi msg (%s) failed.", args);
            m_downloadLock.unlock();
            return -1;
        }

        JsonUtils::JsonValue content;
        if (!JsonUtils::GetSubobjectValue(jValue, "feature_upgrade", content)) {
            ErrorLogf(GetLoggerPtr(), "Get amsi feature_upgrade (%s) failed.", args);
            m_downloadLock.unlock();
            return -1;
        }
        std::string url = JsonUtils::GetStringValue(content, "url");
        std::string hash = JsonUtils::GetStringValue(content, "hash");
        std::string version = JsonUtils::GetStringValue(content, "upgrade_version");

        auto *taskPtr = dynamic_cast<AmsiDetectTask *>(FindTask(TASK_NAME_AMSI_DETECT));
        if (taskPtr == nullptr) {
            ErrorLog(GetLoggerPtr(), "Get amsi task ptr failed.");
            SendAmsiDownloadResponse(version, false, "amsi policy not ready");
            m_downloadLock.unlock();
            return -1;
        }

        int ret = taskPtr->DownloadAmsiPackage(url, hash, version);
        m_downloadLock.unlock();

        return ret;
    }
}

Framework::Module *CreateModule()
{
    return new Engine::AmsiDetectModule();
}
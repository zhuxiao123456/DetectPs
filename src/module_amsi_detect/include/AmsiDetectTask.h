//
// Created by y00969037 on 2026/5/19.
//

#ifndef CSA_ENGINE_AMSI_DETECT_TASK_H
#define CSA_ENGINE_AMSI_DETECT_TASK_H

#include <memory>

#include "LockUtils.h"

#include "CsaTask.h"

#include "AmsiIpcRuntime.h"
#include "AmsiDetectPolicy.h"

namespace Engine {

    class AmsiDetectTask : public Framework::CsaTask {
    public:
        AmsiDetectTask();
        ~AmsiDetectTask() override;

        int Init() override;
        int Run() override;
        void UnInit() override;

        int DownloadAmsiPackage(const std::string &url, const std::string &hash, const std::string &version);

    private:
        bool InitPath();
        int StartCheck();
        bool CheckFileIsExist();
        bool LoadRuleSnapshot(const std::string &rulePath, const std::string &version, AmsiDetect::AmsiRuleSnapshot &snapshot);
        bool ReadAndDescramblingFile(const std::string &srcFilePath, std::string &content);
        bool StartAmsiIpc(const AmsiDetect::AmsiRuleSnapshot &snapshot, std::string &error);
        void StopAmsiIpcIfStarted();
        void SendAmsiDownloadRequest();
        void HandleAmsiVersionInFeatureUpgradeModule(const std::string &version, bool isSet);
        void FirstDownloadPackage();
        void UpgradeDownloadPackage();
        bool DecompressPackage(const std::string &destDir);
        bool ScramblingRules(const std::string &srcRulePath, const std::string &saveRulePath);
        void ClearTmpDirAndSendFailedReason(const std::string &reason);
        bool SaveAmsiLibVersion();
        bool GetAmsiLibVersion();

    private:
        bool m_autoBlock{false};
        std::set<std::string> m_trustProcess;

        // P1 compatibility flag: true means AMSI IPC runtime is started, not AMSI Provider registered.
        bool m_isDetecting{false};
        bool m_isIpcRunning{false};
        bool m_isAmsiRegistered{false};
        bool m_lastReloadBroadcastOk{false};

        // 当前用于检测的AMSI特征库版本.
        std::string m_usingAmsiVersion;
        // 当前处理中的AMSI特征库版本（下载成功，加载中）.
        std::string m_handingAmsiVersion;
        std::string m_localRuleHash;

        std::string m_amsiDir;
        std::string m_amsiTmpDir;
        std::string m_amsiZipPath;
        std::string m_amsiRulePath;
        std::string m_amsiConfPath;
        std::string m_amsiDllFilePath;

        std::unique_ptr<AmsiIpcRuntime> m_amsiIpcRuntime;

        // 保证同一时间只有一个线程操作特征库.
        SDK::LockUtils::MutexLock m_operateAmsiLibLock;
    };
}

#endif //CSA_ENGINE_AMSI_DETECT_TASK_H

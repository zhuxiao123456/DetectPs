//
// Created by y00969037 on 2026/5/19.
//

#include "AmsiDetectTask.h"

#include "CpuCtrlUtils.h"
#include "SystemUtils.h"
#include "DirUtils.h"
#include "HttpUtils.h"
#include "CompressUtils.h"

#include "CsaEngine.h"

#include "ModuleUtils.h"
#include "../../native_module/module_feature_upgrade/include/FeatureUpgradeTask.h"

#include "AmsiDetectGlobalParam.h"
#include "AmsiDetectDllManager.h"

namespace Engine {
    using namespace SDK;
    using namespace Framework;
    using namespace AmsiDetect;

    AmsiDetectTask::AmsiDetectTask() : CsaTask(TASK_NAME_AMSI_DETECT, FEATURE_NAME_AMSI_DETECT,
                                               TaskCondition::TASK_TYPE_ENDLESS_LOOP)
    {
    }

    AmsiDetectTask::~AmsiDetectTask() = default;

    int AmsiDetectTask::Init()
    {
        InfoLogf1(GetLoggerPtr(), "Task(%s) init.", name());

        int osName = SystemUtilsRef.GetOsName();
        if (osName <  SystemUtils::WINDOWS_10 || osName >= SystemUtils::WINDOWS_MAX) {
            InfoLogf1(GetLoggerPtr(), "Unsupported os name (%s).", SystemUtilsRef.GetOsNameDesc());
            return -1;
        }

        bool isRefreshed = false;
        auto *taskPolicy = dynamic_cast<AmsiDetectTaskPolicy *>(this->GetTaskPolicy(isRefreshed));
        if (taskPolicy == nullptr) {
            ErrorLog(GetLoggerPtr(), "Get policy failed.");
            return -1;
        }
        m_autoBlock = taskPolicy->IsAutoBlock();
        m_trustProcess = taskPolicy->GetTrustProcess();

        m_isDetecting = false;
        m_isIpcRunning = false;
        m_isAmsiRegistered = false;
        m_lastReloadBroadcastOk = false;

        if (!InitPath()) {
            return -1;
        }

        StartCheck();

        return CsaTask::Init();
    }

    int AmsiDetectTask::Run()
    {
        GracefulSleep(5);
        return 0;
    }

    void AmsiDetectTask::UnInit()
    {
        // 通知特征库升级模块不再发送AMSI版本.
        HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, false);

        if (m_isDetecting) {
            // 注销AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            amsiDetectDllManager.UnregisterAmsiProvider();

            // 广播通知dll停止检测.

            //  等待所有dll响应.

            // 关闭通信通道
            if (m_isIpcRunning) {
                std::string error;
                if (m_amsiIpcRuntime != nullptr && !m_amsiIpcRuntime->PauseDetection(1000, error)) {
                    WarningLogf1(GetLoggerPtr(), "Pause amsi detection failed during uninit: %s.", error);
                }
                StopAmsiIpcIfStarted();
            }
            // 清理变量

            m_isDetecting = false;
        }

        m_isDetecting = false;
        m_isIpcRunning = false;
        m_isAmsiRegistered = false;
        m_lastReloadBroadcastOk = false;

        m_usingAmsiVersion.clear();
        m_handingAmsiVersion.clear();
        m_localRuleHash.clear();
        m_loadedRuleVersion.clear();

        CsaTask::UnInit();
        InfoLogf1(GetLoggerPtr(), "Task(%s) uninit.", name());
    }

    bool AmsiDetectTask::InitPath()
    {
        std::string installationPath;
        if (PathUtils::GetInstallationPath(installationPath) == -1) {
            ErrorLog(GetLoggerPtr(), "Get installation path failed.");
            return false;
        }
        m_amsiDir = installationPath + "\\data\\amsi\\";
        m_amsiTmpDir =  installationPath + "\\data\\amsi\\tmp\\";
        m_amsiZipPath = m_amsiTmpDir + "HSS_AMSI.zip";
        m_amsiRuleDir = installationPath + "\\data\\amsi\\rules\\";
        m_amsiRulePath = m_amsiRuleDir + "rasp_rules.json";
        m_amsiConfPath = installationPath + "\\data\\amsi\\rules\\version.conf";
        m_amsiDllFilePath = installationPath + "\\data\\amsi\\hss_amsi.dll";
        m_amsiLuaLibPath = m_amsiRuleDir + "lib\\rasp_lib.lua";

        return true;
    }

    void AmsiDetectTask::StartCheck()
    {
        LockUtils::ScopedMutexLock lock(m_operateAmsiLibLock);
        std::string error;

        if(CheckFileIsExist()) {
            InfoLog(GetLoggerPtr(), "Amsi file exist.");

            bool isStartCheckSuccess{false};
            do {
                // 读取AMSI特征库版本.
                if (!GetAmsiLibVersion()) {
                    break;
                }

                // 读取规则.
                AmsiRuleSnapshot snapshot;
                if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, snapshot, error)) {
                    ErrorLogf1(GetLoggerPtr(), "Load amsi rule snapshot failed: %s.", error);
                    return;
                }

                // 预编译规则.

                // 创建通信通道.
                if (!StartAmsiIpc(snapshot, error)) {
                    ErrorLogf1(GetLoggerPtr(), "Start amsi ipc failed: %s.", error);
                    StopAmsiIpcIfStarted();
                    return;
                }

                // 注册AMSI.
//                AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
//                if (!amsiDetectDllManager.RegisterAmsiProvider()) {
//                    break;
//                }

                // 通知已加载的dll重新开始检测.

                m_isDetecting = true;
                m_isIpcRunning = true;
                m_isAmsiRegistered = false;

                // 通知特征库升级模块定时发送AMSI特征库版本.
                m_usingAmsiVersion = m_handingAmsiVersion;
                m_localRuleHash = snapshot.hash;
                m_loadedRuleVersion = snapshot.version;
                m_lastReloadBroadcastOk = false;
                InfoLogf2(GetLoggerPtr(), "Amsi ipc ready, rule version=%s hash=%s.", m_loadedRuleVersion, m_localRuleHash);
                HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

                isStartCheckSuccess = true;
            } while (false);

            if (!isStartCheckSuccess) {
                // 清理AMSI特征库.
                if(DirUtils::DeleteDir(m_amsiDir) != 0){
                    ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
                }
                // 发送AMSI特征库初始版本.
                SendAmsiDownloadRequest();
                // 通知特征库升级模块定时发送AMSI特征库版本.
                HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
            }

        } else {
            InfoLog(GetLoggerPtr(), "Amsi file not exist.");
            // 发送AMSI特征库初始版本.
            SendAmsiDownloadRequest();
            // 通知特征库升级模块定时发送AMSI特征库版本.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
        }

        return;
    }

    bool AmsiDetectTask::CheckFileIsExist()
    {
        if (!FileUtils::IsFile(m_amsiDllFilePath)) {
            InfoLogf1(GetLoggerPtr(), "%s not exist.", m_amsiDllFilePath);
            return false;
        }

        if (!FileUtils::IsFile(m_amsiRulePath)) {
            InfoLogf1(GetLoggerPtr(), "%s not exist.", m_amsiRulePath);
            return false;
        }

        if (!FileUtils::IsFile(m_amsiConfPath)) {
            InfoLogf1(GetLoggerPtr(), "%s not exist.", m_amsiConfPath);
            return false;
        }

        if (!FileUtils::IsFile(m_amsiLuaLibPath)) {
            InfoLogf1(GetLoggerPtr(), "%s not exist, ignored in P1.", m_amsiLuaLibPath);
        }

        return true;
    }

    bool AmsiDetectTask::StartAmsiIpc(const AmsiRuleSnapshot &snapshot, std::string &error)
    {
        AmsiIpcRuntimeConfig config;
        config.amsiIpcEnabled = true;
        config.enableRealIpc = true;
        config.useProductionPipes = true;
        config.requireAmsiDllFile = true;
        config.requireVersionConf = true;
        config.allowLuaLibMissing = true;
        config.dllPath = m_amsiDllFilePath;
        config.rulePath = m_amsiRulePath;
        config.versionPath = m_amsiConfPath;
        config.luaLibPath = m_amsiLuaLibPath;
        config.version = snapshot.version;

        if (m_amsiIpcRuntime == nullptr) {
            m_amsiIpcRuntime.reset(new AmsiIpcRuntime());
        }

        if (!m_amsiIpcRuntime->Init(config, error)) {
            return false;
        }

        if (!m_amsiIpcRuntime->Start(snapshot, error)) {
            return false;
        }

        InfoLog(GetLoggerPtr(), "Amsi ipc started with production pipes.");
        return true;
    }

    void AmsiDetectTask::StopAmsiIpcIfStarted()
    {
        if (m_amsiIpcRuntime == nullptr) {
            m_isIpcRunning = false;
            return;
        }

        std::string error;
        if (!m_amsiIpcRuntime->Stop(3000, error)) {
            WarningLogf1(GetLoggerPtr(), "Stop amsi ipc failed: %s.", error);
        }
        m_isIpcRunning = false;
    }

    void AmsiDetectTask::FailStartAndRequestDownload(const std::string &reason)
    {
        WarningLogf1(GetLoggerPtr(), "Amsi start check failed: %s.", reason);
        StopAmsiIpcIfStarted();
        SendAmsiDownloadRequest();
        HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
    }

    void AmsiDetectTask::SendAmsiDownloadRequest()
    {
        JsonUtils::JsonValue jMsg;
        JsonUtils::JsonValue info;
        info["name"] = "HSS_AMSI";
        info["current_version"] = "2022010101";
        jMsg["feature_collect"].append(info);
        std::string jsonStr = JsonUtils::JsonToString(jMsg);

        bool ret = SendCmdMessage(AGENT_AMSI_LIB_VERSION, jsonStr);
        InfoLogf3(GetLoggerPtr(), "Send msg id=%s, content=(%s), ret(%s).", AGENT_AMSI_LIB_VERSION, jsonStr, BOOL_TO_STR(ret));
    }

    void AmsiDetectTask::HandleAmsiVersionInFeatureUpgradeModule(const std::string &version, bool isSet)
    {
        FeatureUpgradeTask *pFeatureTask = (FeatureUpgradeTask *) CsaEngineRef.FindTask("feature_upgrade_task");
        if (pFeatureTask == nullptr) {
            ErrorLog(GetLoggerPtr(), "Get feature_upgrade_task ptr failed." );
            return;
        }

        if (isSet) {
            pFeatureTask->SetTmpLibNameAndVersion("HSS_AMSI", version);
        } else {
            pFeatureTask->EraseTmpLibNameAndVersion("HSS_AMSI");
        }

        return;
    }

    int AmsiDetectTask::DownloadAmsiPackage(const std::string &url, const std::string &hash, const std::string &version)
    {
        int osName = SystemUtilsRef.GetOsName();
        if (osName <  SystemUtils::WINDOWS_10 || osName >= SystemUtils::WINDOWS_MAX) {
            SendAmsiDownloadResponse(version, false, "os version unsupported amsi");
            InfoLogf1(GetLoggerPtr(), "(%s) unsupported amsi, send amsi download failed msg.", SystemUtilsRef.GetOsNameDesc());
            return -1;
        }

        LockUtils::ScopedMutexLock lock(m_operateAmsiLibLock);

        if (!DirUtils::IsDir(m_amsiTmpDir)) {
            if (DirUtils::MakeDirs(m_amsiTmpDir, S_IRWXU | S_IRWXG | S_IRWXO) == 0) {
                InfoLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) success.", m_amsiTmpDir);
            } else {
                ErrorLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) failed.", m_amsiTmpDir);
                SendAmsiDownloadResponse(version, false, "create amsi tmp dir failed");
                return -1;
            }
        }

        int httpCode = HttpUtilsRef.Download(url, m_amsiZipPath, hash);
        if (httpCode != Poco::Net::HTTPResponse::HTTPStatus::HTTP_OK) {
            ErrorLogf2(GetLoggerPtr(), "Download amsi package failed, url=%s, hash=%s.", url, hash);
            SendAmsiDownloadResponse(version, false, "download package failed");
            return -1;
        } else {
            InfoLogf2(GetLoggerPtr(), "Download amsi package success, url=%s, hash=%s.", url, hash);
            SendAmsiDownloadResponse(version, true, "");
        }
        m_handingAmsiVersion = version;

        if (!m_isDetecting) {  // 首次下载AMSI特征库.
            FirstDownloadPackage();
        } else { // 更新AMSI特征库.
            UpgradeDownloadPackage();
        }

        return 0;
    }

    void AmsiDetectTask::FirstDownloadPackage()
    {
        // 解压特征库.
        if (!DecompressPackage(m_amsiTmpDir)) {
            return;
        }

        bool isStartCheckSuccess{false};
        do {
            // 读取规则.

            // 预编译规则.

            // 创建通信通道.

            // 保存规则和脚本、dll到amsi目录，删除tmp目录下的内容.

            // 注册AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            if (!amsiDetectDllManager.RegisterAmsiProvider()) {
                break;
            }

            isStartCheckSuccess = true;
        } while (false);

        if (!isStartCheckSuccess) {
            // 清理AMSI特征库.
            if(DirUtils::DeleteDir(m_amsiDir) != 0){
                ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
            }
            // 发送AMSI特征库初始版本.
            SendAmsiDownloadRequest();
            // 通知特征库升级模块定时发送AMSI特征库版本.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
        } else {
            m_isDetecting = true;
            m_usingAmsiVersion = m_handingAmsiVersion;
            // 保存AMSI特征库版本.
            SaveAmsiLibVersion();
            // 通知特征库升级模块定时发送AMSI特征库版本.
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);
        }

        return;
    }

    void AmsiDetectTask::UpgradeDownloadPackage()
    {
        // 解压特征库.
        if (!DecompressPackage(m_amsiTmpDir)) {
            return;
        }

        // 读取规则.

        // 预编译规则.

        // 升级dll.

        // 保存规则和脚本到amsi目录，删除tmp目录下的内容.

        // 广播规则更新消息通知已加载的dll使用新规则.

        m_usingAmsiVersion = m_handingAmsiVersion;
        // 保存AMSI特征库版本.
        SaveAmsiLibVersion();
        // 通知特征库升级模块定时发送AMSI特征库版本.
        HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

        return;
    }

    bool AmsiDetectTask::DecompressPackage(const std::string &destDir)
    {
        bool ret;
        if (CompressUtils::DecompressDirectory(m_amsiZipPath, destDir) != 0) {
            ErrorLogf2(GetLoggerPtr(), "Decompress (%s) to (%s) failed.", m_amsiZipPath, destDir);
            SendAmsiDownloadResponse(m_handingAmsiVersion, false, "decompress package failed");
            ret = false;
        } else {
            InfoLogf2(GetLoggerPtr(), "Decompress (%s) to (%s) success.", m_amsiZipPath, destDir);
            ret = true;
        }

        if (FileUtils::CsaDeleteFile(m_amsiZipPath) != 0) {
            ErrorLogf2(GetLoggerPtr(), "Delete (%s) failed, errno(%d).", m_amsiZipPath, errno);
        }

        return ret;
    }

    bool AmsiDetectTask::SaveAmsiLibVersion()
    {
       int ret = FileUtils::WriteFile(m_amsiConfPath, m_usingAmsiVersion, false);
        if (ret != 0) {
            ErrorLogf3(GetLoggerPtr(), "Write amsi lib version (%s) to (%s) failed, ret(%d).", m_usingAmsiVersion, m_amsiConfPath, ret);
            return false;
        } else {
            InfoLogf2(GetLoggerPtr(), "Write amsi lib version (%s) to (%s) success.", m_usingAmsiVersion, m_amsiConfPath);
            return true;
        }
    }

    bool AmsiDetectTask::GetAmsiLibVersion()
    {
        int ret = FileUtils::ReadFile(m_amsiConfPath, m_handingAmsiVersion);
        if (ret != 0) {
            ErrorLogf2(GetLoggerPtr(), "Read amsi lib version from (%s) failed, ret(%d).", m_amsiConfPath, ret);
            return false;
        } else {
            InfoLogf2(GetLoggerPtr(), "Read amsi lib version (%s) from (%s) success.", m_handingAmsiVersion, m_amsiConfPath);
            return true;
        }
    }

}
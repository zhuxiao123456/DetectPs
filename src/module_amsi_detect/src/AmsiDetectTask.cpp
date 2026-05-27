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
#include "DataScrambling.h"

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

        if (StartCheck() != 0) {
            return -1;
        }

        return CsaTask::Init();
    }

    int AmsiDetectTask::Run()
    {
        GracefulSleep(5);
        return 0;
    }

    void AmsiDetectTask::UnInit()
    {
        InfoLogf1(GetLoggerPtr(), "Task(%s) uninit begin.", name());
        // 通知特征库升级模块不再发送AMSI版本.
        if (!m_usingAmsiVersion.empty()) {
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, false);
        }

        if (m_isDetecting) {
            // 如果dll注册成功则卸�?
            if (m_isAmsiRegistered) {
                AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
                if (!amsiDetectDllManager.UnregisterAmsiProvider()) {
                    WarningLog(GetLoggerPtr(), "Unregister amsi provider failed during uninit.");
                }
                m_isAmsiRegistered = false;
            }

            // 广播通知dll停止检�?0x03)，等待所有dll响应，关闭通信通道; 需要添加ack信息
            if (m_isIpcRunning) {
                std::string error;
                if (m_amsiIpcRuntime != nullptr && !m_amsiIpcRuntime->PauseDetection(1000, error)) {
                    WarningLogf1(GetLoggerPtr(), "Pause amsi detection failed during uninit: %s.", error);
                }
                if (m_amsiIpcRuntime != nullptr) {
                    const AmsiIpcBroadcastSummary summary = m_amsiIpcRuntime->GetLastBroadcastSummary("pause");
                    InfoLogf1(GetLoggerPtr(), "Pause amsi detection broadcast reached=%lu.",
                              static_cast<unsigned long>(summary.reached));
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

    bool AmsiDetectTask::InitPath() {
        std::string installationPath;
        if (PathUtils::GetInstallationPath(installationPath) == -1) {
            ErrorLog(GetLoggerPtr(), "Get installation path failed.");
            return false;
        }
        m_amsiDir = installationPath + "data\\amsi\\";
        m_amsiTmpDir = installationPath + "data\\amsi\\tmp\\";
        m_amsiZipPath = m_amsiTmpDir + "HSS_AMSI.zip";
        m_amsiRuleDir = installationPath + "data\\amsi\\rules\\";
        m_amsiRulePath = m_amsiRuleDir + "rasp_rules.json";
        m_amsiConfPath = installationPath + "data\\amsi\\rules\\version.conf";
        m_amsiDllFilePath = installationPath + "data\\amsi\\hss_amsi.dll";
        m_amsiLuaLibPath = m_amsiRuleDir + "lib\\rasp_lib.lua";

        return true;
    }

    int AmsiDetectTask::StartCheck()
    {
        LockUtils::ScopedMutexLock lock(m_operateAmsiLibLock);

        if(!CheckFileIsExist()) {
            // 特征库不完整时，清理AMSI特征�?
            if (DirUtils::IsDir(m_amsiDir)) {
                if(DirUtils::DeleteDir(m_amsiDir) != 0){
                    ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
                }
            }

            // 发送AMSI特征库初始版�?
            SendAmsiDownloadRequest();
            // 通知特征库升级模块定时发送AMSI特征库版�?
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
            return 0;
        }

        InfoLog(GetLoggerPtr(), "Amsi file exist.");
        std::string error;
        bool isStartCheckSuccess{false};
        do {
            // 读取AMSI特征库版�?
            if (!GetAmsiLibVersion()) {
                break;
            }

            // 读取规则.
            AmsiRuleSnapshot snapshot;
            if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Load amsi rule snapshot failed: %s.", error);
                break;
            }

            // 预编译规�? todo

            // 创建通信通道.
            if (!StartAmsiIpc(snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc failed: %s.", error);
                StopAmsiIpcIfStarted();
                return -1;
            }
            m_isIpcRunning = true;
            m_localRuleHash = snapshot.hash;
            m_loadedRuleVersion = snapshot.version;
            InfoLogf2(GetLoggerPtr(), "Amsi ipc ready, rule version=%s hash=%s.", m_loadedRuleVersion, m_localRuleHash);

            // 注册AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            if (!amsiDetectDllManager.RegisterAmsiProvider()) {
                return -1;
            }
            m_isAmsiRegistered = true;

            // 通知已加载的dll重新开始检�?先开始检测在广播最新规�?
            m_lastReloadBroadcastOk = false;
            error.clear();
            bool resumeBroadcastOk = true;
            if (m_amsiIpcRuntime != nullptr) {
                resumeBroadcastOk = m_amsiIpcRuntime->ResumeDetection(1000, error);
                const AmsiIpcBroadcastSummary summary = m_amsiIpcRuntime->GetLastBroadcastSummary("resume");
                if (!resumeBroadcastOk && !(summary.reached == 0 && summary.lastError == 2)) {
                    WarningLogf1(GetLoggerPtr(), "Broadcast amsi resume during start check failed: %s.", error);
                }
                InfoLogf2(GetLoggerPtr(), "Resume amsi detection broadcast reached=%lu lastError=%lu.",
                          static_cast<unsigned long>(summary.reached),
                          static_cast<unsigned long>(summary.lastError));
            }
            error.clear();
            bool reloadBroadcastOk = false;
            if (m_amsiIpcRuntime != nullptr) {
                reloadBroadcastOk = m_amsiIpcRuntime->Reload(3000, error);
                const AmsiIpcBroadcastSummary summary = m_amsiIpcRuntime->GetLastBroadcastSummary("reload");
                if (!reloadBroadcastOk && !(summary.reached == 0 && summary.lastError == 2)) {
                    WarningLogf1(GetLoggerPtr(), "Broadcast amsi reload during start check failed: %s.", error);
                }
                InfoLogf2(GetLoggerPtr(), "Reload amsi rules broadcast reached=%lu lastError=%lu.",
                          static_cast<unsigned long>(summary.reached),
                          static_cast<unsigned long>(summary.lastError));
            }
            if (reloadBroadcastOk) {
                m_lastReloadBroadcastOk = true;
            }
            m_isDetecting = true;

            // 通知特征库升级模块定时发送AMSI特征库版�?
            m_usingAmsiVersion = m_handingAmsiVersion;
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

            isStartCheckSuccess = true;
        } while (false);

        if (!isStartCheckSuccess) {
            // 清理AMSI特征�?
            if(DirUtils::DeleteDir(m_amsiDir) != 0){
                ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
            }
            // 发送AMSI特征库初始版�?
            SendAmsiDownloadRequest();
            // 通知特征库升级模块定时发送AMSI特征库版�?
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
        }

        return 0;
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
            InfoLogf1(GetLoggerPtr(), "%s not exist.", m_amsiLuaLibPath);
        }

        return true;
    }

    bool AmsiDetectTask::ReadAndDescramblingFile(const std::string &srcFilePath, std::string &content)
    {
        FileUtils::ReadFile(srcFilePath, content);
        if (content.empty()) {
            ErrorLogf1(GetLoggerPtr(), "Read file(%s) failed.", srcFilePath)
            return false;
        }

        std::string scramblingStr;
        int ret = DataScrambling::Descrambling(content, scramblingStr);
        if (ret != 0) {
            ErrorLogf2(GetLoggerPtr(), "Descrambling file(%s) failed, ret(%d).", srcFilePath, ret)
            return false;
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
        // 如果操作系统不支持AMSI，直接发送下载失败消�?
        int osName = SystemUtilsRef.GetOsName();
        if (osName <  SystemUtils::WINDOWS_10 || osName >= SystemUtils::WINDOWS_MAX) {
            SendAmsiDownloadResponse(version, false, "os version unsupported amsi");
            InfoLogf1(GetLoggerPtr(), "(%s) unsupported amsi, send amsi download failed msg.", SystemUtilsRef.GetOsNameDesc());
            return -1;
        }

        LockUtils::ScopedMutexLock lock(m_operateAmsiLibLock);

        // 检查临时下载目录是否存�? 不存在则创建目录.
        if (!DirUtils::IsDir(m_amsiTmpDir)) {
            if (DirUtils::MakeDirs(m_amsiTmpDir, S_IRWXU | S_IRWXG | S_IRWXO) == 0) {
                InfoLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) success.", m_amsiTmpDir);
            } else {
                ErrorLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) failed.", m_amsiTmpDir);
                SendAmsiDownloadResponse(version, false, "create amsi tmp dir failed");
                return -1;
            }
        }

        // 下载AMSI特征�?
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

        if (!m_isDetecting) {  // 首次下载AMSI特征�?
            FirstDownloadPackage();
        } else { // 更新AMSI特征�?
            UpgradeDownloadPackage();
        }

        return 0;
    }

    void AmsiDetectTask::FirstDownloadPackage()
    {
        // 解压特征�?
        if (!DecompressPackage(m_amsiTmpDir)) {
            return;
        }

        bool isStartCheckSuccess{false};
        do {
            // 加扰规则.
            if (!ScramblingRules()) {
                // 发送新库应用失败原�?
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "scrambling rules failed");
                break;
            }

            // 保存dll到amsi目录.
            std::string tmpDllPath = m_amsiTmpDir + "hss_amsi.dll";
            int ret = FileUtils::CsaCopyFile(tmpDllPath, m_amsiDllFilePath);
            if (ret != 0) {
                ErrorLogf3(GetLoggerPtr(), "Copy (%s) to (%s) failed, ret(%d).", tmpDllPath, m_amsiDllFilePath, ret);
                // 发送新库应用失败原�?
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "save amsi dll failed");
                break;
            }

            // 读取规则,后续直接将读取的规则传递给快照snapshot即可
            std::string error;
            AmsiRuleSnapshot snapshot;
            if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Load amsi rule snapshot failed: %s.", error);
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "load rule snapshot failed");
                break;
            }

            // 预编译规�?后续预编译snapshot中的规则

            // 创建通信通道.
            if (!StartAmsiIpc(snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc failed: %s.", error);
                StopAmsiIpcIfStarted();
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "start amsi ipc failed");
                break;
            }
            m_isIpcRunning = true;
            m_localRuleHash = snapshot.hash;
            m_loadedRuleVersion = snapshot.version;
            InfoLogf2(GetLoggerPtr(), "Amsi ipc ready, rule version=%s hash=%s.", m_loadedRuleVersion, m_localRuleHash);

            // 保存规则和脚本到amsi目录.
            SaveRules();

            // 注册AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            if (!amsiDetectDllManager.RegisterAmsiProvider()) {
                StopAmsiIpcIfStarted();  // 注册失败,关闭相关通道
                break;
            }

            isStartCheckSuccess = true;
        } while (false);

        if (!isStartCheckSuccess) {
            // 清理AMSI特征�?
            if(DirUtils::DeleteDir(m_amsiDir) != 0){
                ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
            }
            // 通知特征库升级模块定时发送AMSI特征库版�?
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
        } else {
            m_isDetecting = true;
            m_usingAmsiVersion = m_handingAmsiVersion;
            // 保存AMSI特征库版�?
            SaveAmsiLibVersion();
            // 通知特征库升级模块定时发送AMSI特征库版�?
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);
        }

        return;
    }

    void AmsiDetectTask::UpgradeDownloadPackage()
    {
        // 解压特征�?
        if (!DecompressPackage(m_amsiTmpDir)) {
            return;
        }

        // 加扰规则.
        if (!ScramblingRules()) {
            ClearTmpDirAndSendFailedReason("scrambling rules failed");
            return;
        }

        // 读取规则，将读取的规则传递给finalSnapshot即可
        std::string error;
        AmsiRuleSnapshot finalSnapshot;
        if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, finalSnapshot, error)) {
            ErrorLogf1(GetLoggerPtr(), "Load final amsi rule snapshot failed: %s.", error);
            ClearTmpDirAndSendFailedReason("load final rule snapshot failed");
            return;
        }

        // 预编译规�?

        // 升级dll.
        AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
        std::string stagingDllPath = m_amsiTmpDir + "hss_amsi.dll";
        int ret = amsiDetectDllManager.UpdateAmsiDll(stagingDllPath); // 重启替换场景需要保留tmp目录里的dll，所以不删除�?
        if (ret < 0) {
            ClearTmpDirAndSendFailedReason("update dll failed");
            return;
        }

        // 保存规则和脚本到amsi目录.
        SaveRules();

        // 广播规则更新消息通知已加载的dll使用新规则，如果没有开启通道则创�? 之后更新provider中的规则快照内容
        if (m_amsiIpcRuntime == nullptr || !m_isIpcRunning) {
            if (!StartAmsiIpc(finalSnapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc during upgrade failed: %s.", error);
                StopAmsiIpcIfStarted();
                ClearTmpDirAndSendFailedReason("start amsi ipc failed");
                return;
            }
            m_isIpcRunning = true;
        } else if (!m_amsiIpcRuntime->UpdateRules(finalSnapshot, error)) {
            ErrorLogf1(GetLoggerPtr(), "Update amsi ipc rules failed: %s.", error);
            ClearTmpDirAndSendFailedReason("update ipc rules failed");
            return;
        }
        m_localRuleHash = finalSnapshot.hash;
        m_loadedRuleVersion = finalSnapshot.version;
        m_lastReloadBroadcastOk = false;
        // 广播新规�?
        if (m_amsiIpcRuntime != nullptr && m_isIpcRunning) {
            if (!m_amsiIpcRuntime->Reload(3000, error)) {
                WarningLogf1(GetLoggerPtr(), "Broadcast amsi reload failed: %s.", error);
            } else {
                m_lastReloadBroadcastOk = true;
            }
            {
                const AmsiIpcBroadcastSummary summary = m_amsiIpcRuntime->GetLastBroadcastSummary("reload");
                InfoLogf1(GetLoggerPtr(), "Reload amsi rules broadcast reached=%lu.",
                          static_cast<unsigned long>(summary.reached));
            }
        }

        m_usingAmsiVersion = m_handingAmsiVersion;
        // 保存AMSI特征库版�?
        SaveAmsiLibVersion();
        // 通知特征库升级模块定时发送AMSI特征库版�?
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

        // 删除压缩�?
        if (FileUtils::CsaDeleteFile(m_amsiZipPath) != 0) {
            ErrorLogf2(GetLoggerPtr(), "Delete (%s) failed, errno(%d).", m_amsiZipPath, errno);
        }

        return ret;
    }

    bool AmsiDetectTask::ScramblingRules()
    {
        // 遍历rules并加�?
        std::string tmpRulesPath = m_amsiTmpDir + "\\rules\\";
        if (!TraverseDirAndScrambling(tmpRulesPath)) {
            return false;
        }

        // 遍历rules\lib并加�?
        std::string tmpRulesLibPath = m_amsiTmpDir + "\\rules\\lib\\";
        if (!TraverseDirAndScrambling(tmpRulesLibPath)) {
            return false;
        }

        return true;
    }

    bool AmsiDetectTask::TraverseDirAndScrambling(const std::string &srcDir)
    {
        std::vector<std::string> fileList = DirUtils::GetFilesInDir(srcDir);
        if (fileList.empty()) {
            ErrorLogf1(GetLoggerPtr(), "Dir(%s) no file.", srcDir);
            return false;
        }

        for (const auto &filePath: fileList) {
            // 对文件进行加扰处�?
            if (!FileUtils::IsFile(filePath)) {
                continue;
            }

            std::string content;
            int ret = FileUtils::ReadFile(filePath, content);
            if (ret != 0 || content.empty()) {
                ErrorLogf2(GetLoggerPtr(), "Read  file(%s) failed, ret(%d).", filePath, ret)
                return false;
            }

            std::string scramblingStr;
            DebugLogf(GetLoggerPtr(), "Scrambling filePath: [%s]", filePath);
            ret = DataScrambling::Scrambling(content, scramblingStr);
            if (ret != 0) {
                ErrorLogf2(GetLoggerPtr(), "Scrambling file(%s) failed, ret(%d)", filePath, ret)
                return false;
            }

            ret = FileUtils::WriteFile(filePath,  scramblingStr, false);
            if (ret != 0) {
                ErrorLogf2(GetLoggerPtr(), "Write file(%s) failed, errno(%d).", filePath, errno)
                return false;
            } else {
                InfoLogf1(GetLoggerPtr(), "Scrambling file(%s) success.", filePath);
            }
        }

        return true;
    }

    void AmsiDetectTask::SaveRules()
    {
        if (DirUtils::DeleteDir(m_amsiRuleDir) != 0) {
            WarningLogf1(GetLoggerPtr(), "Delete dir(%s) failed.", m_amsiRuleDir);
        }
        std::string tmpRulesPath = m_amsiTmpDir + "\\rules\\";
        if (DirUtils::CopyDir(tmpRulesPath, m_amsiRuleDir) != 0) {
            ErrorLogf2(GetLoggerPtr(), "Copy (%s) to (%s) failed.", tmpRulesPath, m_amsiRuleDir);
            // 保存新规则失败不处理，下次task重启自然会重新下载特征库.
        } else {
            InfoLogf2(GetLoggerPtr(), "Copy (%s) to (%s) success.", tmpRulesPath, m_amsiRuleDir);
        }
        if (DirUtils::DeleteDir(tmpRulesPath) != 0) {
            WarningLogf1(GetLoggerPtr(), "Delete dir(%s) failed.", tmpRulesPath);
        }
    }

    void AmsiDetectTask::ClearTmpDirAndSendFailedReason(const std::string &reason)
    {
        // 清理AMSI特征库临时目�?
        if(DirUtils::DeleteDir(m_amsiTmpDir) != 0){
            ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiTmpDir);
        }

        // 发送新库应用失败原�?
        SendAmsiDownloadResponse(m_handingAmsiVersion, false, reason);

        return;
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
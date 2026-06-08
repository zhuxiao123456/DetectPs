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

    namespace {

        bool FillRequiredDllHash(const std::string &dllPath, AmsiRuleSnapshot &snapshot) {
            std::string dllHash;
            if (FileUtils::GetFileSha256(dllPath, dllHash) != 0) {
                ErrorLogf1(GetLoggerPtr(), "Failed to get amsi dll hash from (%s).", dllPath);
                return false;
            }
            snapshot.requiredDllHash = dllHash;
            return true;
        }
        std::string BuildRunningStateEnvelope(const SDK::JsonUtils::JsonValue &rulesJson, const std::string &version) {
            SDK::JsonUtils::JsonValue envelope;
            envelope["desiredRuntimeState"] = "running";
            envelope["state"] = "running";
            envelope["stateVersion"] = version;
            envelope["ruleVersion"] = version;
            envelope["rules"] = rulesJson;
            return SDK::JsonUtils::JsonToString(envelope);
        }
    }


    AmsiDetectTask::AmsiDetectTask() : CsaTask(TASK_NAME_AMSI_DETECT, FEATURE_NAME_AMSI_DETECT,
                                               TaskCondition::TASK_TYPE_ENDLESS_LOOP) {
    }

    AmsiDetectTask::~AmsiDetectTask() = default;

    int AmsiDetectTask::Init() {
        InfoLogf1(GetLoggerPtr(), "Task(%s) init.", name());

        // 获取系统已经运行的毫秒数.
        uint64_t ms = GetTickCount64();
       if(ms <= 60000) { // 系统启动时间小于60s, 等待一分钟系统稳定.
           GracefulSleep(60);
       }

        int osName = SystemUtilsRef.GetOsName();
        if (osName < SystemUtils::WINDOWS_10 || osName >= SystemUtils::WINDOWS_MAX) {
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
        m_maxScanContentBytes = taskPolicy->GetMaxScanContentBytes();
        m_trustProcess = taskPolicy->GetTrustProcess();

        m_isDetecting = false;
        m_isIpcRunning = false;
        m_isAmsiRegistered = false;

        if (!InitPath()) {
            return -1;
        }

        if (StartCheck() != 0) {
            return -1;
        }

        return CsaTask::Init();
    }

    int AmsiDetectTask::Run() {
        GracefulSleep(5);
        return 0;
    }

    void AmsiDetectTask::UnInit() {
        InfoLogf1(GetLoggerPtr(), "Task(%s) uninit begin.", name());
        // 通知特征库升级模块不再发送AMSI版本.
        HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, false);

        if (m_isDetecting) {
            // 如果dll注册成功则卸载
            if (m_isAmsiRegistered) {
                AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
                if (!amsiDetectDllManager.UnregisterAmsiProvider()) {
                    WarningLog(GetLoggerPtr(), "Unregister amsi provider failed during uninit.");
                }
            }
            // 如果通道开启，则关闭.
            if (m_isIpcRunning) {
                StopAmsiIpcIfStarted();
            }
        }

        // 清理变量.
        m_isDetecting = false;
        m_isIpcRunning = false;
        m_isAmsiRegistered = false;

        m_usingAmsiVersion.clear();
        m_handingAmsiVersion.clear();
        m_localRuleHash.clear();

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
        m_amsiTmpDir = m_amsiDir + "tmp\\";
        m_amsiZipPath = m_amsiTmpDir + "HSS_AMSI.zip";
        m_amsiRulePath = m_amsiDir + "amsi_rules.json";
        m_amsiConfPath = m_amsiDir + "version.conf";
        m_amsiDllFilePath = m_amsiDir + "hss_amsi.dll";

        return true;
    }

    int AmsiDetectTask::StartCheck() {
        LockUtils::ScopedMutexLock lock(m_operateAmsiLibLock);

        if (!CheckFileIsExist()) {
            // 特征库不完整时，清理AMSI特征库.
            if (DirUtils::IsDir(m_amsiDir)) {
                if (DirUtils::DeleteDir(m_amsiDir) != 0) {
                    ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
                }
            }

            // 发送AMSI特征库初始版本.
            SendAmsiDownloadRequest();
            // 通知特征库升级模块定时发送AMSI特征库版本.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
            return 0;
        }

        InfoLog(GetLoggerPtr(), "Amsi file exist.");
        bool isStartCheckSuccess{false};
        do {
            // 读取AMSI特征库版本.
            if (!GetAmsiLibVersion()) {
                break;
            }

            // 读取规则.
            AmsiRuleSnapshot snapshot;
            if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, snapshot)) {
                break;
            }
            if (!FillRequiredDllHash(m_amsiDllFilePath, snapshot)) {
                break;
            }

            // 创建通信通道.
            std::string error;
            if (!StartAmsiIpc(snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc failed: %s.", error);
                StopAmsiIpcIfStarted();
                return -1;
            }
            m_isIpcRunning = true;
            InfoLogf1(GetLoggerPtr(), "Amsi ipc ready, rule version=%s.", snapshot.version);

            // 注册AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            if (!amsiDetectDllManager.RegisterAmsiProvider()) {
                return -1;
            }
            m_isAmsiRegistered = true;
            m_isDetecting = true;

            // 通知特征库升级模块定时发送AMSI特征库版本.
            m_usingAmsiVersion = m_handingAmsiVersion;
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

            isStartCheckSuccess = true;
        } while (false);

        if (!isStartCheckSuccess) {
            // 清理AMSI特征库.
            if (DirUtils::DeleteDir(m_amsiDir) != 0) {
                ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
            }
            // 发送AMSI特征库初始版本.
            SendAmsiDownloadRequest();
            // 通知特征库升级模块定时发送AMSI特征库版本.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
        } else {
            // 如果曾经升级时备份文件未成功删除，那么尝试删除一次（无进程加载旧dll即可成功删除）.
            std::string backup = m_amsiDllFilePath + ".bak";
            if (FileUtils::IsFile(backup)) {
                int ret = FileUtils::CsaDeleteFile(backup);
                InfoLogf2(GetLoggerPtr(), "Delete (%s), ret(%d).", backup, ret);
            }
        }

        return 0;
    }

    bool AmsiDetectTask::CheckFileIsExist() {
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

        return true;
    }

    bool AmsiDetectTask::LoadRuleSnapshot(const std::string &rulePath, const std::string &version,
                                          AmsiDetect::AmsiRuleSnapshot &snapshot) {
        std::string content;
        if (!ReadAndDescramblingFile(rulePath, content)) {
            return false;
        }

        SDK::JsonUtils::JsonValue ruleJson;
        if (SDK::JsonUtils::ParseJsonStr(content.c_str(), content.length(), ruleJson) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Parse rule json(%s) failed.", rulePath)
            return false;
        }
        ruleJson["version"] = version;

        // 加入策略里的配置.
        if (m_autoBlock) {
            ruleJson["globalMode"] = "block";
        } else {
            ruleJson["globalMode"] = "audit";
        }
        ruleJson["maxScanContentBytes"] = m_maxScanContentBytes;

        if (!m_trustProcess.empty()) {
            JsonUtils::JsonValue trustProcessJson;
            if (!JsonUtils::GetArrayValue(ruleJson, "trust_process", trustProcessJson)) {
                WarningLog(GetLoggerPtr(), "Rule json no trust_process.")
            }
            for (const auto &item: m_trustProcess) {
                trustProcessJson.append(item);
            }
            ruleJson["trust_process"] = trustProcessJson;
        }

        std::string assembledRules = BuildRunningStateEnvelope(ruleJson, version);
        snapshot.amsiRulesJson = assembledRules;
        snapshot.version = version;
        InfoLog(GetLoggerPtr(), "Load rule success.")

        return true;
    }

    bool AmsiDetectTask::ReadAndDescramblingFile(const std::string &srcFilePath, std::string &content) {
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

        if(scramblingStr.empty() || scramblingStr[0] != '{') {
            ErrorLogf1(GetLoggerPtr(), "Descrambling file(%s) content not a json.", srcFilePath)
            return false;
        }

        content = scramblingStr;

        return true;
    }

    bool AmsiDetectTask::StartAmsiIpc(const AmsiRuleSnapshot &snapshot, std::string &error) {
        AmsiIpcRuntimeConfig config;
        config.amsiIpcEnabled = true;
        config.enableRealIpc = true;
        config.useProductionPipes = true;
        config.dllPath = m_amsiDllFilePath;
        config.rulePath = m_amsiRulePath;
        config.versionPath = m_amsiConfPath;
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

    void AmsiDetectTask::StopAmsiIpcIfStarted() {
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

    void AmsiDetectTask::SendAmsiDownloadRequest() {
        JsonUtils::JsonValue jMsg;
        JsonUtils::JsonValue info;
        info["name"] = "HSS_AMSI";
        info["current_version"] = "2022010101";
        jMsg["feature_collect"].append(info);
        std::string jsonStr = JsonUtils::JsonToString(jMsg);

        bool ret = SendCmdMessage(AGENT_AMSI_LIB_VERSION, jsonStr);
        InfoLogf3(GetLoggerPtr(), "Send msg id=%s, content=(%s), ret(%s).", AGENT_AMSI_LIB_VERSION, jsonStr,
                  BOOL_TO_STR(ret));
    }

    void AmsiDetectTask::HandleAmsiVersionInFeatureUpgradeModule(const std::string &version, bool isSet) {
        FeatureUpgradeTask *pFeatureTask = (FeatureUpgradeTask *) CsaEngineRef.FindTask("feature_upgrade_task");
        if (pFeatureTask == nullptr) {
            ErrorLog(GetLoggerPtr(), "Get feature_upgrade_task ptr failed.");
            return;
        }

        if (isSet) {
            pFeatureTask->SetTmpLibNameAndVersion("HSS_AMSI", version);
        } else {
            pFeatureTask->EraseTmpLibNameAndVersion("HSS_AMSI");
        }

        return;
    }

    int
    AmsiDetectTask::DownloadAmsiPackage(const std::string &url, const std::string &hash, const std::string &version) {
        // 如果操作系统不支持AMSI，直接发送下载失败消息.
        int osName = SystemUtilsRef.GetOsName();
        if (osName < SystemUtils::WINDOWS_10 || osName >= SystemUtils::WINDOWS_MAX) {
            SendAmsiDownloadResponse(version, false, "os version unsupported amsi");
            InfoLogf1(GetLoggerPtr(), "(%s) unsupported amsi, send amsi download failed msg.",
                      SystemUtilsRef.GetOsNameDesc());
            return -1;
        }

        LockUtils::ScopedMutexLock lock(m_operateAmsiLibLock);

        // 如果版本已应用，不重复下载.
        if (m_usingAmsiVersion == version) {
            InfoLogf1(GetLoggerPtr(), "Amsi package version(%s) is using, not repeat download.", m_usingAmsiVersion);
            SendAmsiDownloadResponse(version, true, "");
            return 0;
        }

        // 检查临时下载目录是否存在, 不存在则创建目录.
        if (!DirUtils::IsDir(m_amsiTmpDir)) {
            if (DirUtils::MakeDirs(m_amsiTmpDir, S_IRWXU | S_IRWXG | S_IRWXO) == 0) {
                InfoLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) success.", m_amsiTmpDir);
            } else {
                ErrorLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) failed.", m_amsiTmpDir);
                SendAmsiDownloadResponse(version, false, "create amsi tmp dir failed");
                return -1;
            }
        }

        // 下载AMSI特征库.
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

        // 解压特征库.
        if (!DecompressPackage(m_amsiTmpDir)) {
            return -1;
        }

        if (!m_isDetecting) {  // 首次下载AMSI特征库.
            FirstDownloadPackage();
        } else { // 更新AMSI特征库.
            UpgradeDownloadPackage();
        }

        return 0;
    }

    void AmsiDetectTask::FirstDownloadPackage() {
        bool isStartCheckSuccess{false};
        do {
            // 加扰规则.
            std::string tmpRulesPath = m_amsiTmpDir + "amsi_rules.json";
            if (!ScramblingRules(tmpRulesPath, m_amsiRulePath)) {
                // 发送新库应用失败原因.
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "scrambling rules failed");
                break;
            }

            // dll暂存位置
            std::string tmpDllPath = m_amsiTmpDir + "hss_amsi.dll";
            // 读取规则.
            AmsiRuleSnapshot snapshot;
            if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, snapshot)) {
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "load rule snapshot failed");
                break;
            }
            // 填充dll hash值
            if (!FillRequiredDllHash(tmpDllPath, snapshot)) {
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "get amsi dll hash failed");
                break;
            }

            // 创建通信通道.
            std::string error;
            if (!StartAmsiIpc(snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc failed: %s.", error);
                StopAmsiIpcIfStarted();
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "start amsi ipc failed");
                break;
            }
            m_isIpcRunning = true;
            InfoLogf1(GetLoggerPtr(), "Amsi ipc ready, rule version=%s.", snapshot.version);

            // 保存dll到amsi目录.
            int ret = FileUtils::CsaCopyFile(tmpDllPath, m_amsiDllFilePath);
            if (ret != 0) {
                ErrorLogf3(GetLoggerPtr(), "Copy (%s) to (%s) failed, ret(%d).", tmpDllPath, m_amsiDllFilePath, ret);
                // 发送新库应用失败原因.
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "save amsi dll failed");
                break;
            }

            // 注册AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            if (!amsiDetectDllManager.RegisterAmsiProvider()) {
                StopAmsiIpcIfStarted();  // 注册失败,关闭相关通道,m_isIpcRunning会被置为false
                break;
            }
            // 注册成功，修改对应变量
            m_isAmsiRegistered = true;

            isStartCheckSuccess = true;
        } while (false);

        if (!isStartCheckSuccess) {
            // 清理AMSI特征库.
            if (DirUtils::DeleteDir(m_amsiDir) != 0) {
                ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
            }
            // 通知特征库升级模块定时发送AMSI特征库版本.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
        } else {
            m_isDetecting = true;
            m_usingAmsiVersion = m_handingAmsiVersion;
            // 保存AMSI特征库版本.
            SaveAmsiLibVersion();
            // 通知特征库升级模块定时发送AMSI特征库版本.
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

            // 清理tmp目录.
            if (DirUtils::DeleteDir(m_amsiTmpDir) != 0) {
                ErrorLogf1(GetLoggerPtr(), "Delete amsi tmp dir (%s) failed.", m_amsiTmpDir);
            }
        }

        return;
    }

    void AmsiDetectTask::UpgradeDownloadPackage() {
        // 加扰规则.
        std::string tmpRulesPath = m_amsiTmpDir + "amsi_rules.json";
        if (!ScramblingRules(tmpRulesPath, tmpRulesPath)) {
            ClearTmpDirAndSendFailedReason("scrambling rules failed");
            return;
        }

        // 读取规则, 这里会将status设置为running
        AmsiRuleSnapshot snapshot;
        if (!LoadRuleSnapshot(tmpRulesPath, m_handingAmsiVersion, snapshot)) {
            ClearTmpDirAndSendFailedReason("load final rule snapshot failed");
            return;
        }

        // 如果通信不可用则创建.
        std::string error;
        if (m_amsiIpcRuntime == nullptr || !m_isIpcRunning) {
            if (!StartAmsiIpc(snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc during upgrade failed: %s.", error);
                StopAmsiIpcIfStarted();
                ClearTmpDirAndSendFailedReason("start amsi ipc failed");
                return;
            }
            m_isIpcRunning = true;
        }

        AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
        std::string stagingDllPath = m_amsiTmpDir + "hss_amsi.dll";
        const AmsiDetectDllManager::AmsiDllUpdateResult updateResult =
                amsiDetectDllManager.UpdateAmsiDllEx(stagingDllPath, m_amsiIpcRuntime);
        if (updateResult.code < 0) {
            ClearTmpDirAndSendFailedReason("update dll failed");
            return;
        }
        snapshot.requiredDllHash = updateResult.targetDllHash;
        // 保存规则到amsi目录.
        int ret = FileUtils::CsaCopyFile(tmpRulesPath, m_amsiRulePath);
        if (ret != 0) {
            ErrorLogf3(GetLoggerPtr(), "Copy (%s) to (%s) failed, ret(%d).", tmpRulesPath, m_amsiRulePath, ret);
            ret = FileUtils::CsaDeleteFile(m_amsiRulePath); // 如果保存规则失败，删除amsi目录下的旧规则，下次重新下载.
            InfoLogf2(GetLoggerPtr(), "Delete (%s), ret(%d).", m_amsiRulePath, ret);
        }
        ret = FileUtils::CsaDeleteFile(tmpRulesPath);
        InfoLogf2(GetLoggerPtr(), "Delete (%s), ret(%d).", tmpRulesPath, ret);

        // 更新provider中的规则快照内容.
        if (!m_amsiIpcRuntime->UpdateRules(snapshot, error)) {
            ErrorLogf1(GetLoggerPtr(), "Update amsi ipc rules failed: %s.", error);

            // 规则发布失败时不能让 provider 继续停留在 upgrade/unloading 状态，否则 DLL 会持续 bypass。
            // 这里按 DLL 文件是否已经实际替换来选择恢复方式：
            // 1. UPDATE_SUCCESS_REPLACE / UPDATE_SUCCESS_MOVE：磁盘上的 DLL 已经是新文件，新启动进程会加载新 DLL。
            //    因此恢复旧规则时必须把 requiredDllHash 改成新 DLL hash，否则新进程会因为 hash 不一致继续 bypass。
            // 2. UPDATE_SUCCESS_REBOOT：当前 DLL 文件还没有被替换，只是登记了重启后替换，恢复原始 pre-upgrade snapshot 即可。
            // 3. UPDATE_SUCCESS：DLL hash 一致，没有进入 unloading，UpdateRules 失败后继续沿用旧 provider 快照，不需要恢复。
            std::string restoreError;
            if (updateResult.code == AmsiDetectDllManager::UPDATE_SUCCESS_REPLACE ||
                updateResult.code == AmsiDetectDllManager::UPDATE_SUCCESS_MOVE) {
                if (!m_amsiIpcRuntime->RestorePreUpgradeSnapshotWithDllHash(updateResult.targetDllHash, restoreError)) {
                    WarningLogf1(GetLoggerPtr(), "Restore amsi ipc snapshot with new dll hash failed: %s.", restoreError);
                }
            } else if (updateResult.code == AmsiDetectDllManager::UPDATE_SUCCESS_REBOOT) {
                if (!m_amsiIpcRuntime->RestorePreUpgradeSnapshot(restoreError)) {
                    WarningLogf1(GetLoggerPtr(), "Restore amsi ipc running snapshot after dll update failure failed: %s.",
                                 restoreError);
                }
            }

            ClearTmpDirAndSendFailedReason("update ipc rules failed");
            return;
        }

        m_usingAmsiVersion = m_handingAmsiVersion;
        // 保存AMSI特征库版本.
        SaveAmsiLibVersion();
        // 通知特征库升级模块定时发送AMSI特征库版本.
        HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

        return;
    }

    bool AmsiDetectTask::DecompressPackage(const std::string &destDir) {
        bool ret;
        if (CompressUtils::DecompressDirectory(m_amsiZipPath, destDir) != 0) {
            ErrorLogf2(GetLoggerPtr(), "Decompress (%s) to (%s) failed.", m_amsiZipPath, destDir);
            SendAmsiDownloadResponse(m_handingAmsiVersion, false, "decompress package failed");
            ret = false;
        } else {
            InfoLogf2(GetLoggerPtr(), "Decompress (%s) to (%s) success.", m_amsiZipPath, destDir);
            ret = true;
        }

        // 删除压缩包.
        if (FileUtils::CsaDeleteFile(m_amsiZipPath) != 0) {
            ErrorLogf2(GetLoggerPtr(), "Delete (%s) failed, errno(%d).", m_amsiZipPath, errno);
        }

        return ret;
    }

    bool AmsiDetectTask::ScramblingRules(const std::string &srcRulePath, const std::string &saveRulePath) {
        std::string content;
        int ret = FileUtils::ReadFile(srcRulePath, content);
        if (ret != 0 || content.empty()) {
            ErrorLogf2(GetLoggerPtr(), "Read  file(%s) failed, ret(%d).", srcRulePath, ret)
            return false;
        }

        std::string scramblingStr;
        ret = DataScrambling::Scrambling(content, scramblingStr);
        if (ret != 0) {
            ErrorLogf2(GetLoggerPtr(), "Scrambling file(%s) failed, ret(%d)", srcRulePath, ret)
            return false;
        }

        ret = FileUtils::WriteFile(saveRulePath, scramblingStr, false);
        if (ret != 0) {
            ErrorLogf2(GetLoggerPtr(), "Write file(%s) failed, errno(%d).", saveRulePath, errno)
            return false;
        } else {
            InfoLogf2(GetLoggerPtr(), "Scrambling file(%s) success, save to (%s).", srcRulePath, saveRulePath);
        }

        return true;
    }

    void AmsiDetectTask::ClearTmpDirAndSendFailedReason(const std::string &reason) {
        // 清理AMSI特征库临时目录.
        if (DirUtils::DeleteDir(m_amsiTmpDir) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiTmpDir);
        }

        // 发送新库应用失败原因.
        SendAmsiDownloadResponse(m_handingAmsiVersion, false, reason);

        return;
    }

    bool AmsiDetectTask::SaveAmsiLibVersion() {
        int ret = FileUtils::WriteFile(m_amsiConfPath, m_usingAmsiVersion, false);
        if (ret != 0) {
            ErrorLogf3(GetLoggerPtr(), "Write amsi lib version (%s) to (%s) failed, ret(%d).", m_usingAmsiVersion,
                       m_amsiConfPath, ret);
            return false;
        } else {
            InfoLogf2(GetLoggerPtr(), "Write amsi lib version (%s) to (%s) success.", m_usingAmsiVersion,
                      m_amsiConfPath);
            return true;
        }
    }

    bool AmsiDetectTask::GetAmsiLibVersion() {
        int ret = FileUtils::ReadFile(m_amsiConfPath, m_handingAmsiVersion);
        if (ret != 0) {
            ErrorLogf2(GetLoggerPtr(), "Read amsi lib version from (%s) failed, ret(%d).", m_amsiConfPath, ret);
            return false;
        } else {
            InfoLogf2(GetLoggerPtr(), "Read amsi lib version (%s) from (%s) success.", m_handingAmsiVersion,
                      m_amsiConfPath);
            return true;
        }
    }

}

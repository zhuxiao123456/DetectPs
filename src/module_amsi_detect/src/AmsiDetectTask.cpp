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

    int AmsiDetectTask::Run() {
        GracefulSleep(5);
        return 0;
    }

    void AmsiDetectTask::UnInit() {
        InfoLogf1(GetLoggerPtr(), "Task(%s) uninit begin.", name());
        // ֪ͨ����������ģ�鲻�ٷ���AMSI�汾.
        if (!m_usingAmsiVersion.empty()) {
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, false);
        }

        if (m_isDetecting) {
            // ���dllע��ɹ���ж��
            if (m_isAmsiRegistered) {
                AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
                if (!amsiDetectDllManager.UnregisterAmsiProvider()) {
                    WarningLog(GetLoggerPtr(), "Unregister amsi provider failed during uninit.");
                }
                m_isAmsiRegistered = false;
            }

            // �㲥֪ͨdllֹͣ���(0x03)���ȴ�����dll��Ӧ���ر�ͨ��ͨ��; ��Ҫ���ack��Ϣ
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

            // �������

            m_isDetecting = false;
        }

        m_isDetecting = false;
        m_isIpcRunning = false;
        m_isAmsiRegistered = false;
        m_lastReloadBroadcastOk = false;

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
            // �����ⲻ����ʱ������AMSI������.
            if (DirUtils::IsDir(m_amsiDir)) {
                if (DirUtils::DeleteDir(m_amsiDir) != 0) {
                    ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
                }
            }

            // ����AMSI�������ʼ�汾.
            SendAmsiDownloadRequest();
            // ֪ͨ����������ģ�鶨ʱ����AMSI������汾.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
            return 0;
        }

        InfoLog(GetLoggerPtr(), "Amsi file exist.");
        bool isStartCheckSuccess{false};
        do {
            // ��ȡAMSI������汾.
            if (!GetAmsiLibVersion()) {
                break;
            }

            // ��ȡ����.
            AmsiRuleSnapshot snapshot;
            if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, snapshot)) {
                break;
            }

            // ����ͨ��ͨ��.
            std::string error;
            if (!StartAmsiIpc(snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc failed: %s.", error);
                StopAmsiIpcIfStarted();
                return -1;
            }
            m_isIpcRunning = true;
            InfoLogf1(GetLoggerPtr(), "Amsi ipc ready, rule version=%s.", snapshot.version);

            // ע��AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            if (!amsiDetectDllManager.RegisterAmsiProvider()) {
                return -1;
            }
            m_isAmsiRegistered = true;
            m_isDetecting = true;

            // ֪ͨ����������ģ�鶨ʱ����AMSI������汾.
            m_usingAmsiVersion = m_handingAmsiVersion;
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

            isStartCheckSuccess = true;
        } while (false);

        if (!isStartCheckSuccess) {
            // ����AMSI������.
            if (DirUtils::DeleteDir(m_amsiDir) != 0) {
                ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
            }
            // ����AMSI�������ʼ�汾.
            SendAmsiDownloadRequest();
            // ֪ͨ����������ģ�鶨ʱ����AMSI������汾.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
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

        // ��������������.
        if (m_autoBlock) {
            ruleJson["globalMode"] = "block";
        } else {
            ruleJson["globalMode"] = "audit";
        }

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
        // �������ϵͳ��֧��AMSI��ֱ�ӷ�������ʧ����Ϣ.
        int osName = SystemUtilsRef.GetOsName();
        if (osName < SystemUtils::WINDOWS_10 || osName >= SystemUtils::WINDOWS_MAX) {
            SendAmsiDownloadResponse(version, false, "os version unsupported amsi");
            InfoLogf1(GetLoggerPtr(), "(%s) unsupported amsi, send amsi download failed msg.",
                      SystemUtilsRef.GetOsNameDesc());
            return -1;
        }

        LockUtils::ScopedMutexLock lock(m_operateAmsiLibLock);

        // �����ʱ����Ŀ¼�Ƿ����, �������򴴽�Ŀ¼.
        if (!DirUtils::IsDir(m_amsiTmpDir)) {
            if (DirUtils::MakeDirs(m_amsiTmpDir, S_IRWXU | S_IRWXG | S_IRWXO) == 0) {
                InfoLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) success.", m_amsiTmpDir);
            } else {
                ErrorLogf1(GetLoggerPtr(), "Create amsi tmp dir (%s) failed.", m_amsiTmpDir);
                SendAmsiDownloadResponse(version, false, "create amsi tmp dir failed");
                return -1;
            }
        }

        // ����AMSI������.
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

        // ��ѹ������.
        if (!DecompressPackage(m_amsiTmpDir)) {
            return -1;
        }

        if (!m_isDetecting) {  // �״�����AMSI������.
            FirstDownloadPackage();
        } else { // ����AMSI������.
            UpgradeDownloadPackage();
        }

        return 0;
    }

    void AmsiDetectTask::FirstDownloadPackage() {
        bool isStartCheckSuccess{false};
        do {
            // ���Ź���.
            std::string tmpRulesPath = m_amsiTmpDir + "amsi_rules.json";
            if (!ScramblingRules(tmpRulesPath, m_amsiRulePath)) {
                // �����¿�Ӧ��ʧ��ԭ��.
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "scrambling rules failed");
                break;
            }

            // ��ȡ����.
            AmsiRuleSnapshot snapshot;
            if (!LoadRuleSnapshot(m_amsiRulePath, m_handingAmsiVersion, snapshot)) {
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "load rule snapshot failed");
                break;
            }

            // ����ͨ��ͨ��.
            std::string error;
            if (!StartAmsiIpc(snapshot, error)) {
                ErrorLogf1(GetLoggerPtr(), "Start amsi ipc failed: %s.", error);
                StopAmsiIpcIfStarted();
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "start amsi ipc failed");
                break;
            }
            m_isIpcRunning = true;
            InfoLogf1(GetLoggerPtr(), "Amsi ipc ready, rule version=%s.", snapshot.version);

            // ����dll��amsiĿ¼.
            std::string tmpDllPath = m_amsiTmpDir + "hss_amsi.dll";
            int ret = FileUtils::CsaCopyFile(tmpDllPath, m_amsiDllFilePath);
            if (ret != 0) {
                ErrorLogf3(GetLoggerPtr(), "Copy (%s) to (%s) failed, ret(%d).", tmpDllPath, m_amsiDllFilePath, ret);
                // �����¿�Ӧ��ʧ��ԭ��.
                SendAmsiDownloadResponse(m_handingAmsiVersion, false, "save amsi dll failed");
                break;
            }

            // ע��AMSI.
            AmsiDetectDllManager amsiDetectDllManager{m_amsiDllFilePath};
            if (!amsiDetectDllManager.RegisterAmsiProvider()) {
                StopAmsiIpcIfStarted();  // ע��ʧ��,�ر����ͨ��
                break;
            }

            isStartCheckSuccess = true;
        } while (false);

        if (!isStartCheckSuccess) {
            // ����AMSI������.
            if (DirUtils::DeleteDir(m_amsiDir) != 0) {
                ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiDir);
            }
            // ֪ͨ����������ģ�鶨ʱ����AMSI������汾.
            HandleAmsiVersionInFeatureUpgradeModule("2022010101", true);
        } else {
            m_isDetecting = true;
            m_usingAmsiVersion = m_handingAmsiVersion;
            // ����AMSI������汾.
            SaveAmsiLibVersion();
            // ֪ͨ����������ģ�鶨ʱ����AMSI������汾.
            HandleAmsiVersionInFeatureUpgradeModule(m_usingAmsiVersion, true);

            // ����tmpĿ¼.
            if (DirUtils::DeleteDir(m_amsiTmpDir) != 0) {
                ErrorLogf1(GetLoggerPtr(), "Delete amsi tmp dir (%s) failed.", m_amsiTmpDir);
            }
        }

        return;
    }

    void AmsiDetectTask::UpgradeDownloadPackage() {
        // ���Ź���.
        std::string tmpRulesPath = m_amsiTmpDir + "amsi_rules.json";
        if (!ScramblingRules(tmpRulesPath, tmpRulesPath)) {
            ClearTmpDirAndSendFailedReason("scrambling rules failed");
            return;
        }

        // ��ȡ����.
        AmsiRuleSnapshot snapshot;
        if (!LoadRuleSnapshot(tmpRulesPath, m_handingAmsiVersion, snapshot)) {
            ClearTmpDirAndSendFailedReason("load final rule snapshot failed");
            return;
        }

        // ���ͨ�Ų������򴴽�.
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
        if (amsiDetectDllManager.UpdateAmsiDll(stagingDllPath, m_amsiIpcRuntime) < 0) {
            ClearTmpDirAndSendFailedReason("update dll failed");
            return;
        }
        // �������amsiĿ¼.
        int ret = FileUtils::CsaCopyFile(tmpRulesPath, m_amsiRulePath);
        if (ret != 0) {
            ErrorLogf3(GetLoggerPtr(), "Copy (%s) to (%s) failed, ret(%d).", tmpRulesPath, m_amsiRulePath, ret);
            ret = FileUtils::CsaDeleteFile(m_amsiRulePath); // ����������ʧ�ܣ�ɾ��amsiĿ¼�µľɹ����´���������.
            InfoLogf2(GetLoggerPtr(), "Delete (%s), ret(%d).", m_amsiRulePath, ret);
        }
        ret = FileUtils::CsaDeleteFile(tmpRulesPath);
        InfoLogf2(GetLoggerPtr(), "Delete (%s), ret(%d).", tmpRulesPath, ret);

        // �㲥���������Ϣ֪ͨ�Ѽ��ص�dllʹ���¹������û�п���ͨ���򴴽�; ֮�����provider�еĹ����������.
        if (!m_amsiIpcRuntime->UpdateRules(snapshot, error)) {
            ErrorLogf1(GetLoggerPtr(), "Update amsi ipc rules failed: %s.", error);
            ClearTmpDirAndSendFailedReason("update ipc rules failed");
            return;
        }
        m_lastReloadBroadcastOk = false;
        // �㲥�¹���
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
        // ����AMSI������汾.
        SaveAmsiLibVersion();
        // ֪ͨ����������ģ�鶨ʱ����AMSI������汾.
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

        // ɾ��ѹ����.
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
        // ����AMSI��������ʱĿ¼.
        if (DirUtils::DeleteDir(m_amsiTmpDir) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Delete amsi dir (%s) failed.", m_amsiTmpDir);
        }

        // �����¿�Ӧ��ʧ��ԭ��.
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

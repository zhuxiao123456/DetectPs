//
// Created by y00969037 on 2026/5/25.
//

#include "../include/AmsiGlobalConf.h"

#include "PathUtils.h"
#include "ConfigUtils.h"

#include "../include/AmsiDetectGlobalParam.h"

namespace Engine {
    SINGLETON_INSTANCE_CROSS_LIB(AmsiGlobalConf)
    AmsiGlobalConf::AmsiGlobalConf() = default;
    AmsiGlobalConf::~AmsiGlobalConf() = default;

    using namespace SDK;
    using namespace AmsiDetect;

    namespace {
        uint32_t ClampPipeThreadCount(int value)
        {
            if (value < 1) {
                return 1;
            }
            if (value > 32) {
                return 32;
            }
            return static_cast<uint32_t>(value);
        }
    }

    void AmsiGlobalConf::ParseAmsiConf()
    {
        std::string installationPath;
        if (PathUtils::GetInstallationPath(installationPath) == -1) {
            ErrorLog(GetLoggerPtr(), "Get installation path failed.");
            return;
        }
        std::string amsiConfPath = installationPath + "conf" + PathUtils::separator() + "amsi.conf";

        SDK::ConfigUtils conf;
        if (conf.LoadConfigFile(amsiConfPath) != 0) {
            ErrorLogf1(GetLoggerPtr(), "Load conf(%s) failed, use default value.", amsiConfPath);
            return;
        }

        m_broadcastCount = conf.GetIntValue("broadcast_count", 256);

        m_rulePipeNums = ClampPipeThreadCount(conf.GetIntValue("rule_pipe_nums", 4));
        m_configPipeAcceptThreads =
                ClampPipeThreadCount(conf.GetIntValue("config_pipe_accept_threads", 8));
        m_eventPipeThreads = conf.GetIntValue("event_pipe_threads", 4);
        m_statusPipeThreads = conf.GetIntValue("status_pipe_threads", 2);
        m_diagDroppedSummaryIntervalMs =
                conf.GetInt64Value("diag_dropped_summary_interval_ms", 60 * 1000);
        
        m_maxPayloadBytes = conf.GetInt64Value("max_payload_bytes", 64 * 1024 - 1);
        m_detectionQueueCapacity = conf.GetInt64Value("detection_queue_capacity", 4096);
        m_detectionQueueMaxBytes = conf.GetInt64Value("detection_queue_max_bytes", 64 * 1024 * 1024);
        m_detectionEnqueueTimeoutMs = conf.GetIntValue("detection_enqueue_timeout_ms", 50);
        m_dllDiagnosticLogQueueCapacity = conf.GetInt64Value("dll_diagnostic_log_queue_capacity", 2048);
        m_dllDiagnosticLogQueueMaxBytes = conf.GetInt64Value("dll_diagnostic_log_queue_max_bytes", 16 * 1024 * 1024);
        m_dllDiagnosticLogMaxLineBytes = conf.GetInt64Value("dll_diagnostic_log_max_line_bytes", 4 * 1024);
        m_detectionLogMaxLineBytes = conf.GetInt64Value("detection_log_max_line_bytes", 4 * 1024);
        m_statusLogMaxLineBytes = conf.GetInt64Value("status_log_max_line_bytes", 4 * 1024);
        m_dllDiagnosticDuplicateWindowMs = conf.GetIntValue("dll_diagnostic_duplicate_window_ms", 60 * 1000);
        m_statusQueueCapacity = conf.GetInt64Value("status_queue_capacity", 1024);
        m_statusQueueMaxBytes = conf.GetInt64Value("status_queue_max_bytes", 16 * 1024 * 1024);
        m_statusEnqueueTimeoutMs = conf.GetIntValue("status_enqueue_timeout_ms", 50);

        m_upgradeUnloadBroadcastCycles = conf.GetIntValue("upgrade_unload_broadcast_cycles", 5);
        m_upgradeUnloadBroadcastTimeoutMs = conf.GetIntValue("upgrade_unload_broadcast_timeout_ms", 2000);
        m_upgradeUnloadSettleMs = conf.GetIntValue("upgrade_unload_settle_ms", 15000);

        return;
    }

}

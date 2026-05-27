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

        m_rulePipeNums = conf.GetIntValue("rule_pipe_nums", 8);
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

        return;
    }

}
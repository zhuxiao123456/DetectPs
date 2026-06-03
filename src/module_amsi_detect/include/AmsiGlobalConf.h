//
// Created by y00969037 on 2026/5/25.
//

#ifndef CSA_AMSI_GLOBAL_CONF_H
#define CSA_AMSI_GLOBAL_CONF_H

#include "CommonDefine.h"

#define AmsiGlobalConfRef Engine::AmsiGlobalConf::GetInstance()

namespace Engine {
    class AmsiGlobalConf {
        DECLARE_UNCOPYABLE(AmsiGlobalConf)
        DECLARE_SINGLETON_CROSS_LIB(AmsiGlobalConf)

    public:
        void ParseAmsiConf();

        // Get Functions
        uint32_t GetBroadcastCount() const {
            return m_broadcastCount;
        }

        size_t GetMaxPayloadBytes() const {
            return m_maxPayloadBytes;
        }

        size_t GetDetectionQueueCapacity() const {
            return m_detectionQueueCapacity;
        }

        size_t GetDetectionQueueMaxBytes() const {
            return m_detectionQueueMaxBytes;
        }

        uint32_t GetDetectionEnqueueTimeoutMs() const {
            return m_detectionEnqueueTimeoutMs;
        }

        size_t GetDllDiagnosticLogQueueCapacity() const {
            return m_dllDiagnosticLogQueueCapacity;
        }

        size_t GetDllDiagnosticLogQueueMaxBytes() const {
            return m_dllDiagnosticLogQueueMaxBytes;
        }

        size_t GetDllDiagnosticLogMaxLineBytes() const {
            return m_dllDiagnosticLogMaxLineBytes;
        }

        size_t GetDetectionLogMaxLineBytes() const {
            return m_detectionLogMaxLineBytes;
        }

        size_t GetStatusLogMaxLineBytes() const {
            return m_statusLogMaxLineBytes;
        }

        uint32_t GetDllDiagnosticDuplicateWindowMs() const {
            return m_dllDiagnosticDuplicateWindowMs;
        }

        size_t GetStatusQueueCapacity() const {
            return m_statusQueueCapacity;
        }

        size_t GetStatusQueueMaxBytes() const {
            return m_statusQueueMaxBytes;
        }

        uint32_t GetStatusEnqueueTimeoutMs() const {
            return m_statusEnqueueTimeoutMs;
        }

        uint32_t GetRulePipeNums() const {
            return m_rulePipeNums;
        }

        uint32_t GetConfigPipeAcceptThreads() const {
            return m_configPipeAcceptThreads;
        }

        uint32_t GetEventPipeThreads() const {
            return m_eventPipeThreads;
        }

        uint32_t GetStatusPipeThreads() const {
            return m_statusPipeThreads;
        }

        size_t GetDiagDroppedSummaryIntervalMs() const {
            return m_diagDroppedSummaryIntervalMs;
        }

        uint32_t GetUnloadBroadcastCycles() const {
            return m_upgradeUnloadBroadcastCycles;
        }

        uint32_t GetUnloadBroadcastTimeoutMs() const {
            return m_upgradeUnloadBroadcastTimeoutMs;
        }

        uint32_t GetUnloadSettleMs() const {
            return m_upgradeUnloadSettleMs;
        }

    private:
        // amsi.conf配置项.
        uint32_t m_broadcastCount = 256; // 广播时重试的次数.
        size_t m_maxPayloadBytes = 64 * 1024 - 1;  // 单条消息最大载荷字节数.
        // 检测队列配置: 优先级队列容量 4096 个元素，最大内存占用 64MB，入队超时时间 50ms
        size_t m_detectionQueueCapacity = 4096;
        size_t m_detectionQueueMaxBytes = 64 * 1024 * 1024;
        uint32_t m_detectionEnqueueTimeoutMs = 50;
        // 诊断日志队列(DLL侧上报): 优先级队列容量 2048 个元素，最大内存占用 16MB，单条日志最大 4KB，重复日志去重窗口 60 秒
        size_t m_dllDiagnosticLogQueueCapacity = 2048;
        size_t m_dllDiagnosticLogQueueMaxBytes = 16 * 1024 * 1024;
        size_t m_dllDiagnosticLogMaxLineBytes = 4 * 1024;
        size_t m_detectionLogMaxLineBytes = 4 * 1024;
        size_t m_statusLogMaxLineBytes = 4 * 1024;
        uint32_t m_dllDiagnosticDuplicateWindowMs = 60 * 1000;
        // 状态队列(Status Queue): 优先级队列容量 1024 个元素，最大内存占用 16MB，入队超时时间 50ms
        size_t m_statusQueueCapacity = 1024;
        size_t m_statusQueueMaxBytes = 16 * 1024 * 1024;
        uint32_t m_statusEnqueueTimeoutMs = 50;

        // IPC管道线程配置.
        uint32_t m_rulePipeNums = 16;
        uint32_t m_configPipeAcceptThreads = 8;
        uint32_t m_eventPipeThreads = 4;
        uint32_t m_statusPipeThreads = 2;

        // DLL诊断日志丢弃统计打印间隔，默认 60 秒.
        size_t m_diagDroppedSummaryIntervalMs = 60 * 1000;

        // dll更新升级参数
        uint32_t m_upgradeUnloadBroadcastCycles = 3;  // unload广播三轮
        uint32_t m_upgradeUnloadBroadcastTimeoutMs = 1000;  // 每轮广播超时1000ms
        uint32_t m_upgradeUnloadSettleMs = 15000;  // 广播完成后等待15s,在替换DLL
    };
}

#endif //CSA_AMSI_GLOBAL_CONF_H

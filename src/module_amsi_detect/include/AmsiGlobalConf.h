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

        uint32_t GetEventPipeThreads() const {
            return m_eventPipeThreads;
        }

        uint32_t GetStatusPipeThreads() const {
            return m_statusPipeThreads;
        }

        size_t GetDiagDroppedSummaryIntervalMs() const {
            return m_diagDroppedSummaryIntervalMs;
        }

    private:
        // amsi.conf配置.
        uint32_t m_broadcastCount = 256; // 广播时最大遍历数目.
        size_t m_maxPayloadBytes = 64 * 1024 - 1;
        // 检测事件队列: 高优先级、最大容纳 4096 个元素，总内存上限 64MB，单次入队超时 50ms
        size_t m_detectionQueueCapacity = 4096;
        size_t m_detectionQueueMaxBytes = 64 * 1024 * 1024;
        uint32_t m_detectionEnqueueTimeoutMs = 50;
        // 探针诊断日志队列(dll传过来的)：中优先级，最大容纳 2048 个元素，总内存上限 16MB，限制单行日志最大 4KB，并设置 60 秒的去重窗口
        size_t m_dllDiagnosticLogQueueCapacity = 2048;
        size_t m_dllDiagnosticLogQueueMaxBytes = 16 * 1024 * 1024;
        size_t m_dllDiagnosticLogMaxLineBytes = 4 * 1024;
        size_t m_detectionLogMaxLineBytes = 4 * 1024;
        size_t m_statusLogMaxLineBytes = 4 * 1024;
        uint32_t m_dllDiagnosticDuplicateWindowMs = 60 * 1000;
        // 状态队列（Status Queue）：低优先级，最大容纳 1024 个元素，总内存上限 16MB，单次入队超时 50ms
        size_t m_statusQueueCapacity = 1024;
        size_t m_statusQueueMaxBytes = 16 * 1024 * 1024;
        uint32_t m_statusEnqueueTimeoutMs = 50;

        // IPC 管道线程数配置.
        uint32_t m_rulePipeNums = 8;
        uint32_t m_eventPipeThreads = 4;
        uint32_t m_statusPipeThreads = 2;

        // DLL 诊断日志 dropped 汇总打印间隔，默认 60 秒.
        size_t m_diagDroppedSummaryIntervalMs = 60 * 1000;
    };
}

#endif //CSA_AMSI_GLOBAL_CONF_H

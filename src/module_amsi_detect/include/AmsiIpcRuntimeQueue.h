//
// Created by z00840245 on 2026/5/22.
// 定义了队列配置参数结构体（AmsiIpcRuntimeQueueConfig）、全局运行时统计状态结构体（AmsiIpcRuntimeStats）
// 数据传输载荷信封（RuntimePayloadEnvelope）、核心的线程安全有界队列类（BoundedPayloadQueue）
//

#ifndef CSA_ENGINE_AMSI_IPC_RUNTIME_QUEUE_H
#define CSA_ENGINE_AMSI_IPC_RUNTIME_QUEUE_H

#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <mutex>
#include <string>

#include "AmsiIpcPayloadClassifier.h"

namespace Engine {
    // 运行时统计状态结构体: 用于安全探针的健康度检测与性能监控;
    // 内部记录了引擎生命周期状态（initialized、running 等）、三大队列各自的接收数/丢弃数计数器以及当前队列的实时大小与内存占用
    struct AmsiIpcRuntimeStats {
        bool initialized = false;
        bool running = false;
        bool stopping = false;
        bool workersStarted = false;
        bool pipeStarted = false;

        uint64_t detectionReceived = 0;
        uint64_t detectionDropped = 0;
        uint64_t dllDiagReceived = 0;
        uint64_t dllDiagDropped = 0;
        uint64_t statusReceived = 0;
        uint64_t statusDropped = 0;
        uint64_t drainAckReceived = 0;
        uint64_t unknownEventReceived = 0;
        uint64_t oversizedPayloadDropped = 0;

        uint64_t lastReloadReached = 0;
        uint64_t lastReloadLastError = 0;
        uint64_t lastPauseReached = 0;
        uint64_t lastPauseLastError = 0;
        uint64_t lastResumeReached = 0;
        uint64_t lastResumeLastError = 0;
        uint64_t lastUnloadReached = 0;
        uint64_t lastUnloadLastError = 0;

        size_t detectionQueueSize = 0;
        size_t detectionQueueBytes = 0;
        size_t dllDiagQueueSize = 0;
        size_t dllDiagQueueBytes = 0;
        size_t statusQueueSize = 0;
        size_t statusQueueBytes = 0;

        std::string lastError;
        bool degraded = false;
    };
    // 数据载荷信封: 进入队列的统一数据单元
    struct RuntimePayloadEnvelope {
        AmsiIpcPayloadKind kind = AmsiIpcPayloadKind::UnknownEvent;  // 通过关键字段匹配类型
        std::string rawJson;  // 原始字符串
        uint64_t receivedTimeMs = 0;  // 时间戳
    };

    class BoundedPayloadQueue {
    public:
        BoundedPayloadQueue();  // 创建一个未指定容量边界的空队列（默认容量和字节限制均为 0，不可直接使用，需后续调用 Reset）
        BoundedPayloadQueue(size_t capacity, size_t maxBytes);  // 队列元素个数和总容量大小

        void Reset(size_t capacity, size_t maxBytes);  // 重置队列状态、引擎配置热更新、重启服务时使用
        // 生产者接口: 数据入队
        bool Push(RuntimePayloadEnvelope &&item, uint32_t timeoutMs, bool waitWhenFull);

        bool TryPush(RuntimePayloadEnvelope &&item);

        bool Pop(RuntimePayloadEnvelope &out);

        void Stop();

        void StopAndDrop();

        void Clear();

        size_t Size() const;

        size_t Bytes() const;

    private:
        // 评估当前队列状态是否能放得下某个特定大小的新元素。由于带 Locked 后缀，内部不加锁，必须由调用者在持有 mutex_ 的安全区域内调用
        bool CanPushLocked(size_t itemBytes) const;

        mutable std::mutex mutex_;
        std::condition_variable notEmpty_;
        std::condition_variable notFull_;
        std::deque<RuntimePayloadEnvelope> queue_;
        size_t capacity_ = 0;
        size_t maxBytes_ = 0;
        size_t bytes_ = 0;
        bool stopped_ = false;
    };

} // namespace Engine

#endif //CSA_ENGINE_AMSI_IPC_RUNTIME_QUEUE_H

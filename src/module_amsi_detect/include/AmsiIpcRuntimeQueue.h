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
    // 数据载荷信封: 进入队列的统一数据单元
    struct RuntimePayloadEnvelope {
        AmsiIpcPayloadKind kind = AmsiIpcPayloadKind::UnknownEvent;  // 通过关键字段匹配类型
        std::string rawJson;  // 原始字符串
        uint64_t receivedTimeMs = 0;  // 时间戳
    };

    class BoundedPayloadQueue {
    public:
        BoundedPayloadQueue();  // 创建一个未指定容量边界的空队列（默认容量和字节限制均为 0，不可直接使用，需后续调用 Reset）

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

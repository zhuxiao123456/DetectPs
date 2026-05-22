//
// Created by Codex on 2026/5/22.
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

    struct AmsiIpcRuntimeQueueConfig {
        size_t maxPayloadBytes = 64 * 1024 - 1;

        size_t detectionQueueCapacity = 4096;
        size_t detectionQueueMaxBytes = 64 * 1024 * 1024;
        uint32_t detectionEnqueueTimeoutMs = 50;

        size_t dllDiagnosticLogQueueCapacity = 2048;
        size_t dllDiagnosticLogQueueMaxBytes = 16 * 1024 * 1024;
        size_t dllDiagnosticLogMaxLineBytes = 4 * 1024;
        uint32_t dllDiagnosticDuplicateWindowMs = 60 * 1000;

        size_t statusQueueCapacity = 1024;
        size_t statusQueueMaxBytes = 16 * 1024 * 1024;
        uint32_t statusEnqueueTimeoutMs = 50;
    };

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

        size_t detectionQueueSize = 0;
        size_t detectionQueueBytes = 0;
        size_t dllDiagQueueSize = 0;
        size_t dllDiagQueueBytes = 0;
        size_t statusQueueSize = 0;
        size_t statusQueueBytes = 0;

        std::string lastError;
        bool degraded = false;
    };

    struct RuntimePayloadEnvelope {
        AmsiIpcPayloadKind kind = AmsiIpcPayloadKind::UnknownEvent;
        std::string rawJson;
        uint64_t receivedTimeMs = 0;
    };

    class BoundedPayloadQueue {
    public:
        BoundedPayloadQueue();
        BoundedPayloadQueue(size_t capacity, size_t maxBytes);

        void Reset(size_t capacity, size_t maxBytes);
        bool Push(RuntimePayloadEnvelope item, uint32_t timeoutMs, bool waitWhenFull);
        bool TryPush(RuntimePayloadEnvelope item);
        bool Pop(RuntimePayloadEnvelope &out);
        void Stop();
        void StopAndDrop();
        void Clear();

        size_t Size() const;
        size_t Bytes() const;

    private:
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

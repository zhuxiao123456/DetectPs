#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

enum class EventPriority {
    Detection,
    Telemetry,
    DiagLog
};

enum class EventType {
    Detection,
    RuntimeTelemetry,
    Diagnostic
};

enum class EnqueueResult {
    Enqueued,
    DroppedQueueFull,
    DroppedLockContention,
    DroppedStopping,
    DroppedTooLarge
};

struct AsyncEvent {
    EventPriority priority = EventPriority::Telemetry;
    EventType type = EventType::RuntimeTelemetry;
    uint64_t timestamp = 0;
    DWORD pid = 0;
    DWORD tid = 0;
    std::string ruleId;
    std::string decision;
    std::string contentName;
    std::string appName;
    std::string sampleHash;
    uint64_t sampleLen = 0;
    std::string reason;
    std::string compactJson;
    bool eventTruncated = false;
};

struct AsyncEventQueueOptions {
    size_t maxEvents = 4096;
    size_t maxEventBytes = 16 * 1024;
};

struct AsyncEventMetrics {
    uint64_t eventsEnqueuedTotal = 0;
    uint64_t eventsSentTotal = 0;
    uint64_t eventsSendFailedTotal = 0;
    uint64_t eventsDroppedTotal = 0;
    uint64_t droppedDetectionCount = 0;
    uint64_t droppedTelemetryCount = 0;
    uint64_t droppedDiagCount = 0;
    uint64_t queueCurrentSize = 0;
    uint64_t queueHighWatermark = 0;
    uint64_t sentryDisconnectedCount = 0;
    uint64_t workerBackoffCount = 0;
    uint64_t shutdownFlushTimeoutCount = 0;
    uint64_t eventsTruncatedTotal = 0;
    uint64_t enqueueLockContentionCount = 0;
    uint64_t enqueueStoppingDropCount = 0;
    uint64_t enqueueTooLargeDropCount = 0;
};

class AsyncEventQueue
{
public:
    explicit AsyncEventQueue(AsyncEventQueueOptions options = {});

    EnqueueResult TryEnqueue(const AsyncEvent& event);
    bool TryDequeue(AsyncEvent& event);
    bool WaitDequeue(AsyncEvent& event, std::chrono::milliseconds timeout);
    void Stop();
    size_t DropRemaining();
    AsyncEventMetrics GetMetrics() const;
    size_t Size() const;

    void RecordSendSuccess();
    void RecordSendFailure();
    void RecordBackoff();
    void RecordShutdownFlushTimeout();

private:
    bool PrepareEvent(AsyncEvent& event);
    size_t EstimateEventBytes(const AsyncEvent& event) const;
    size_t CurrentSizeLocked() const;
    bool HasCapacityLocked() const;
    bool MakeRoomLocked(EventPriority priority);
    void DropOneLocked(EventPriority priority);
    void RecordDrop(EventPriority priority);
    void UpdateSizeMetricsLocked();

    AsyncEventQueueOptions options_;
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<AsyncEvent> high_;
    std::deque<AsyncEvent> medium_;
    std::deque<AsyncEvent> low_;
    std::atomic<bool> stopping_{false};

    std::atomic<uint64_t> eventsEnqueuedTotal_{0};
    std::atomic<uint64_t> eventsSentTotal_{0};
    std::atomic<uint64_t> eventsSendFailedTotal_{0};
    std::atomic<uint64_t> eventsDroppedTotal_{0};
    std::atomic<uint64_t> droppedDetectionCount_{0};
    std::atomic<uint64_t> droppedTelemetryCount_{0};
    std::atomic<uint64_t> droppedDiagCount_{0};
    std::atomic<uint64_t> queueHighWatermark_{0};
    std::atomic<uint64_t> sentryDisconnectedCount_{0};
    std::atomic<uint64_t> workerBackoffCount_{0};
    std::atomic<uint64_t> shutdownFlushTimeoutCount_{0};
    std::atomic<uint64_t> eventsTruncatedTotal_{0};
    std::atomic<uint64_t> enqueueLockContentionCount_{0};
    std::atomic<uint64_t> enqueueStoppingDropCount_{0};
    std::atomic<uint64_t> enqueueTooLargeDropCount_{0};
};

class AsyncEventSink
{
public:
    using Sender = std::function<bool(const AsyncEvent&)>;

    explicit AsyncEventSink(AsyncEventQueueOptions options = {});
    ~AsyncEventSink();

    bool Start(Sender sender);
    EnqueueResult TrySubmit(const AsyncEvent& event);
    void Stop(std::chrono::milliseconds flushTimeout);
    AsyncEventMetrics GetMetrics() const;

private:
    void WorkerLoop();
    std::chrono::milliseconds NextBackoff();
    void ResetBackoff();

    AsyncEventQueue queue_;
    Sender sender_;
    std::thread worker_;
    std::atomic<bool> running_{false};
    uint32_t consecutiveFailures_ = 0;
};

#pragma once

#include "amsi_rule_provider.h"

#include <condition_variable>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <thread>
#include <vector>

class AmsiIpcHost;

namespace hostguard_demo {

class HostGuardAmsiIpcRuntime;

enum class DetectionQueueFullPolicy {
    DropImmediately,
    WaitThenDrop,
    BlockForever,
};

enum class QueueFullPolicy {
    DropImmediately,
    WaitThenDrop,
    BlockForever,
};

struct HostGuardAmsiIpcConfig {
    bool useProductionPipes = true;
    bool enableRealIpc = false;

    int rulePipeThreads = 8;
    int eventPipeThreads = 4;
    int statusPipeThreads = 4;

    std::size_t maxRuleResponseBytes = 4 * 1024 * 1024;
    std::size_t maxEventBytes = 1024 * 1024;
    std::size_t maxStatusBytes = 256 * 1024;

    std::size_t detectionEventQueueCapacity = 4096;
    std::size_t dllDiagnosticLogQueueCapacity = 8192;
    std::size_t statusQueueCapacity = 1024;
    std::size_t adapterDiagRingCapacity = 1024;

    std::size_t detectionEventQueueMaxBytes = 64 * 1024 * 1024;
    std::size_t dllDiagnosticLogQueueMaxBytes = 16 * 1024 * 1024;
    std::size_t statusQueueMaxBytes = 16 * 1024 * 1024;

    std::uint32_t stopTimeoutMs = 3000;
    std::uint32_t callbackTimeoutMs = 100;
    std::uint32_t detectionEnqueueTimeoutMs = 50;
    std::uint32_t statusEnqueueTimeoutMs = 50;

    DetectionQueueFullPolicy detectionQueueFullPolicy = DetectionQueueFullPolicy::WaitThenDrop;
    bool dropDllDiagnosticLogOnQueueFull = true;
    QueueFullPolicy statusQueueFullPolicy = QueueFullPolicy::WaitThenDrop;
    bool failStartIfPipeSecurityInvalid = true;

    std::wstring rulesPipeName;
    std::wstring eventsPipeName;
    std::wstring controlStatusPipeName;
    std::wstring configPipeName;
};

enum class HostGuardAmsiMessageKind {
    Detection,
    DiagnosticLog,
    DrainAck,
    Unknown,
};

struct HostGuardAmsiEventEnvelope {
    HostGuardAmsiMessageKind kind = HostGuardAmsiMessageKind::Unknown;
    std::string rawJson;
    std::string cat;
    std::string sensor;
    std::string pattern;
    std::string broadcastId;
};

struct HostGuardAmsiAdapterDiag {
    std::string timestamp;
    std::string level;
    std::string component;
    std::string message;
};

struct HostGuardAmsiBroadcastResult {
    std::uint32_t attempted = 0;
    std::uint32_t delivered = 0;
    std::uint32_t failed = 0;
    std::uint32_t timeout = 0;
    std::uint32_t acked = 0;
    std::uint32_t elapsedMs = 0;

    std::string broadcastId;
    std::string command;
    std::string policyVersion;
    std::string ruleVersion;
    std::string error;
};

struct HostGuardAmsiAckInfo {
    std::string broadcastId;
    std::string instanceId;
    std::string command;
    std::string rawJson;
};

struct HostGuardAmsiIpcStatus {
    bool initialized = false;
    bool started = false;
    bool stopping = false;
    bool productionPipes = false;
    bool detectionEnabled = true;

    std::uint64_t ruleRequests = 0;
    std::uint64_t ruleRequestUnsupported = 0;
    std::uint64_t eventReceived = 0;
    std::uint64_t detectionEventReceived = 0;
    std::uint64_t dllDiagnosticLogReceived = 0;
    std::uint64_t drainAckReceived = 0;
    std::uint64_t drainAckCorrelated = 0;
    std::uint64_t drainAckUncorrelated = 0;
    std::uint64_t unknownEventReceived = 0;
    std::uint64_t statusReceived = 0;
    std::uint64_t detectionEventDropped = 0;
    std::uint64_t dllDiagnosticLogDropped = 0;
    std::uint64_t unknownEventDropped = 0;
    std::uint64_t statusDropped = 0;
    std::uint64_t adapterDiagDropped = 0;

    std::string lastError;
    std::string lastRuleVersion;
    std::string lastRuleHash;
    std::string lastPolicyVersion;
    std::string lifecycleState;
};

struct HostGuardRuleSnapshot {
    std::string allRulesJson;
    std::string amsiRulesJson;
    std::string version;
    std::string hash;
};

class HostGuardRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    bool UpdateRules(std::string allRulesJson,
                     std::string amsiRulesJson,
                     std::string version,
                     std::string hash,
                     std::string& error);

    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override;

    void InvalidateRuleCache() override {}

    std::string version() const;
    std::string hash() const;

private:
    mutable std::shared_mutex mutex_;
    std::shared_ptr<const HostGuardRuleSnapshot> snapshot_;
};

template <typename T>
class BoundedQueue {
public:
    using SizeFn = std::function<std::size_t(const T&)>;

    BoundedQueue() = default;

    BoundedQueue(std::size_t maxCount, std::size_t maxBytes, SizeFn sizeFn)
        : maxCount_(maxCount), maxBytes_(maxBytes), sizeFn_(std::move(sizeFn))
    {
    }

    void Reset(std::size_t maxCount, std::size_t maxBytes, SizeFn sizeFn)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        maxCount_ = maxCount;
        maxBytes_ = maxBytes;
        sizeFn_ = std::move(sizeFn);
        items_.clear();
        bytes_ = 0;
        closed_ = false;
    }

    bool Push(const T& value)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (closed_ || !CanEverFitLocked(value) || !CanFitLocked(value)) {
            return false;
        }
        PushLocked(value);
        return true;
    }

    bool PushWaitFor(const T& value, std::uint32_t timeoutMs)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!CanEverFitLocked(value)) {
            return false;
        }
        const auto canPush = [&]() { return closed_ || CanFitLocked(value); };
        if (!notFull_.wait_for(lock, std::chrono::milliseconds(timeoutMs), canPush)) {
            return false;
        }
        if (closed_ || !CanFitLocked(value)) {
            return false;
        }
        PushLocked(value);
        return true;
    }

    bool PushBlock(const T& value)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        if (!CanEverFitLocked(value)) {
            return false;
        }
        notFull_.wait(lock, [&]() { return closed_ || CanFitLocked(value); });
        if (closed_ || !CanFitLocked(value)) {
            return false;
        }
        PushLocked(value);
        return true;
    }

    bool Pop(T& value)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        notEmpty_.wait(lock, [&]() { return closed_ || !items_.empty(); });
        if (items_.empty()) {
            return false;
        }
        auto item = std::move(items_.front());
        value = std::move(item.value);
        bytes_ -= item.bytes;
        items_.pop_front();
        notFull_.notify_one();
        return true;
    }

    void Close()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        closed_ = true;
        notEmpty_.notify_all();
        notFull_.notify_all();
    }

private:
    std::size_t ItemSize(const T& value) const
    {
        return sizeFn_ ? sizeFn_(value) : sizeof(T);
    }

    bool CanFitLocked(const T& value) const
    {
        if (maxCount_ > 0 && items_.size() >= maxCount_) {
            return false;
        }
        const std::size_t itemSize = ItemSize(value);
        if (maxBytes_ > 0 && bytes_ + itemSize > maxBytes_) {
            return false;
        }
        return true;
    }

    bool CanEverFitLocked(const T& value) const
    {
        const std::size_t itemSize = ItemSize(value);
        return maxBytes_ == 0 || itemSize <= maxBytes_;
    }

    struct Item {
        T value;
        std::size_t bytes = 0;
    };

    void PushLocked(const T& value)
    {
        const std::size_t itemBytes = ItemSize(value);
        items_.push_back(Item{value, itemBytes});
        bytes_ += itemBytes;
        notEmpty_.notify_one();
    }

    std::size_t maxCount_ = 0;
    std::size_t maxBytes_ = 0;
    SizeFn sizeFn_;
    std::deque<Item> items_;
    std::size_t bytes_ = 0;
    bool closed_ = false;
    mutable std::mutex mutex_;
    std::condition_variable notEmpty_;
    std::condition_variable notFull_;
};

class AdapterDiagRingBuffer {
public:
    explicit AdapterDiagRingBuffer(std::size_t capacity = 1024);

    void SetCapacity(std::size_t capacity);
    void Add(std::string level, std::string component, std::string message);
    std::vector<HostGuardAmsiAdapterDiag> Recent() const;
    std::uint64_t dropped() const;

private:
    std::size_t capacity_;
    std::deque<HostGuardAmsiAdapterDiag> entries_;
    std::uint64_t dropped_ = 0;
    mutable std::mutex mutex_;
};

class EventPipeClassifier {
public:
    static HostGuardAmsiEventEnvelope Classify(const std::string& rawJson);
};

class BroadcastTracker {
public:
    bool BeginBroadcast(const std::string& broadcastId,
                        const std::string& command,
                        std::uint32_t attempted,
                        std::string& error);

    void OnAck(const std::string& broadcastId, const HostGuardAmsiAckInfo& ack);

    HostGuardAmsiBroadcastResult WaitResult(const std::string& broadcastId,
                                            std::uint32_t timeoutMs);

    void ExpireOldBroadcasts();

private:
    struct Context {
        HostGuardAmsiBroadcastResult result;
        bool completed = false;
    };

    std::map<std::string, Context> contexts_;
    std::mutex mutex_;
};

class HostGuardAmsiIpcAdapter {
public:
    HostGuardAmsiIpcAdapter();
    ~HostGuardAmsiIpcAdapter();

    bool Init(const HostGuardAmsiIpcConfig& config, std::string& error);
    bool Start(std::string& error);
    void Stop();

    bool UpdateRules(std::string allRulesJson,
                     std::string amsiRulesJson,
                     std::string version,
                     std::string hash,
                     std::string& error);

    bool SetDetectionEnabled(bool enabled,
                             std::string policyVersion,
                             std::string& error);

    bool Reload(std::uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
    bool PauseDetection(std::uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
    bool ResumeDetection(std::uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);
    bool Unload(std::uint32_t timeoutMs, HostGuardAmsiBroadcastResult& result);

    void SetDetectionEventCallback(std::function<void(const HostGuardAmsiEventEnvelope& event)> cb);
    void SetDllDiagnosticLogCallback(std::function<void(const HostGuardAmsiEventEnvelope& log)> cb);
    void SetStatusCallback(std::function<void(const std::string& rawJson)> cb);
    void SetAdapterDiagCallback(std::function<void(const HostGuardAmsiAdapterDiag& diag)> cb);

    bool InjectRawEventForTest(const std::string& rawJson);
    bool InjectStatusForTest(const std::string& rawJson);

    bool SubmitRawEventPayload(const std::string& rawJson) { return InjectRawEventForTest(rawJson); }
    bool SubmitStatusPayload(const std::string& rawJson) { return InjectStatusForTest(rawJson); }

    std::vector<HostGuardAmsiAdapterDiag> GetRecentAdapterDiag() const;
    HostGuardAmsiIpcStatus GetStatus() const;

private:
    friend class HostGuardAmsiIpcRuntime;

    bool BuildRulesResponseForIpc(const std::string& command,
                                  amsi_ipc::AmsiRuleResponse& out,
                                  std::string& error);
    bool EnqueueRawEventFromIpc(const std::string& rawJson);
    bool EnqueueStatusFromIpc(const std::string& rawJson);
    std::string NextBroadcastId();
    void MarkFaulted(const std::string& error);

    void DetectionForwarder();
    void DllDiagnosticLogForwarder();
    void StatusForwarder();
    void AddDiag(const std::string& level, const std::string& component, const std::string& message);

    mutable std::mutex mutex_;
    HostGuardAmsiIpcConfig config_;
    HostGuardAmsiIpcStatus status_;
    HostGuardRuleProvider ruleProvider_;
    AdapterDiagRingBuffer diag_;
    std::unique_ptr<HostGuardAmsiIpcRuntime> runtime_;
    mutable std::mutex runtimeMutex_;
    BroadcastTracker broadcastTracker_;
    std::uint64_t nextBroadcastCounter_ = 1;
    bool detectionEnabled_ = true;

    BoundedQueue<HostGuardAmsiEventEnvelope> detectionQueue_;
    BoundedQueue<HostGuardAmsiEventEnvelope> dllLogQueue_;
    BoundedQueue<std::string> statusQueue_;

    std::function<void(const HostGuardAmsiEventEnvelope&)> detectionCallback_;
    std::function<void(const HostGuardAmsiEventEnvelope&)> dllLogCallback_;
    std::function<void(const std::string&)> statusCallback_;
    std::function<void(const HostGuardAmsiAdapterDiag&)> adapterDiagCallback_;

    std::thread detectionForwarder_;
    std::thread dllLogForwarder_;
    std::thread statusForwarder_;
};

} // namespace hostguard_demo

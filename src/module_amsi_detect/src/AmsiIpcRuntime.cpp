//
// Created by Codex on 2026/5/21.
//

#include "AmsiIpcRuntime.h"

#include "AmsiIpcPayloadClassifier.h"
#include "AmsiIpcRuntimeQueue.h"
#include "../amsi_ipc_host/include/AmsiConfigBroadcaster.h"
#include "../amsi_ipc_host/include/AmsiControlStatusChannel.h"
#include "../amsi_ipc_host/include/AmsiControlStatusSink.h"
#include "../amsi_ipc_host/include/AmsiEventChannel.h"
#include "../amsi_ipc_host/include/AmsiEventSink.h"
#include "../amsi_ipc_host/include/AmsiRuleChannel.h"
#include "../amsi_ipc_host/include/AmsiRuleProvider.h"
#include "../amsi_ipc_host/include/NamedPipeServerPool.h"

#include "AmsiDetectGlobalParam.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace Engine {
    namespace {

        const wchar_t *kRulesPipeName = L"\\\\.\\pipe\\amsi_detect_rules";
        const wchar_t *kEventsPipeName = L"\\\\.\\pipe\\amsi_detect_events";
        const wchar_t *kControlStatusPipeName = L"\\\\.\\pipe\\amsi_detect_control_status";
        const wchar_t *kConfigPipeName = L"\\\\.\\pipe\\amsi_detect_config";

        const int kRulePipeThreads = 8;
        const int kEventPipeThreads = 4;
        const int kStatusPipeThreads = 2;
        const int kBroadcastMaxListeners = 32;
        const uint32_t kDiagDroppedSummaryIntervalMs = 60 * 1000;

        class RuntimeRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
        public:
            bool UpdateSnapshot(const AmsiRuleSnapshot &snapshot, std::string &error)
            {
                if (snapshot.allRulesJson.empty()) {
                    error = "all rules json is empty";
                    return false;
                }
                if (snapshot.amsiRulesJson.empty()) {
                    error = "amsi rules json is empty";
                    return false;
                }
                if (snapshot.version.empty()) {
                    error = "rule version is empty";
                    return false;
                }

                std::lock_guard<std::mutex> lock(mutex_);
                snapshot_ = snapshot;
                error.clear();
                return true;
            }

            bool BuildRulesResponse(const std::string &command,
                                    amsi_ipc::AmsiRuleResponse &out,
                                    std::string &error) override
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (command == "GET_RULES") {
                    out.json = snapshot_.amsiRulesJson;
                    error.clear();
                    return !out.json.empty();
                }
                if (command == "GET_ALL_RULES") {
                    out.json = snapshot_.allRulesJson;
                    error.clear();
                    return !out.json.empty();
                }

                error = "unsupported rules command: " + command;
                return false;
            }

            void InvalidateRuleCache() override {}

        private:
            std::mutex mutex_;
            AmsiRuleSnapshot snapshot_;
        };

        class RuntimeEventSink final : public amsi_ipc::IAmsiEventSink {
        public:
            explicit RuntimeEventSink(std::function<void(const std::string &)> onEvent)
                : onEvent_(std::move(onEvent))
            {
            }

            void OnEventLine(const amsi_ipc::AmsiEventLine &event) override
            {
                if (onEvent_) {
                    onEvent_(event.payload);
                }
            }

        private:
            std::function<void(const std::string &)> onEvent_;
        };

        class RuntimeControlStatusSink final : public amsi_ipc::IAmsiControlStatusSink {
        public:
            explicit RuntimeControlStatusSink(std::function<void(const std::string &)> onStatus)
                : onStatus_(std::move(onStatus))
            {
            }

            void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine &status) override
            {
                if (onStatus_) {
                    onStatus_(status.payload);
                }
            }

        private:
            std::function<void(const std::string &)> onStatus_;
        };

        bool BroadcastSucceeded(const amsi_ipc::AmsiBroadcastResult &result, std::string &error)
        {
            if (result.lastError != 0) {
                error = "broadcast failed, lastError=" + std::to_string(result.lastError);
                return false;
            }

            error.clear();
            return true;
        }

        bool PipeHasExistingServer(const wchar_t *pipeName)
        {
            if (WaitNamedPipeW(pipeName, 1)) {
                return true;
            }

            const DWORD lastError = GetLastError();
            return lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND;
        }

        uint64_t NowMs()
        {
            return static_cast<uint64_t>(GetTickCount64());
        }

        std::string TruncateForLog(const std::string &payload, size_t maxBytes)
        {
            if (payload.size() <= maxBytes) {
                return payload;
            }
            return payload.substr(0, maxBytes) + "...<truncated>";
        }

        bool ExtractJsonStringField(const std::string &payload,
                                    const char *fieldName,
                                    std::string &value)
        {
            const std::string key = std::string("\"") + fieldName + "\"";
            const std::string::size_type keyPos = payload.find(key);
            if (keyPos == std::string::npos) {
                return false;
            }

            const std::string::size_type colonPos = payload.find(':', keyPos + key.size());
            if (colonPos == std::string::npos) {
                return false;
            }

            std::string::size_type quotePos = payload.find('"', colonPos + 1);
            if (quotePos == std::string::npos) {
                return false;
            }

            ++quotePos;
            std::string result;
            bool escaping = false;
            for (std::string::size_type i = quotePos; i < payload.size(); ++i) {
                const char ch = payload[i];
                if (escaping) {
                    result.push_back(ch);
                    escaping = false;
                    continue;
                }
                if (ch == '\\') {
                    escaping = true;
                    continue;
                }
                if (ch == '"') {
                    value = result;
                    return true;
                }
                result.push_back(ch);
            }
            return false;
        }

        std::string DiagnosticKey(const std::string &payload)
        {
            std::string pattern;
            std::string desc;
            ExtractJsonStringField(payload, "pattern", pattern);
            ExtractJsonStringField(payload, "desc", desc);
            if (!pattern.empty() || !desc.empty()) {
                return pattern + "|" + desc;
            }
            return payload;
        }

    }

    struct AmsiIpcRuntime::Impl {
        AmsiIpcRuntimeConfig config;
        AmsiRuleSnapshot snapshot;

        std::unique_ptr<RuntimeRuleProvider> ruleProvider;
        std::unique_ptr<RuntimeEventSink> eventSink;
        std::unique_ptr<RuntimeControlStatusSink> statusSink;

        std::unique_ptr<amsi_ipc::AmsiRuleChannel> ruleChannel;
        std::unique_ptr<amsi_ipc::AmsiEventChannel> eventChannel;
        std::unique_ptr<amsi_ipc::AmsiControlStatusChannel> statusChannel;

        std::unique_ptr<amsi_ipc::NamedPipeServerPool> rulePool;
        std::unique_ptr<amsi_ipc::NamedPipeServerPool> eventPool;
        std::unique_ptr<amsi_ipc::NamedPipeServerPool> statusPool;

        std::unique_ptr<amsi_ipc::AmsiConfigBroadcaster> broadcaster;

        BoundedPayloadQueue detectionQueue;
        BoundedPayloadQueue dllDiagQueue;
        BoundedPayloadQueue statusQueue;

        std::thread detectionWorker;
        std::thread dllDiagWorker;
        std::thread statusWorker;

        std::atomic<bool> initialized{false};
        std::atomic<bool> running{false};
        std::atomic<bool> stopping{false};
        std::atomic<bool> workersStarted{false};
        std::atomic<bool> pipeStarted{false};

        std::atomic<uint64_t> detectionReceived{0};
        std::atomic<uint64_t> detectionDropped{0};
        std::atomic<uint64_t> dllDiagReceived{0};
        std::atomic<uint64_t> dllDiagDropped{0};
        std::atomic<uint64_t> statusReceived{0};
        std::atomic<uint64_t> statusDropped{0};
        std::atomic<uint64_t> drainAckReceived{0};
        std::atomic<uint64_t> unknownEventReceived{0};
        std::atomic<uint64_t> oversizedPayloadDropped{0};

        std::mutex statsMutex;
        std::string lastError;
        bool degraded = false;

        std::mutex diagMutex;
        std::string lastDiagKey;
        uint64_t lastDiagLogMs = 0;
        uint64_t suppressedDuplicateDiag = 0;
        uint64_t lastDiagDroppedSummaryMs = 0;
        uint64_t lastDiagDroppedSummaryCount = 0;

        uint64_t stopDeadlineMs = 0;

        void ResetRuntimeObjects()
        {
            broadcaster.reset();

            statusPool.reset();
            eventPool.reset();
            rulePool.reset();

            statusChannel.reset();
            eventChannel.reset();
            ruleChannel.reset();

            statusSink.reset();
            eventSink.reset();
            ruleProvider.reset();
        }

        void SetLastError(const std::string &message, bool markDegraded)
        {
            std::lock_guard<std::mutex> lock(statsMutex);
            lastError = message;
            if (markDegraded) {
                degraded = true;
            }
        }

        bool StopDeadlineReached() const
        {
            return stopDeadlineMs != 0 && NowMs() >= stopDeadlineMs;
        }

        void StopPools()
        {
            if (statusPool) {
                statusPool->Stop();
            }
            if (eventPool) {
                eventPool->Stop();
            }
            if (rulePool) {
                rulePool->Stop();
            }
            pipeStarted.store(false);
        }

        RuntimePayloadEnvelope MakeEnvelope(AmsiIpcPayloadKind kind, const std::string &payload)
        {
            RuntimePayloadEnvelope envelope;
            envelope.kind = kind;
            envelope.rawJson = payload;
            envelope.receivedTimeMs = NowMs();
            return envelope;
        }

        void ResetQueues()
        {
            const AmsiIpcRuntimeQueueConfig &queueConfig = config.queueConfig;
            detectionQueue.Reset(queueConfig.detectionQueueCapacity, queueConfig.detectionQueueMaxBytes);
            dllDiagQueue.Reset(queueConfig.dllDiagnosticLogQueueCapacity, queueConfig.dllDiagnosticLogQueueMaxBytes);
            statusQueue.Reset(queueConfig.statusQueueCapacity, queueConfig.statusQueueMaxBytes);
        }

        void StartWorkers()
        {
            stopping.store(false);
            stopDeadlineMs = 0;
            detectionWorker = std::thread(&Impl::DetectionWorkerLoop, this);
            dllDiagWorker = std::thread(&Impl::DllDiagWorkerLoop, this);
            statusWorker = std::thread(&Impl::StatusWorkerLoop, this);
            workersStarted.store(true);
        }

        void StopQueuesAndWorkers(uint32_t timeoutMs)
        {
            stopping.store(true);
            stopDeadlineMs = NowMs() + timeoutMs;

            detectionQueue.Stop();
            dllDiagQueue.Stop();
            statusQueue.Stop();

            if (detectionWorker.joinable()) {
                detectionWorker.join();
            }
            if (dllDiagWorker.joinable()) {
                dllDiagWorker.join();
            }
            if (statusWorker.joinable()) {
                statusWorker.join();
            }

            detectionQueue.Clear();
            dllDiagQueue.Clear();
            statusQueue.Clear();
            workersStarted.store(false);
            stopDeadlineMs = 0;
        }

        void DropRemainingDetection()
        {
            const size_t dropped = detectionQueue.Size();
            if (dropped > 0) {
                detectionDropped.fetch_add(static_cast<uint64_t>(dropped));
                SetLastError("detection queue drain timeout, remaining payload dropped", true);
            }
            detectionQueue.StopAndDrop();
        }

        void DropRemainingDllDiag()
        {
            const size_t dropped = dllDiagQueue.Size();
            if (dropped > 0) {
                dllDiagDropped.fetch_add(static_cast<uint64_t>(dropped));
                SetLastError("dll diagnostic queue drain timeout, remaining payload dropped", true);
            }
            dllDiagQueue.StopAndDrop();
        }

        void DropRemainingStatus()
        {
            const size_t dropped = statusQueue.Size();
            if (dropped > 0) {
                statusDropped.fetch_add(static_cast<uint64_t>(dropped));
                SetLastError("status queue drain timeout, remaining payload dropped", true);
            }
            statusQueue.StopAndDrop();
        }

        void SubmitEventPayload(const std::string &payload)
        {
            if (payload.size() > config.queueConfig.maxPayloadBytes) {
                oversizedPayloadDropped.fetch_add(1);
                return;
            }

            const AmsiIpcPayloadKind kind = ClassifyAmsiEventPayload(payload);
            if (kind == AmsiIpcPayloadKind::Detection) {
                detectionReceived.fetch_add(1);
                const bool ok = detectionQueue.Push(
                    MakeEnvelope(kind, payload),
                    config.queueConfig.detectionEnqueueTimeoutMs,
                    true);
                if (!ok) {
                    detectionDropped.fetch_add(1);
                }
                return;
            }

            if (kind == AmsiIpcPayloadKind::DllDiagnosticLog) {
                dllDiagReceived.fetch_add(1);
                if (!dllDiagQueue.TryPush(MakeEnvelope(kind, payload))) {
                    dllDiagDropped.fetch_add(1);
                }
                return;
            }

            if (kind == AmsiIpcPayloadKind::DrainAck) {
                drainAckReceived.fetch_add(1);
                return;
            }

            unknownEventReceived.fetch_add(1);
        }

        void SubmitStatusPayload(const std::string &payload)
        {
            if (payload.size() > config.queueConfig.maxPayloadBytes) {
                oversizedPayloadDropped.fetch_add(1);
                return;
            }

            statusReceived.fetch_add(1);
            const bool ok = statusQueue.Push(
                MakeEnvelope(AmsiIpcPayloadKind::Status, payload),
                config.queueConfig.statusEnqueueTimeoutMs,
                true);
            if (!ok) {
                statusDropped.fetch_add(1);
                SetLastError("status queue full, payload dropped", true);
            }
        }

        void MaybeLogDllDiagDroppedSummary()
        {
            const uint64_t dropped = dllDiagDropped.load();
            if (dropped == lastDiagDroppedSummaryCount) {
                return;
            }

            const uint64_t now = NowMs();
            std::lock_guard<std::mutex> lock(diagMutex);
            if (lastDiagDroppedSummaryMs == 0 ||
                now - lastDiagDroppedSummaryMs >= kDiagDroppedSummaryIntervalMs) {
                const uint64_t delta = dropped - lastDiagDroppedSummaryCount;
                lastDiagDroppedSummaryMs = now;
                lastDiagDroppedSummaryCount = dropped;
                InfoLogf1(AmsiDetect::GetLoggerPtr(),
                          "Amsi dll diagnostic log queue dropped payloads in recent window: %llu.",
                          static_cast<unsigned long long>(delta));
            }
        }

        void FlushSuppressedDiagLocked()
        {
            if (suppressedDuplicateDiag > 0) {
                InfoLogf1(AmsiDetect::GetLoggerPtr(),
                          "Suppressed duplicate amsi dll diagnostic log count: %llu.",
                          static_cast<unsigned long long>(suppressedDuplicateDiag));
                suppressedDuplicateDiag = 0;
            }
        }

        void LogDllDiagnosticPayload(const std::string &payload)
        {
            const uint64_t now = NowMs();
            const std::string key = DiagnosticKey(payload);
            const size_t rawLen = payload.size();
            const std::string line = TruncateForLog(payload, config.queueConfig.dllDiagnosticLogMaxLineBytes);

            std::lock_guard<std::mutex> lock(diagMutex);
            if (!lastDiagKey.empty() &&
                key == lastDiagKey &&
                now - lastDiagLogMs < config.queueConfig.dllDiagnosticDuplicateWindowMs) {
                ++suppressedDuplicateDiag;
                return;
            }

            FlushSuppressedDiagLocked();
            lastDiagKey = key;
            lastDiagLogMs = now;
            InfoLogf2(AmsiDetect::GetLoggerPtr(),
                      "Recv amsi dll diagnostic payload rawLen=%llu payload: %s.",
                      static_cast<unsigned long long>(rawLen),
                      line.c_str());
        }

        void DetectionWorkerLoop()
        {
            RuntimePayloadEnvelope item;
            while (detectionQueue.Pop(item)) {
                if (stopping.load() && StopDeadlineReached()) {
                    DropRemainingDetection();
                    break;
                }
                const std::string line = TruncateForLog(item.rawJson, config.queueConfig.dllDiagnosticLogMaxLineBytes);
                InfoLogf2(AmsiDetect::GetLoggerPtr(),
                          "Recv amsi detection event rawLen=%llu payload: %s.",
                          static_cast<unsigned long long>(item.rawJson.size()),
                          line.c_str());
            }
        }

        void DllDiagWorkerLoop()
        {
            RuntimePayloadEnvelope item;
            while (dllDiagQueue.Pop(item)) {
                if (stopping.load() && StopDeadlineReached()) {
                    DropRemainingDllDiag();
                    break;
                }
                MaybeLogDllDiagDroppedSummary();
                LogDllDiagnosticPayload(item.rawJson);
            }

            std::lock_guard<std::mutex> lock(diagMutex);
            FlushSuppressedDiagLocked();
        }

        void StatusWorkerLoop()
        {
            RuntimePayloadEnvelope item;
            while (statusQueue.Pop(item)) {
                if (stopping.load() && StopDeadlineReached()) {
                    DropRemainingStatus();
                    break;
                }
                const std::string line = TruncateForLog(item.rawJson, config.queueConfig.dllDiagnosticLogMaxLineBytes);
                InfoLogf2(AmsiDetect::GetLoggerPtr(),
                          "Recv amsi control status payload rawLen=%llu payload: %s.",
                          static_cast<unsigned long long>(item.rawJson.size()),
                          line.c_str());
            }
        }
    };

    AmsiIpcRuntime::AmsiIpcRuntime() : m_impl(new Impl())
    {
    }

    AmsiIpcRuntime::~AmsiIpcRuntime()
    {
        std::string error;
        Stop(3000, error);
    }

    bool AmsiIpcRuntime::Init(const AmsiIpcRuntimeConfig &config, std::string &error)
    {
        if (!config.amsiIpcEnabled) {
            error = "amsi ipc is disabled";
            return false;
        }
        if (!config.enableRealIpc) {
            error = "real ipc is disabled";
            return false;
        }
        if (!config.useProductionPipes) {
            error = "production pipe mode is required";
            return false;
        }

        m_impl->config = config;
        m_impl->initialized.store(true);
        m_impl->running.store(false);
        m_impl->stopping.store(false);
        m_impl->pipeStarted.store(false);
        m_impl->workersStarted.store(false);
        {
            std::lock_guard<std::mutex> lock(m_impl->statsMutex);
            m_impl->lastError.clear();
            m_impl->degraded = false;
        }
        error.clear();
        InfoLog(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime initialized with production pipes.");
        return true;
    }

    bool AmsiIpcRuntime::Start(const AmsiRuleSnapshot &snapshot, std::string &error)
    {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }
        if (m_impl->running.load()) {
            return UpdateRules(snapshot, error);
        }

        m_impl->ruleProvider.reset(new RuntimeRuleProvider());
        if (!m_impl->ruleProvider->UpdateSnapshot(snapshot, error)) {
            m_impl->ResetRuntimeObjects();
            return false;
        }
        m_impl->ResetQueues();
        m_impl->StartWorkers();

        if (PipeHasExistingServer(kRulesPipeName)) {
            error = "production rules pipe already has a server";
            m_impl->StopQueuesAndWorkers(3000);
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (PipeHasExistingServer(kEventsPipeName)) {
            error = "production events pipe already has a server";
            m_impl->StopQueuesAndWorkers(3000);
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (PipeHasExistingServer(kControlStatusPipeName)) {
            error = "production control status pipe already has a server";
            m_impl->StopQueuesAndWorkers(3000);
            m_impl->ResetRuntimeObjects();
            return false;
        }

        m_impl->eventSink.reset(new RuntimeEventSink([this](const std::string &payload) {
            m_impl->SubmitEventPayload(payload);
        }));
        m_impl->statusSink.reset(new RuntimeControlStatusSink([this](const std::string &payload) {
            m_impl->SubmitStatusPayload(payload);
        }));

        m_impl->ruleChannel.reset(new amsi_ipc::AmsiRuleChannel(*m_impl->ruleProvider));
        m_impl->eventChannel.reset(new amsi_ipc::AmsiEventChannel(*m_impl->eventSink));
        m_impl->statusChannel.reset(new amsi_ipc::AmsiControlStatusChannel(*m_impl->statusSink));

        m_impl->rulePool.reset(new amsi_ipc::NamedPipeServerPool(kRulesPipeName, kRulePipeThreads, *m_impl->ruleChannel));
        m_impl->eventPool.reset(new amsi_ipc::NamedPipeServerPool(kEventsPipeName, kEventPipeThreads, *m_impl->eventChannel));
        m_impl->statusPool.reset(new amsi_ipc::NamedPipeServerPool(kControlStatusPipeName, kStatusPipeThreads, *m_impl->statusChannel));

        if (!m_impl->rulePool->Start()) {
            error = "start rules pipe failed";
            m_impl->StopPools();
            m_impl->StopQueuesAndWorkers(3000);
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (!m_impl->eventPool->Start()) {
            error = "start events pipe failed";
            m_impl->StopPools();
            m_impl->StopQueuesAndWorkers(3000);
            m_impl->ResetRuntimeObjects();
            return false;
        }
        if (!m_impl->statusPool->Start()) {
            error = "start control status pipe failed";
            m_impl->StopPools();
            m_impl->StopQueuesAndWorkers(3000);
            m_impl->ResetRuntimeObjects();
            return false;
        }

        m_impl->broadcaster.reset(new amsi_ipc::AmsiConfigBroadcaster(kConfigPipeName));
        m_impl->snapshot = snapshot;
        m_impl->pipeStarted.store(true);
        m_impl->running.store(true);

        InfoLogf2(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime started, rule version=%s hash=%s.",
                  snapshot.version.c_str(), snapshot.hash.c_str());
        error.clear();
        return true;
    }

    bool AmsiIpcRuntime::Stop(uint32_t timeoutMs, std::string &error)
    {
        if (!m_impl) {
            error.clear();
            return true;
        }

        m_impl->StopPools();
        m_impl->StopQueuesAndWorkers(timeoutMs);
        m_impl->ResetRuntimeObjects();
        m_impl->running.store(false);
        m_impl->stopping.store(false);
        error.clear();
        InfoLog(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime stopped.");
        return true;
    }

    bool AmsiIpcRuntime::PauseDetection(uint32_t timeoutMs, std::string &error)
    {
        if (!m_impl->running.load() || !m_impl->broadcaster) {
            error.clear();
            return true;
        }

        const amsi_ipc::AmsiBroadcastResult result =
            m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::PauseDetection,
                                           kBroadcastMaxListeners,
                                           timeoutMs);
        return BroadcastSucceeded(result, error);
    }

    bool AmsiIpcRuntime::UpdateRules(const AmsiRuleSnapshot &snapshot, std::string &error)
    {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }

        if (m_impl->ruleProvider && !m_impl->ruleProvider->UpdateSnapshot(snapshot, error)) {
            return false;
        }

        m_impl->snapshot = snapshot;
        error.clear();
        return true;
    }

    bool AmsiIpcRuntime::Reload(uint32_t timeoutMs, std::string &error)
    {
        if (!m_impl->running.load() || !m_impl->broadcaster) {
            error = "amsi ipc runtime is not running";
            return false;
        }

        const amsi_ipc::AmsiBroadcastResult result =
            m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::Reload,
                                           kBroadcastMaxListeners,
                                           timeoutMs);
        return BroadcastSucceeded(result, error);
    }

    bool AmsiIpcRuntime::IsRunning() const
    {
        return m_impl && m_impl->running.load();
    }

    AmsiIpcRuntimeStats AmsiIpcRuntime::GetStats() const
    {
        AmsiIpcRuntimeStats stats;
        if (!m_impl) {
            return stats;
        }

        stats.initialized = m_impl->initialized.load();
        stats.running = m_impl->running.load();
        stats.stopping = m_impl->stopping.load();
        stats.workersStarted = m_impl->workersStarted.load();
        stats.pipeStarted = m_impl->pipeStarted.load();

        stats.detectionReceived = m_impl->detectionReceived.load();
        stats.detectionDropped = m_impl->detectionDropped.load();
        stats.dllDiagReceived = m_impl->dllDiagReceived.load();
        stats.dllDiagDropped = m_impl->dllDiagDropped.load();
        stats.statusReceived = m_impl->statusReceived.load();
        stats.statusDropped = m_impl->statusDropped.load();
        stats.drainAckReceived = m_impl->drainAckReceived.load();
        stats.unknownEventReceived = m_impl->unknownEventReceived.load();
        stats.oversizedPayloadDropped = m_impl->oversizedPayloadDropped.load();

        stats.detectionQueueSize = m_impl->detectionQueue.Size();
        stats.detectionQueueBytes = m_impl->detectionQueue.Bytes();
        stats.dllDiagQueueSize = m_impl->dllDiagQueue.Size();
        stats.dllDiagQueueBytes = m_impl->dllDiagQueue.Bytes();
        stats.statusQueueSize = m_impl->statusQueue.Size();
        stats.statusQueueBytes = m_impl->statusQueue.Bytes();

        {
            std::lock_guard<std::mutex> lock(m_impl->statsMutex);
            stats.lastError = m_impl->lastError;
            stats.degraded = m_impl->degraded;
        }
        return stats;
    }

}

//
// Created by z00840245 on 2026/5/21.
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
#include "AmsiEventProcessor.h"
#include "AmsiGlobalConf.h"
#include "JsonUtils.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <atomic>
#include <cctype>
#include <functional>
#include <mutex>
#include <thread>
#include <utility>

namespace Engine {
    namespace {

        const wchar_t *kRulesPipeName = L"\\\\.\\pipe\\amsi_detect_rules";
        const wchar_t *kEventsPipeName = L"\\\\.\\pipe\\amsi_detect_events";
        const wchar_t *kLogsPipeName = L"\\\\.\\pipe\\amsi_detect_logs";
        const wchar_t *kControlStatusPipeName = L"\\\\.\\pipe\\amsi_detect_control_status";
        constexpr DWORD kRulePipeOutBufferBytes = 512 * 1024;
        constexpr DWORD kRulePipeInBufferBytes = 256;

        /**
         * Runtime rule provider backed by the in-memory AmsiRuleSnapshot.
         */
        std::string BuildUpgradeUnloadingRulesJson(const std::string &stateVersion, const std::string &ruleVersion, const std::string &requiredDllHash) {
            SDK::JsonUtils::JsonValue envelope;
            SDK::JsonUtils::JsonValue rules;
            envelope["desiredRuntimeState"] = "unloading";
            envelope["state"] = "unload";
            envelope["stateVersion"] = stateVersion;
            envelope["ruleVersion"] = ruleVersion;
            if (!requiredDllHash.empty()) {
                envelope["requiredDllHash"] = requiredDllHash;
            }
            envelope["rules"] = rules;
            return SDK::JsonUtils::JsonToString(envelope);
        }
        bool BuildProviderSnapshot(const AmsiDetect::AmsiRuleSnapshot &snapshot,
                                   AmsiDetect::AmsiRuleSnapshot &providerSnapshot,
                                   std::string &error) {
            providerSnapshot = snapshot;
            if (providerSnapshot.requiredDllHash.empty()) {
                error.clear();
                return true;
            }

            SDK::JsonUtils::JsonValue root;
            if (SDK::JsonUtils::ParseJsonStr(providerSnapshot.amsiRulesJson.c_str(),
                                             providerSnapshot.amsiRulesJson.length(),
                                             root) != 0) {
                error = "parse amsi rules state envelope failed";
                return false;
            }

            root["requiredDllHash"] = providerSnapshot.requiredDllHash;
            providerSnapshot.amsiRulesJson = SDK::JsonUtils::JsonToString(root);
            error.clear();
            return true;
        }
        class RuntimeRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
        public:
            bool UpdateSnapshot(const AmsiDetect::AmsiRuleSnapshot &snapshot, std::string &error) {
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
                                    std::string &error) override {
                std::lock_guard<std::mutex> lock(mutex_);
                if (command == "GET_ALL_RULES") {
                    out.json = snapshot_.amsiRulesJson;
                    error.clear();
                    return !out.json.empty();
                }
                error = "unsupported rules command: " + command;
                return false;
            }

            void InvalidateRuleCache() override {}

        private:
            std::mutex mutex_;
            AmsiDetect::AmsiRuleSnapshot snapshot_;
        };

        /**
         * ????? Sink ????????????????????? lambda ???????onEvent_ / onStatus_????
         * ??????????????????????????????????? SubmitEventPayload
         */
        class RuntimeEventSink final : public amsi_ipc::IAmsiEventSink {
        public:
            explicit RuntimeEventSink(std::function<void(const std::string &)> onEvent)
                    : onEvent_(std::move(onEvent)) {
            }

            void OnEventLine(const amsi_ipc::AmsiEventLine &event) override {
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
                    : onStatus_(std::move(onStatus)) {
            }

            void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine &status) override {
                if (onStatus_) {
                    onStatus_(status.payload);
                }
            }

        private:
            std::function<void(const std::string &)> onStatus_;
        };

        bool BroadcastSucceeded(const amsi_ipc::AmsiBroadcastResult &result, std::string &error) {
            if (result.lastError != 0) {
                error = "broadcast failed, lastError=" + std::to_string(result.lastError);
                return false;
            }

            error.clear();
            return true;
        }

        bool PipeHasExistingServer(const wchar_t *pipeName) {
            if (WaitNamedPipeW(pipeName, 1)) {
                return true;
            }

            const DWORD lastError = GetLastError();
            return lastError != ERROR_FILE_NOT_FOUND && lastError != ERROR_PATH_NOT_FOUND;
        }

        uint64_t NowMs() {
            return static_cast<uint64_t>(GetTickCount64());
        }

        std::string TruncateForLog(const std::string &payload, size_t maxBytes) {
            static const char kSuffix[] = "...<truncated>";
            const size_t suffixLen = sizeof(kSuffix) - 1;
            if (payload.size() <= maxBytes) {
                return payload;
            }
            if (maxBytes == 0) {
                return std::string();
            }
            if (maxBytes <= suffixLen) {
                return std::string(kSuffix, maxBytes);
            }
            return payload.substr(0, maxBytes - suffixLen) + kSuffix;
        }

        bool ExtractJsonStringField(const std::string &payload,
                                    const char *fieldName,
                                    std::string &value) {
            const std::string key = std::string("\"") + fieldName + "\"";
            const std::string::size_type keyPos = payload.find(key);
            if (keyPos == std::string::npos) {
                return false;
            }

            const std::string::size_type colonPos = payload.find(':', keyPos + key.size());
            if (colonPos == std::string::npos) {
                return false;
            }

            std::string::size_type valuePos = colonPos + 1;
            while (valuePos < payload.size() &&
                   (payload[valuePos] == ' ' || payload[valuePos] == '\t' ||
                    payload[valuePos] == '\r' || payload[valuePos] == '\n')) {
                ++valuePos;
            }
            if (valuePos >= payload.size() || payload[valuePos] != '"') {
                return false;
            }

            std::string result;
            bool escaping = false;
            for (std::string::size_type i = valuePos + 1; i < payload.size(); ++i) {
                const char ch = payload[i];
                if (escaping) {
                    switch (ch) {
                        case '"':
                        case '\\':
                        case '/':
                            result.push_back(ch);
                            break;
                        case 'b':
                            result.push_back('\b');
                            break;
                        case 'f':
                            result.push_back('\f');
                            break;
                        case 'n':
                            result.push_back('\n');
                            break;
                        case 'r':
                            result.push_back('\r');
                            break;
                        case 't':
                            result.push_back('\t');
                            break;
                        case 'u':
                            return false;
                        default:
                            return false;
                    }
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

        std::string DiagnosticKey(const std::string &payload) {
            std::string pattern;
            std::string desc;
            ExtractJsonStringField(payload, "pattern", pattern);
            ExtractJsonStringField(payload, "desc", desc);
            if (!pattern.empty() || !desc.empty()) {
                return pattern + "|" + desc;
            }
            return payload;
        }

        enum class DllDiagLogLevel {
            Debug,
            Info,
            Warning,
            Error
        };

        /**
         * ?????? JSON ????????????????????????
         * @param payload ???????????????? JSON ?????????????????
         * @return  ??????????????????????????????? DllDiagLogLevel::Info
         */
        DllDiagLogLevel ParseDllDiagLogLevel(const std::string &payload) {
            std::string severity;
            if (!ExtractJsonStringField(payload, "sev", severity)) {
                return DllDiagLogLevel::Info;
            }

            for (char &ch: severity) {
                ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
            }

            if (severity == "debug") {
                return DllDiagLogLevel::Debug;
            }
            if (severity == "warning" || severity == "warn") {
                return DllDiagLogLevel::Warning;
            }
            if (severity == "error") {
                return DllDiagLogLevel::Error;
            }
            return DllDiagLogLevel::Info;
        }

        /**
         * ????????§Õ
         * @param level  ????????????????
         * @param rawLen  ?????????????
         * @param line  ??????????????????????? JSON ?????
         */
        void WriteDllDiagnosticLog(DllDiagLogLevel level,
                                   size_t rawLen,
                                   const std::string &line) {
            switch (level) {
                case DllDiagLogLevel::Debug:
                    DebugLogf(AmsiDetect::GetLoggerPtr(),
                              "Recv dll rawLen=%lu payload: %s.",
                              static_cast<unsigned long>(rawLen),
                              line);
                    break;
                case DllDiagLogLevel::Warning:
                    WarningLogf2(AmsiDetect::GetLoggerPtr(),
                                 "Recv dll rawLen=%lu payload: %s.",
                                 static_cast<unsigned long>(rawLen),
                                 line);
                    break;
                case DllDiagLogLevel::Error:
                    ErrorLogf2(AmsiDetect::GetLoggerPtr(),
                               "Recv dll rawLen=%lu payload: %s.",
                               static_cast<unsigned long>(rawLen),
                               line);
                    break;
                case DllDiagLogLevel::Info:
                default:
                    InfoLogf2(AmsiDetect::GetLoggerPtr(),
                              "Recv dll rawLen=%lu payload: %s.",
                              static_cast<unsigned long>(rawLen),
                              line);
                    break;
            }
        }
    }

    struct AmsiIpcRuntime::Impl {
        AmsiIpcRuntimeConfig config;
        AmsiDetect::AmsiRuleSnapshot snapshot;
        AmsiDetect::AmsiRuleSnapshot preUpgradeSnapshot;
        bool hasPreUpgradeSnapshot = false;

        std::unique_ptr<RuntimeRuleProvider> ruleProvider;
        std::unique_ptr<RuntimeEventSink> eventSink;
        std::unique_ptr<RuntimeEventSink> logSink;
        std::unique_ptr<RuntimeControlStatusSink> statusSink;

        std::unique_ptr<amsi_ipc::AmsiRuleChannel> ruleChannel;
        std::unique_ptr<amsi_ipc::AmsiEventChannel> eventChannel;
        std::unique_ptr<amsi_ipc::AmsiEventChannel> logChannel;
        std::unique_ptr<amsi_ipc::AmsiControlStatusChannel> statusChannel;

        std::unique_ptr<amsi_ipc::NamedPipeServerPool> rulePool;
        std::unique_ptr<amsi_ipc::NamedPipeServerPool> eventPool;
        std::unique_ptr<amsi_ipc::NamedPipeServerPool> logPool;
        std::unique_ptr<amsi_ipc::NamedPipeServerPool> statusPool;
        BoundedPayloadQueue detectionQueue;
        BoundedPayloadQueue dllDiagQueue;
        BoundedPayloadQueue statusQueue;

        std::thread detectionWorker;
        std::thread dllDiagWorker;
        std::thread statusWorker;

        std::atomic<bool> initialized{false};
        std::atomic<bool> running{false};
        std::atomic<bool> stopping{false};
        std::atomic<bool> acceptingPayload{false};
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

        mutable std::mutex broadcastMutex;
        AmsiIpcBroadcastSummary lastReloadBroadcast;
        AmsiIpcBroadcastSummary lastPauseBroadcast;
        AmsiIpcBroadcastSummary lastResumeBroadcast;
        AmsiIpcBroadcastSummary lastUnloadBroadcast;

        /**
         * ??????????????????§Ö??????Pool????????????Channel?????????????Sink????????????
         * ?????????????????????????????????
         */
        void ResetRuntimeObjects() {
            acceptingPayload.store(false);
            statusPool.reset();
            logPool.reset();
            eventPool.reset();
            rulePool.reset();

            statusChannel.reset();
            logChannel.reset();
            eventChannel.reset();
            ruleChannel.reset();

            statusSink.reset();
            logSink.reset();
            eventSink.reset();
            ruleProvider.reset();
        }

        void SetLastError(const std::string &message, bool markDegraded) {
            std::lock_guard<std::mutex> lock(statsMutex);
            lastError = message;
            if (markDegraded) {
                degraded = true;
            }
        }

        void StoreBroadcastSummary(const std::string &command,
                                   uint32_t timeoutMs,
                                   const amsi_ipc::AmsiBroadcastResult &result) {
            AmsiIpcBroadcastSummary summary;
            summary.command = command;
            summary.reached = static_cast<uint32_t>(result.reached < 0 ? 0 : result.reached);
            summary.lastError = static_cast<uint32_t>(result.lastError);
            summary.timeoutMs = timeoutMs;

            std::lock_guard<std::mutex> lock(broadcastMutex);
            if (command == "reload") {
                lastReloadBroadcast = summary;
            } else if (command == "pause") {
                lastPauseBroadcast = summary;
            } else if (command == "resume") {
                lastResumeBroadcast = summary;
            } else if (command == "unload") {
                lastUnloadBroadcast = summary;
            }
        }

        bool StopDeadlineReached() const {
            return stopDeadlineMs != 0 && NowMs() >= stopDeadlineMs;
        }

        void StopPools() {
            if (statusPool) {
                statusPool->Stop();
            }
            if (logPool) {
                logPool->Stop();
            }
            if (eventPool) {
                eventPool->Stop();
            }
            if (rulePool) {
                rulePool->Stop();
            }
            pipeStarted.store(false);
        }

        RuntimePayloadEnvelope MakeEnvelope(AmsiIpcPayloadKind kind, const std::string &payload) {
            RuntimePayloadEnvelope envelope;
            envelope.kind = kind;
            envelope.rawJson = payload;
            envelope.receivedTimeMs = NowMs();
            return envelope;
        }

        /*
         * ???????? config.queueConfig ??????????????????? Bounded ???????§µ????????????
         * ???????????????????? stopped_ ????¦Ë
         */
        void ResetQueues() {
            detectionQueue.Reset(AmsiGlobalConfRef.GetDetectionQueueCapacity(),
                                 AmsiGlobalConfRef.GetDetectionQueueMaxBytes());
            dllDiagQueue.Reset(AmsiGlobalConfRef.GetDllDiagnosticLogQueueCapacity(),
                               AmsiGlobalConfRef.GetDllDiagnosticLogQueueMaxBytes());
            statusQueue.Reset(AmsiGlobalConfRef.GetStatusQueueCapacity(), AmsiGlobalConfRef.GetStatusQueueMaxBytes());
        }

        /**
         * ???? 3 ????????????????????detectionWorker, dllDiagWorker, statusWorker??
         * ?????????????????????§µ??????????
         */
        void StartWorkers() {
            stopping.store(false);
            stopDeadlineMs = 0;
            detectionWorker = std::thread(&Impl::DetectionWorkerLoop, this);
            dllDiagWorker = std::thread(&Impl::DllDiagWorkerLoop, this);
            statusWorker = std::thread(&Impl::StatusWorkerLoop, this);
            workersStarted.store(true);
        }

        /**
         * ????????????????????? stopping ????? true?????????????????§Ö????????????????§á??? Pop/Push ??????
         * ??? join() ??? 3 ????????????????????? Clear() ??????
         * @param timeoutMs  ????????????????????????
         */
        void StopQueuesAndWorkers(uint32_t timeoutMs) {
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

        void DropRemainingDetection() {
            const size_t dropped = detectionQueue.Size();
            if (dropped > 0) {
                detectionDropped.fetch_add(static_cast<uint64_t>(dropped));
                SetLastError("detection queue drain timeout, remaining payload dropped", true);
            }
            detectionQueue.StopAndDrop();
        }

        void DropRemainingDllDiag() {
            const size_t dropped = dllDiagQueue.Size();
            if (dropped > 0) {
                dllDiagDropped.fetch_add(static_cast<uint64_t>(dropped));
                SetLastError("dll diagnostic queue drain timeout, remaining payload dropped", true);
            }
            dllDiagQueue.StopAndDrop();
        }

        void DropRemainingStatus() {
            const size_t dropped = statusQueue.Size();
            if (dropped > 0) {
                statusDropped.fetch_add(static_cast<uint64_t>(dropped));
                SetLastError("status queue drain timeout, remaining payload dropped", true);
            }
            statusQueue.StopAndDrop();
        }

        /**
         * ?????????????????? JSON????????§Ù???????????????????????§³???? AmsiGlobalConfRef.GetMaxPayloadBytes() ????????????
         * ???????????????? ClassifyAmsiEventPayload ???§Ù???
         * @param payload
         */
        void SubmitEventPayload(const std::string &payload) {
            if (!acceptingPayload.load()) {
                return;
            }
            if (payload.size() > AmsiGlobalConfRef.GetMaxPayloadBytes()) {
                oversizedPayloadDropped.fetch_add(1);
                return;
            }

            const AmsiIpcPayloadKind kind = ClassifyAmsiEventPayload(payload);
            if (kind == AmsiIpcPayloadKind::Detection) {
                detectionReceived.fetch_add(1);
                const bool ok = detectionQueue.Push(
                        MakeEnvelope(kind, payload),
                        AmsiGlobalConfRef.GetDetectionEnqueueTimeoutMs(),
                        true);
                if (!ok) {
                    detectionDropped.fetch_add(1);
                }
                return;
            }
            if (kind == AmsiIpcPayloadKind::DrainAck) {
                drainAckReceived.fetch_add(1);
                return;
            }

            unknownEventReceived.fetch_add(1);
        }

        void SubmitDllDiagnosticPayload(const std::string &payload) {
            if (!acceptingPayload.load()) {
                return;
            }
            if (payload.size() > AmsiGlobalConfRef.GetMaxPayloadBytes()) {
                oversizedPayloadDropped.fetch_add(1);
                return;
            }

            dllDiagReceived.fetch_add(1);
            if (!dllDiagQueue.TryPush(MakeEnvelope(AmsiIpcPayloadKind::DllDiagnosticLog, payload))) {
                dllDiagDropped.fetch_add(1);
            }
        }

        /**
         * ???????????????????????????????????? statusQueue?????????????????????????????? Degraded????????
         * @param payload
         */
        void SubmitStatusPayload(const std::string &payload) {
            if (!acceptingPayload.load()) {
                return;
            }
            if (payload.size() > AmsiGlobalConfRef.GetMaxPayloadBytes()) {
                oversizedPayloadDropped.fetch_add(1);
                return;
            }

            statusReceived.fetch_add(1);
            const bool ok = statusQueue.Push(
                    MakeEnvelope(AmsiIpcPayloadKind::Status, payload),
                    AmsiGlobalConfRef.GetStatusEnqueueTimeoutMs(),
                    true);
            if (!ok) {
                statusDropped.fetch_add(1);
                SetLastError("status queue full, payload dropped", true);
            }
        }

        void MaybeLogDllDiagDroppedSummary() {
            const uint64_t dropped = dllDiagDropped.load();
            if (dropped == lastDiagDroppedSummaryCount) {
                return;
            }

            const uint64_t now = NowMs();
            std::lock_guard<std::mutex> lock(diagMutex);
            if (lastDiagDroppedSummaryMs == 0 ||
                now - lastDiagDroppedSummaryMs >= AmsiGlobalConfRef.GetDiagDroppedSummaryIntervalMs()) {
                const uint64_t delta = dropped - lastDiagDroppedSummaryCount;
                lastDiagDroppedSummaryMs = now;
                lastDiagDroppedSummaryCount = dropped;
                InfoLogf1(AmsiDetect::GetLoggerPtr(),
                          "Amsi dll diagnostic log queue dropped payloads in recent window: %lu.",
                          static_cast<unsigned long>(delta));
            }
        }

        void FlushSuppressedDiagLocked() {
            if (suppressedDuplicateDiag > 0) {
                InfoLogf1(AmsiDetect::GetLoggerPtr(),
                          "Suppressed duplicate amsi dll diagnostic log count: %lu.",
                          static_cast<unsigned long>(suppressedDuplicateDiag));
                suppressedDuplicateDiag = 0;
            }
        }

        /**
         * ???????????????????? hss_amsi.dll ???????????????????????????????????????????????????
         * ?¨²?????????????????????????; ???????§Ö? pattern ?? desc ???¦·? Key???????? Key ??????¦²?lastDiagKey???????
         * ???????§³??????? dllDiagnosticDuplicateWindowMs???????????????????????? suppressedDuplicateDiag ??????
         * @param payload
         */
        void LogDllDiagnosticPayload(const std::string &payload) {
            const uint64_t now = NowMs();
            const std::string key = DiagnosticKey(payload);
            const size_t rawLen = payload.size();
            const std::string line = TruncateForLog(payload, AmsiGlobalConfRef.GetDllDiagnosticLogMaxLineBytes());

            std::lock_guard<std::mutex> lock(diagMutex);
            if (!lastDiagKey.empty() &&
                key == lastDiagKey &&
                now - lastDiagLogMs < AmsiGlobalConfRef.GetDllDiagnosticDuplicateWindowMs()) {
                ++suppressedDuplicateDiag;
                return;
            }

            FlushSuppressedDiagLocked();
            lastDiagKey = key;
            lastDiagLogMs = now;
            WriteDllDiagnosticLog(ParseDllDiagLogLevel(payload), rawLen, line);
        }

        /**
         * DetectionWorkerLoop() / DllDiagWorkerLoop() / StatusWorkerLoop()
         * ??????????: ??? queue.Pop(item) ??????????????????????????§Ý???????? TruncateForLog ???§ß??
         * ???????????????????????????????????? InfoLogf2 §Õ??????????????????
         */
        void DetectionWorkerLoop() {
            RuntimePayloadEnvelope item;
            while (detectionQueue.Pop(item)) {
                if (stopping.load() && StopDeadlineReached()) {
                    DropRemainingDetection();
                    break;
                }
                const std::string line = TruncateForLog(item.rawJson, AmsiGlobalConfRef.GetDetectionLogMaxLineBytes());
                std::string error;
                if (!AmsiEventProcessor::ProcessDetectionEvent(item.rawJson, error)) {
                    ErrorLogf1(AmsiDetect::GetLoggerPtr(),
                               "Process amsi detection event failed: %s.",
                               error.c_str());
                }
            }
        }

        void DllDiagWorkerLoop() {
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

        void StatusWorkerLoop() {
            RuntimePayloadEnvelope item;
            while (statusQueue.Pop(item)) {
                if (stopping.load() && StopDeadlineReached()) {
                    DropRemainingStatus();
                    break;
                }
                const std::string line = TruncateForLog(item.rawJson, AmsiGlobalConfRef.GetStatusLogMaxLineBytes());
                InfoLogf2(AmsiDetect::GetLoggerPtr(),
                          "Recv amsi control status payload rawLen=%lu payload: %s.",
                          static_cast<unsigned long>(item.rawJson.size()),
                          line);
            }
        }
    };

    AmsiIpcRuntime::AmsiIpcRuntime() : m_impl(new Impl()) {
    }

    AmsiIpcRuntime::~AmsiIpcRuntime() {
        std::string error;
        Stop(3000, error);
    }

    /**
     * ???????: ???????????????????????????? amsiIpcEnabled ????? true????
     * ??????????????????????????????????????????????????????
     * @param config  ???????¨°???????
     * @param error  ???????????
     * @return  ???¦Ä???? IPC ????œY?? false????????? true
     */
    bool AmsiIpcRuntime::Init(const AmsiIpcRuntimeConfig &config, std::string &error) {
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

    /**
     * ???????????
     * @param snapshot  ???????????????????????? JSON??
     * @param error  ???????????
     * @return  ?¦Ê???????????????????????????????????? false
     */
    bool AmsiIpcRuntime::Start(const AmsiDetect::AmsiRuleSnapshot &snapshot, std::string &error) {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }
        if (m_impl->running.load()) {
            return UpdateRules(snapshot, error);  // §µ??: ????????????????????
        }

        // ???? ResetQueues() ?? StartWorkers() ?????????
        AmsiDetect::AmsiRuleSnapshot providerSnapshot;
        if (!BuildProviderSnapshot(snapshot, providerSnapshot, error)) {
            m_impl->ResetRuntimeObjects();
            return false;
        }
        m_impl->ruleProvider.reset(new RuntimeRuleProvider());
        if (!m_impl->ruleProvider->UpdateSnapshot(providerSnapshot, error)) {
            m_impl->ResetRuntimeObjects();
            return false;
        }
        m_impl->ResetQueues();
        m_impl->StartWorkers();
        // ???? PipeHasExistingServer ????? 3 ???????????????? Windows ?????????????????????
        // ??????????????????????????e???????¦Ä??????????????????????????????????????§Û?
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
        if (PipeHasExistingServer(kLogsPipeName)) {
            error = "production logs pipe already has a server";
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
            if (m_impl && m_impl->acceptingPayload.load()) {
                m_impl->SubmitEventPayload(payload);
            }
        }));
        m_impl->logSink.reset(new RuntimeEventSink([this](const std::string &payload) {
            if (m_impl && m_impl->acceptingPayload.load()) {
                m_impl->SubmitDllDiagnosticPayload(payload);
            }
        }));
        m_impl->statusSink.reset(new RuntimeControlStatusSink([this](const std::string &payload) {
            if (m_impl && m_impl->acceptingPayload.load()) {
                m_impl->SubmitStatusPayload(payload);
            }
        }));

        m_impl->ruleChannel.reset(new amsi_ipc::AmsiRuleChannel(*m_impl->ruleProvider));
        m_impl->eventChannel.reset(new amsi_ipc::AmsiEventChannel(*m_impl->eventSink));
        m_impl->logChannel.reset(new amsi_ipc::AmsiEventChannel(*m_impl->logSink));
        m_impl->statusChannel.reset(new amsi_ipc::AmsiControlStatusChannel(*m_impl->statusSink));

        m_impl->rulePool.reset(
                new amsi_ipc::NamedPipeServerPool(kRulesPipeName, AmsiGlobalConfRef.GetRulePipeNums(),
                                                  *m_impl->ruleChannel,
                                                  kRulePipeOutBufferBytes,
                                                  kRulePipeInBufferBytes));
        m_impl->eventPool.reset(
                new amsi_ipc::NamedPipeServerPool(kEventsPipeName, AmsiGlobalConfRef.GetEventPipeThreads(),
                                                  *m_impl->eventChannel));
        m_impl->logPool.reset(
                new amsi_ipc::NamedPipeServerPool(kLogsPipeName, AmsiGlobalConfRef.GetEventPipeThreads(),
                                                  *m_impl->logChannel));
        m_impl->statusPool.reset(
                new amsi_ipc::NamedPipeServerPool(kControlStatusPipeName, AmsiGlobalConfRef.GetStatusPipeThreads(),
                                                  *m_impl->statusChannel));

        // ???????? 3 ?? Pool ?? Start()??????? Windows ??????????????????????????
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
        if (!m_impl->logPool->Start()) {
            error = "start logs pipe failed";
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
        m_impl->acceptingPayload.store(true);
        m_impl->snapshot = providerSnapshot;
        m_impl->hasPreUpgradeSnapshot = false;
        m_impl->pipeStarted.store(true);
        m_impl->running.store(true);

        InfoLogf1(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime started, rule version=%s.", snapshot.version);
        error.clear();
        return true;
    }

    /**
     * ???¦É??????????????????????????????????????????????????§Ö???????????????¨²????????????????????????
     * @param timeoutMs  ?????????????????????????
     * @param error  ??????? true
     * @return
     */
    bool AmsiIpcRuntime::Stop(uint32_t timeoutMs, std::string &error) {
        if (!m_impl) {
            error.clear();
            return true;
        }

        m_impl->acceptingPayload.store(false);
        m_impl->StopPools();
        m_impl->StopQueuesAndWorkers(timeoutMs);
        m_impl->ResetRuntimeObjects();
        m_impl->running.store(false);
        m_impl->stopping.store(false);
        error.clear();
        InfoLog(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime stopped.");
        return true;
    }

    /**
     * ???¦Ì?????????????????????????????????y??; ????????????? ruleProvider ?§Ö????????
     * @param snapshot  ?¦Ì?????????????
     * @param error ???????
     * @return ??????? true
     */
    bool AmsiIpcRuntime::UpdateRules(const AmsiDetect::AmsiRuleSnapshot &snapshot, std::string &error) {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }

        AmsiDetect::AmsiRuleSnapshot providerSnapshot;
        if (!BuildProviderSnapshot(snapshot, providerSnapshot, error)) {
            return false;
        }
        if (m_impl->ruleProvider && !m_impl->ruleProvider->UpdateSnapshot(providerSnapshot, error)) {
            return false;
        }

        m_impl->snapshot = providerSnapshot;
        m_impl->hasPreUpgradeSnapshot = false;
        error.clear();
        return true;
    }

    /**
     * amsi dll????????§Ø??????????????§Ò?????????????????????????????????
     * @param stateVersion  ???·Ú
     * @param error ???????
     * @return
     */
    bool AmsiIpcRuntime::EnterUpgradeUnloadingState(const std::string &stateVersion, std::string &error) {
        return EnterUpgradeUnloadingState(stateVersion, std::string(), error);
    }

    bool AmsiIpcRuntime::EnterUpgradeUnloadingState(const std::string &stateVersion, const std::string &requiredDllHash, std::string &error) {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;  // ??ùn??? IPC (????????) ????????????????????
        }

        // ?????????????§Ø????????·Ú???
        AmsiDetect::AmsiRuleSnapshot unloadingSnapshot;
        unloadingSnapshot.version = !m_impl->snapshot.version.empty() ? m_impl->snapshot.version : m_impl->config.version;
        if (unloadingSnapshot.version.empty()) {
            unloadingSnapshot.version = "unknown";
        }
        const std::string effectiveStateVersion = stateVersion.empty() ? ("upgrade-" + unloadingSnapshot.version) : stateVersion;
        // ???????§Ø???¦±???????????????? JSON ???????????,state????unload
        unloadingSnapshot.requiredDllHash = requiredDllHash;
        unloadingSnapshot.amsiRulesJson = BuildUpgradeUnloadingRulesJson(effectiveStateVersion, unloadingSnapshot.version, requiredDllHash);
        if (!m_impl->ruleProvider) {
            error = "amsi rule provider is not initialized";
            return false;
        }
        // ???????????????§á??????????§¹??????????????????? preUpgradeSnapshot ?§µ???????????
        if (!m_impl->hasPreUpgradeSnapshot) {
            m_impl->preUpgradeSnapshot = m_impl->snapshot;
            m_impl->hasPreUpgradeSnapshot = true;
        }
        // ?????????????????????????? unloadingSnapshot ?????¡¤??????????????ruleProvider
        if (!m_impl->ruleProvider->UpdateSnapshot(unloadingSnapshot, error)) {
            return false;
        }
        m_impl->snapshot = unloadingSnapshot;
        error.clear();
        return true;
    }

    /**
     * ???????????¨À????????????????????§³?????????????????
     * @param error
     * @return
     */
    bool AmsiIpcRuntime::RestorePreUpgradeSnapshot(std::string &error) {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }
        if (!m_impl->hasPreUpgradeSnapshot) {
            error.clear();
            return true;
        }
        if (!m_impl->ruleProvider) {
            error = "amsi rule provider is not initialized";
            return false;
        }
        AmsiDetect::AmsiRuleSnapshot restoreSnapshot = m_impl->preUpgradeSnapshot;
        AmsiDetect::AmsiRuleSnapshot providerSnapshot;
        if (!BuildProviderSnapshot(restoreSnapshot, providerSnapshot, error)) {
            return false;
        }
        if (!m_impl->ruleProvider->UpdateSnapshot(providerSnapshot, error)) {
            return false;
        }
        m_impl->snapshot = providerSnapshot;
        m_impl->hasPreUpgradeSnapshot = false;
        error.clear();
        return true;
    }
    /**
     * Restore the pre-upgrade running snapshot after the DLL file has already been replaced,
     * but the new rule snapshot failed to publish.
     *
     * Why this is different from RestorePreUpgradeSnapshot():
     * - RestorePreUpgradeSnapshot() restores both the old rules and the old requiredDllHash.
     * - After UPDATE_SUCCESS_REPLACE / UPDATE_SUCCESS_MOVE, new processes will load the new DLL file.
     * - If we restore the old requiredDllHash, those new processes will see a hash mismatch and bypass forever.
     *
     * Therefore this method keeps the pre-upgrade rule content, but overwrites requiredDllHash with
     * the hash of the DLL that is now installed on disk. This prevents the runtime from staying in
     * unloading state and allows newly started processes to keep detecting with the last known-good rules.
     */
    bool AmsiIpcRuntime::RestorePreUpgradeSnapshotWithDllHash(const std::string &requiredDllHash, std::string &error) {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }
        if (!m_impl->hasPreUpgradeSnapshot) {
            error.clear();
            return true;
        }
        if (!m_impl->ruleProvider) {
            error = "amsi rule provider is not initialized";
            return false;
        }

        AmsiDetect::AmsiRuleSnapshot restoreSnapshot = m_impl->preUpgradeSnapshot;
        restoreSnapshot.requiredDllHash = requiredDllHash;

        AmsiDetect::AmsiRuleSnapshot providerSnapshot;
        if (!BuildProviderSnapshot(restoreSnapshot, providerSnapshot, error)) {
            return false;
        }
        if (!m_impl->ruleProvider->UpdateSnapshot(providerSnapshot, error)) {
            return false;
        }
        m_impl->snapshot = providerSnapshot;
        m_impl->hasPreUpgradeSnapshot = false;
        error.clear();
        return true;
    }
}

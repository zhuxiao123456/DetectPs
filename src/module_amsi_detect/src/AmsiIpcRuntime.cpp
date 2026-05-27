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
        const wchar_t *kControlStatusPipeName = L"\\\\.\\pipe\\amsi_detect_control_status";
        const wchar_t *kConfigPipeName = L"\\\\.\\pipe\\amsi_detect_config";

        const int kRulePipeThreads = 8;
        const int kEventPipeThreads = 4;
        const int kStatusPipeThreads = 2;
        const int kBroadcastMaxListeners = 32;
        const uint32_t kDiagDroppedSummaryIntervalMs = 60 * 1000;

        /**
         * 继承自 amsi_ipc::IAmsiRuleProvider。内部封装了互斥锁和规则快照 AmsiRuleSnapshot。
         * 当管道收到探针发来的 GET_RULES 或 GET_ALL_RULES 命令时，负责安全地从内存中提取对应的 JSON 文本返回给探针
         */
        class RuntimeRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
        public:
            bool UpdateSnapshot(const AmsiRuleSnapshot &snapshot, std::string &error) {
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
                                    std::string &error) override {
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

        /**
         * 标准的 Sink 回调适配器。通过接收一个 lambda 表达式（onEvent_ / onStatus_），
         * 把底层抽象的管道回调数据一揽子接入到运行时主类的 SubmitEventPayload
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

        void WriteDllDiagnosticLog(DllDiagLogLevel level,
                                   size_t rawLen,
                                   const std::string &line) {
            switch (level) {
                case DllDiagLogLevel::Debug:
                    DebugLogf(AmsiDetect::GetLoggerPtr(),
                               "Recv amsi dll diagnostic payload rawLen=%lu payload: %s.",
                               static_cast<unsigned long>(rawLen),
                               line);
                    break;
                case DllDiagLogLevel::Warning:
                    WarningLogf2(AmsiDetect::GetLoggerPtr(),
                                 "Recv amsi dll diagnostic payload rawLen=%lu payload: %s.",
                                 static_cast<unsigned long>(rawLen),
                                 line);
                    break;
                case DllDiagLogLevel::Error:
                    ErrorLogf2(AmsiDetect::GetLoggerPtr(),
                               "Recv amsi dll diagnostic payload rawLen=%lu payload: %s.",
                               static_cast<unsigned long>(rawLen),
                               line);
                    break;
                case DllDiagLogLevel::Info:
                default:
                    InfoLogf2(AmsiDetect::GetLoggerPtr(),
                              "Recv amsi dll diagnostic payload rawLen=%lu payload: %s.",
                              static_cast<unsigned long>(rawLen),
                              line);
                    break;
            }
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
         * 以严格相反的顺序释放所有的管道池（Pool）、通信通道（Channel）、数据接收槽（Sink）和规则提供者，
         * 防止多线程环境下句柄释放时引发悬空指针崩溃
         */
        void ResetRuntimeObjects() {
            acceptingPayload.store(false);
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
         * 根据当前的 config.queueConfig 边界参数，重置内部三大 Bounded 阻塞队列（检测、诊断、状态）
         * 的容量和内存限制，并将 stopped_ 状态复位
         */
        void ResetQueues() {
            detectionQueue.Reset(AmsiGlobalConfRef.GetDetectionQueueCapacity(), AmsiGlobalConfRef.GetDetectionQueueMaxBytes());
            dllDiagQueue.Reset(AmsiGlobalConfRef.GetDllDiagnosticLogQueueCapacity(), AmsiGlobalConfRef.GetDllDiagnosticLogQueueMaxBytes());
            statusQueue.Reset(AmsiGlobalConfRef.GetStatusQueueCapacity(), AmsiGlobalConfRef.GetStatusQueueMaxBytes());
        }

        /**
         * 拉起 3 个后台独立的工作者线程（detectionWorker, dllDiagWorker, statusWorker）
         * 分别独立消费对应的阻塞队列，实现线程隔离
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
         * 停止所有异步工作线程。首先将 stopping 状态置为 true，然后强制中止三大队列的阻塞状态（唤醒所有卡在 Pop/Push 的线程）
         * 通过 join() 等待 3 个线程安全安全退场，最后执行 Clear() 释放内存
         * @param timeoutMs  允许等待线程退出的超时时间上限
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
         * 接收来自事件管道的原始 JSON。首先执行防防御性大包拦截（如果单包大小超过 AmsiGlobalConfRef.GetMaxPayloadBytes() 则直接丢弃）。
         * 随后调用之前分析过的 ClassifyAmsiEventPayload 进行分类
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
            // 原子计数 +1，调用 dllDiagQueue.TryPush 非阻塞投递，满了就直接计入 dllDiagDropped
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

        /**
         * 接收状态管道的心跳数据，防御大包后，直接投递进 statusQueue。如果队列满导致失败，则标记引擎状态为 Degraded（降级）
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
         * 为了防止注入到几百个进程里的 hss_amsi.dll 产生疯狂的刷屏日志（例如由于某个业务死循环触发的大量相同错误）
         * 该函数实现了基于时间窗口的日志去重算法; 提取日志中的 pattern 和 desc 组成唯一 Key。如果当前 Key 与上一次（lastDiagKey）相同，
         * 且时间间隔小于配置的 dllDiagnosticDuplicateWindowMs，则不再落盘，而是直接原子累加 suppressedDuplicateDiag 计数器
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
         * 线程循环状态机: 通过 queue.Pop(item) 挂起等待。一旦有数据，就将其反序列化或者调用 TruncateForLog 进行截断
         * （防止单行日志过长击穿日志组件），随后调用 InfoLogf2 写入本地物理磁盘日志文件
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
     * 公开接口: 运行时初始化。验证相关的策略开关（如 amsiIpcEnabled 必须为 true）。
     * 配置基础运行上下文，重置状态标志。此时不会创建管道，只是处于就绪状态
     * @param config  引擎配置参数对象
     * @param error  传出错误信息
     * @return  如果未启用 IPC 或不合规返回 false，成功返回 true
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
     * 一键启动引擎
     * @param snapshot  当前的规则库快照（包含全量正则 JSON）
     * @param error  传出错误原因
     * @return  任何一个管道池启动失败均会触发全量回滚销毁并返回 false
     */
    bool AmsiIpcRuntime::Start(const AmsiRuleSnapshot &snapshot, std::string &error) {
        if (!m_impl->initialized.load()) {
            error = "amsi ipc runtime is not initialized";
            return false;
        }
        if (m_impl->running.load()) {
            return UpdateRules(snapshot, error);  // 校验: 已在运行则直接重载规则
        }

        // 调用 ResetQueues() 和 StartWorkers() 拉起消费端
        m_impl->ruleProvider.reset(new RuntimeRuleProvider());
        if (!m_impl->ruleProvider->UpdateSnapshot(snapshot, error)) {
            m_impl->ResetRuntimeObjects();
            return false;
        }
        m_impl->ResetQueues();
        m_impl->StartWorkers();
        // 调用 PipeHasExistingServer 检查这 3 个管道的名字是否在 Windows 系统中已经被其他人占用了。
        // 如果被占用了（说明可能存在恶意的仿冒管道或者未清理干净的僵尸服务），为了安全拒绝启动，防止数据泄露
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
            if (m_impl && m_impl->acceptingPayload.load()) {
                m_impl->SubmitEventPayload(payload);
            }
        }));
        m_impl->statusSink.reset(new RuntimeControlStatusSink([this](const std::string &payload) {
            if (m_impl && m_impl->acceptingPayload.load()) {
                m_impl->SubmitStatusPayload(payload);
            }
        }));

        m_impl->ruleChannel.reset(new amsi_ipc::AmsiRuleChannel(*m_impl->ruleProvider));
        m_impl->eventChannel.reset(new amsi_ipc::AmsiEventChannel(*m_impl->eventSink));
        m_impl->statusChannel.reset(new amsi_ipc::AmsiControlStatusChannel(*m_impl->statusSink));

        m_impl->rulePool.reset(
                new amsi_ipc::NamedPipeServerPool(kRulesPipeName, AmsiGlobalConfRef.GetRulePipeNums(), *m_impl->ruleChannel));
        m_impl->eventPool.reset(
                new amsi_ipc::NamedPipeServerPool(kEventsPipeName, AmsiGlobalConfRef.GetEventPipeThreads(), *m_impl->eventChannel));
        m_impl->statusPool.reset(
                new amsi_ipc::NamedPipeServerPool(kControlStatusPipeName, AmsiGlobalConfRef.GetStatusPipeThreads(), *m_impl->statusChannel));

        // 连续调用 3 个 Pool 的 Start()，正式向 Windows 内核激活管道监听、此时能抓到数据
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
        m_impl->acceptingPayload.store(true);
        m_impl->snapshot = snapshot;
        m_impl->pipeStarted.store(true);
        m_impl->running.store(true);

        InfoLogf2(AmsiDetect::GetLoggerPtr(), "Amsi ipc runtime started, rule version=%s hash=%s.",
                  snapshot.version, snapshot.hash);
        error.clear();
        return true;
    }

    /**
     * 依次关闭管道服务池（不再接收新连接），排空并终止后台工作线程，释放所有的互斥锁与底层句柄。该函数在析构函数中也会被默认调用
     * @param timeoutMs  许排空残余数据的最大优雅等待时间
     * @param error  成功返回 true
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
     * 当主服务需要立即让所有探针“暂停检测”时调用,策略关闭
     * @param timeoutMs  单次广播连接每一个进程的超时时间，防止被某个死锁的僵尸进程拖垮
     * @param error
     * @return
     */
    bool AmsiIpcRuntime::PauseDetection(uint32_t timeoutMs, std::string &error) {
        if (!m_impl->running.load() || !m_impl->broadcaster) {
            error.clear();
            return true;
        }

        const amsi_ipc::AmsiBroadcastResult result =
                m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::PauseDetection,
                                               AmsiGlobalConfRef.GetBroadcastCount(),
                                               timeoutMs);
        m_impl->StoreBroadcastSummary("pause", timeoutMs, result);
        DebugLogf3(AmsiDetect::GetLoggerPtr(), "Amsi pause broadcast reached=%lu lastError=%lu timeoutMs=%lu.",
                   static_cast<unsigned long>(result.reached < 0 ? 0 : result.reached),
                   static_cast<unsigned long>(result.lastError),
                   static_cast<unsigned long>(timeoutMs));
        return BroadcastSucceeded(result, error);
    }

    bool AmsiIpcRuntime::ResumeDetection(uint32_t timeoutMs, std::string &error) {
        if (!m_impl->running.load() || !m_impl->broadcaster) {
            error.clear();
            return true;
        }

        const amsi_ipc::AmsiBroadcastResult result =
                m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::ResumeDetection,
                                               AmsiGlobalConfRef.GetBroadcastCount(),
                                               timeoutMs);
        m_impl->StoreBroadcastSummary("resume", timeoutMs, result);
        DebugLogf3(AmsiDetect::GetLoggerPtr(), "Amsi resume broadcast reached=%lu lastError=%lu timeoutMs=%lu.",
                   static_cast<unsigned long>(result.reached < 0 ? 0 : result.reached),
                   static_cast<unsigned long>(result.lastError),
                   static_cast<unsigned long>(timeoutMs));
        return BroadcastSucceeded(result, error);
    }
    // Best-effort unload broadcast. Current wire protocol does not provide reliable ack.
    bool AmsiIpcRuntime::Unload(uint32_t timeoutMs, std::string &error) {
        if (!m_impl->running.load() || !m_impl->broadcaster) {
            error.clear();
            return true;
        }

        const amsi_ipc::AmsiBroadcastResult result =
                m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::Unload,
                                               AmsiGlobalConfRef.GetBroadcastCount(),
                                               timeoutMs);
        m_impl->StoreBroadcastSummary("unload", timeoutMs, result);
        DebugLogf3(AmsiDetect::GetLoggerPtr(), "Amsi unload broadcast reached=%lu lastError=%lu timeoutMs=%lu.",
                   static_cast<unsigned long>(result.reached < 0 ? 0 : result.reached),
                   static_cast<unsigned long>(result.lastError),
                   static_cast<unsigned long>(timeoutMs));
        return BroadcastSucceeded(result, error);
    }

    /**
     * 有新的特征库或者本地修改了正则规则的时候，调用该接口; 它会加锁并更新 ruleProvider 中的快照内容
     * @param snapshot  新的规则特征库快照
     * @param error 报错信息
     * @return 成功返回 true
     */
    bool AmsiIpcRuntime::UpdateRules(const AmsiRuleSnapshot &snapshot, std::string &error) {
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

    bool AmsiIpcRuntime::Reload(uint32_t timeoutMs, std::string &error) {
        if (!m_impl->running.load() || !m_impl->broadcaster) {
            error = "amsi ipc runtime is not running";
            return false;
        }

        const amsi_ipc::AmsiBroadcastResult result =
                m_impl->broadcaster->Broadcast(amsi_ipc::AmsiControlSignal::Reload,
                                               AmsiGlobalConfRef.GetBroadcastCount(),
                                               timeoutMs);
        m_impl->StoreBroadcastSummary("reload", timeoutMs, result);
        DebugLogf3(AmsiDetect::GetLoggerPtr(), "Amsi reload broadcast reached=%lu lastError=%lu timeoutMs=%lu.",
                   static_cast<unsigned long>(result.reached < 0 ? 0 : result.reached),
                   static_cast<unsigned long>(result.lastError),
                   static_cast<unsigned long>(timeoutMs));
        return BroadcastSucceeded(result, error);
    }
    bool AmsiIpcRuntime::IsRunning() const {
        return m_impl && m_impl->running.load();
    }

    /**
     * 收集当前运行时的全量原子计数器状态，并实时读取三大有界队列当前的元素个数（Size()）和内存占用（Bytes()）
     * 打包成静态结构体返回给上层监控模块或维护线程。
     * @return
     */
    AmsiIpcRuntimeStats AmsiIpcRuntime::GetStats() const {
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

        {
            std::lock_guard<std::mutex> lock(m_impl->broadcastMutex);
            stats.lastReloadReached = m_impl->lastReloadBroadcast.reached;
            stats.lastReloadLastError = m_impl->lastReloadBroadcast.lastError;
            stats.lastPauseReached = m_impl->lastPauseBroadcast.reached;
            stats.lastPauseLastError = m_impl->lastPauseBroadcast.lastError;
            stats.lastResumeReached = m_impl->lastResumeBroadcast.reached;
            stats.lastResumeLastError = m_impl->lastResumeBroadcast.lastError;
            stats.lastUnloadReached = m_impl->lastUnloadBroadcast.reached;
            stats.lastUnloadLastError = m_impl->lastUnloadBroadcast.lastError;
        }

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

    AmsiIpcBroadcastSummary AmsiIpcRuntime::GetLastBroadcastSummary(const std::string &command) const {
        AmsiIpcBroadcastSummary summary;
        if (!m_impl) {
            return summary;
        }

        std::lock_guard<std::mutex> lock(m_impl->broadcastMutex);
        if (command == "reload") {
            return m_impl->lastReloadBroadcast;
        }
        if (command == "pause") {
            return m_impl->lastPauseBroadcast;
        }
        if (command == "resume") {
            return m_impl->lastResumeBroadcast;
        }
        if (command == "unload") {
            return m_impl->lastUnloadBroadcast;
        }
        return summary;
    }

}

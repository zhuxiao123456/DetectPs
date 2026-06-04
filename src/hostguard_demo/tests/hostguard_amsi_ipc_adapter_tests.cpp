#include "hostguard_amsi_ipc_adapter.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <future>
#include <string>
#include <thread>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return false;
    }
    return true;
}

bool WaitUntil(std::function<bool()> predicate, int timeoutMs)
{
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (predicate()) {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return predicate();
}

template <typename T>
bool WaitFuture(std::future<T>& future, int timeoutMs)
{
    return future.wait_for(std::chrono::milliseconds(timeoutMs)) == std::future_status::ready;
}

} // namespace

int main()
{
    using namespace hostguard_demo;

    bool ok = true;

    {
        const auto detection = EventPipeClassifier::ClassifyEventPipe(R"({"cat":"Detection","sensor":"RaspLog"})");
        ok &= Expect(detection.kind == HostGuardAmsiMessageKind::Detection,
                     "event pipe classifies Detection as detection");

        const auto drain = EventPipeClassifier::ClassifyEventPipe(
            R"({"cat":"drain-ack","sensor":"RaspLog","broadcastId":"b1"})");
        ok &= Expect(drain.kind == HostGuardAmsiMessageKind::DrainAck,
                     "event pipe classifies drain-ack as drain ack");
        ok &= Expect(drain.broadcastId == "b1", "classifier extracts broadcastId");

        const auto eventDiag = EventPipeClassifier::ClassifyEventPipe(R"({"sensor":"RaspLog","pattern":"amsi-log"})");
        ok &= Expect(eventDiag.kind == HostGuardAmsiMessageKind::Unknown,
                     "event pipe does not treat RaspLog as diagnostic fallback");

        const auto diag = EventPipeClassifier::ClassifyLogPipe(R"({"sensor":"RaspLog","pattern":"amsi-log"})");
        ok &= Expect(diag.kind == HostGuardAmsiMessageKind::DiagnosticLog,
                     "log pipe classifies payload as diagnostic log");
    }

    {
        HostGuardRuleProvider provider;
        std::string error;
        ok &= Expect(provider.UpdateRules("all-v1", "amsi-v1", "v1", "h1", error),
                     "rule provider accepts complete snapshot");

        amsi_ipc::AmsiRuleResponse response;
        ok &= Expect(provider.BuildRulesResponse("GET_RULES", response, error),
                     "GET_RULES succeeds after snapshot update");
        ok &= Expect(response.json == "amsi-v1", "GET_RULES returns amsi snapshot");
        ok &= Expect(provider.BuildRulesResponse("GET_ALL_RULES", response, error),
                     "GET_ALL_RULES succeeds after snapshot update");
        ok &= Expect(response.json == "all-v1", "GET_ALL_RULES returns all snapshot");
        ok &= Expect(!provider.UpdateRules("", "amsi-v2", "v2", "h2", error),
                     "invalid update is rejected");
        ok &= Expect(provider.BuildRulesResponse("GET_RULES", response, error) && response.json == "amsi-v1",
                     "failed update does not replace old snapshot");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        std::string error;
        std::atomic<int> detections{0};
        std::atomic<int> statuses{0};

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds");
        ok &= Expect(!adapter.Init(config, error), "adapter Init rejects duplicate call");

        adapter.SetDetectionEventCallback([&](const HostGuardAmsiEventEnvelope&) {
            ++detections;
        });
        adapter.SetStatusCallback([&](const std::string&) {
            ++statuses;
        });

        ok &= Expect(adapter.Start(error), "adapter Start succeeds");
        ok &= Expect(!adapter.Start(error), "adapter Start rejects duplicate call");
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"Detection"})"), "submit detection succeeds");
        ok &= Expect(adapter.InjectStatusForTest(R"({"msgType":"DLL_LOADED"})"), "submit status succeeds");
        ok &= Expect(WaitUntil([&]() { return detections.load() == 1 && statuses.load() == 1; }, 1000),
                     "forwarders deliver detection and status callbacks");

        adapter.Stop();
        ok &= Expect(!adapter.GetStatus().started, "adapter Stop clears started state");
        ok &= Expect(!adapter.InjectRawEventForTest(R"({"cat":"Detection"})"),
                     "submit after Stop is rejected");
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        ok &= Expect(detections.load() == 1, "Stop prevents later callbacks");

        ok &= Expect(adapter.Start(error), "adapter can Start again after Stop");
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"Detection"})"),
                     "submit detection succeeds after restart");
        ok &= Expect(WaitUntil([&]() { return detections.load() == 2; }, 1000),
                     "forwarder delivers callbacks after restart");
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        std::string error;
        HostGuardAmsiBroadcastResult pause;

        ok &= Expect(adapter.Init(config, error), "mock adapter Init succeeds for pause failure policy test");
        ok &= Expect(!adapter.PauseDetection(10, pause), "PauseDetection fails when real runtime is not started");
        ok &= Expect(!adapter.GetStatus().detectionEnabled,
                     "PauseDetection records detection disabled even when broadcast cannot run");
    }

    {
        HostGuardAmsiIpcConfig config;
        config.detectionEventQueueCapacity = 1;
        config.detectionEventQueueMaxBytes = 64 * 1024;
        config.detectionQueueFullPolicy = DetectionQueueFullPolicy::WaitThenDrop;
        config.detectionEnqueueTimeoutMs = 20;

        HostGuardAmsiIpcAdapter adapter;
        std::string error;
        std::promise<void> callbackEntered;
        std::promise<void> unblockCallback;
        auto unblockFuture = unblockCallback.get_future();
        std::atomic<int> detections{0};
        std::atomic<bool> firstCallbackSeen{false};

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds for queue pressure test");
        adapter.SetDetectionEventCallback([&](const HostGuardAmsiEventEnvelope&) {
            ++detections;
            if (!firstCallbackSeen.exchange(true)) {
                callbackEntered.set_value();
            }
            unblockFuture.wait();
        });
        ok &= Expect(adapter.Start(error), "adapter Start succeeds for queue pressure test");
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"Detection","id":"1"})"), "first detection submits");
        auto callbackEnteredFuture = callbackEntered.get_future();
        ok &= Expect(WaitFuture(callbackEnteredFuture, 1000), "first callback is entered");
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"Detection","id":"2"})"), "second detection fills queue");
        ok &= Expect(!adapter.InjectRawEventForTest(R"({"cat":"Detection","id":"3"})"),
                     "third detection is dropped after bounded wait");
        ok &= Expect(adapter.GetStatus().detectionEventDropped == 1,
                     "dropped detection is counted");
        unblockCallback.set_value();
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        std::string error;
        std::promise<void> logEntered;
        std::promise<void> unblockLog;
        auto unblockLogFuture = unblockLog.get_future();
        std::atomic<int> logs{0};
        std::atomic<int> detections{0};

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds for isolation test");
        adapter.SetDllDiagnosticLogCallback([&](const HostGuardAmsiEventEnvelope&) {
            ++logs;
            logEntered.set_value();
            unblockLogFuture.wait();
        });
        adapter.SetDetectionEventCallback([&](const HostGuardAmsiEventEnvelope&) {
            ++detections;
        });
        ok &= Expect(adapter.Start(error), "adapter Start succeeds for isolation test");
        ok &= Expect(adapter.InjectRawLogForTest(R"({"cat":"diag","sensor":"RaspLog"})"), "diag submits");
        auto logEnteredFuture = logEntered.get_future();
        ok &= Expect(WaitFuture(logEnteredFuture, 1000), "log callback is entered");
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"Detection"})"), "detection submits while log callback blocks");
        ok &= Expect(WaitUntil([&]() { return detections.load() == 1; }, 1000),
                     "blocked DLL log callback does not block detection forwarder");
        unblockLog.set_value();
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcConfig config;
        config.maxEventBytes = 32;
        config.maxStatusBytes = 32;
        HostGuardAmsiIpcAdapter adapter;
        std::string error;

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds for max payload test");
        ok &= Expect(adapter.Start(error), "adapter Start succeeds for max payload test");
        ok &= Expect(!adapter.InjectRawEventForTest(std::string(64, 'e')),
                     "oversized event payload is rejected before classification");
        ok &= Expect(!adapter.InjectStatusForTest(std::string(64, 's')),
                     "oversized status payload is rejected before queueing");
        ok &= Expect(adapter.GetStatus().oversizedEventDropped == 1,
                     "oversized event drop is counted");
        ok &= Expect(adapter.GetStatus().oversizedStatusDropped == 1,
                     "oversized status drop is counted");
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcConfig config;
        config.dllDiagnosticLogDuplicateWindowMs = 60 * 1000;
        HostGuardAmsiIpcAdapter adapter;
        std::string error;
        std::atomic<int> logs{0};

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds for diag suppression test");
        adapter.SetDllDiagnosticLogCallback([&](const HostGuardAmsiEventEnvelope&) {
            ++logs;
        });
        ok &= Expect(adapter.Start(error), "adapter Start succeeds for diag suppression test");
        const std::string repeated = R"({"cat":"diag","sensor":"RaspLog","pattern":"amsi-log","desc":"same"})";
        ok &= Expect(adapter.InjectRawLogForTest(repeated), "first repeated diag submits");
        ok &= Expect(adapter.InjectRawLogForTest(repeated), "second repeated diag submits");
        ok &= Expect(WaitUntil([&]() {
                         const auto status = adapter.GetStatus();
                         return logs.load() == 1 && status.dllDiagnosticLogSuppressed == 1;
                     }, 1000),
                     "duplicate DLL diagnostic log is suppressed in forwarder");
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcConfig config;
        config.detectionEventQueueCapacity = 1;
        config.detectionQueueFullPolicy = DetectionQueueFullPolicy::DropImmediately;
        HostGuardAmsiIpcAdapter adapter;
        std::string error;
        std::promise<void> callbackEntered;
        std::promise<void> unblockCallback;
        auto unblockFuture = unblockCallback.get_future();
        std::atomic<bool> firstCallbackSeen{false};

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds for drop-immediately test");
        adapter.SetDetectionEventCallback([&](const HostGuardAmsiEventEnvelope&) {
            if (!firstCallbackSeen.exchange(true)) {
                callbackEntered.set_value();
            }
            unblockFuture.wait();
        });
        ok &= Expect(adapter.Start(error), "adapter Start succeeds for drop-immediately test");
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"Detection","id":"1"})"), "first detection submits");
        auto callbackEnteredFuture = callbackEntered.get_future();
        ok &= Expect(WaitFuture(callbackEnteredFuture, 1000), "drop-immediately first callback is entered");
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"Detection","id":"2"})"), "second detection fills queue");
        ok &= Expect(!adapter.InjectRawEventForTest(R"({"cat":"Detection","id":"3"})"),
                     "DropImmediately drops full queue without waiting");
        unblockCallback.set_value();
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcConfig config;
        config.detectionEventQueueMaxBytes = 8;
        config.detectionQueueFullPolicy = DetectionQueueFullPolicy::BlockForever;
        HostGuardAmsiIpcAdapter adapter;
        std::string error;

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds for block-forever oversize test");
        ok &= Expect(adapter.Start(error), "adapter Start succeeds for block-forever oversize test");
        ok &= Expect(!adapter.InjectRawEventForTest(R"({"cat":"Detection","payload":"larger-than-eight"})"),
                     "BlockForever rejects item larger than byte budget instead of hanging");
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcConfig config;
        config.statusQueueCapacity = 1;
        config.statusQueueFullPolicy = QueueFullPolicy::WaitThenDrop;
        config.statusEnqueueTimeoutMs = 20;
        HostGuardAmsiIpcAdapter adapter;
        std::string error;
        std::promise<void> callbackEntered;
        std::promise<void> unblockCallback;
        auto unblockFuture = unblockCallback.get_future();
        std::atomic<bool> firstCallbackSeen{false};

        ok &= Expect(adapter.Init(config, error), "adapter Init succeeds for status queue test");
        adapter.SetStatusCallback([&](const std::string&) {
            if (!firstCallbackSeen.exchange(true)) {
                callbackEntered.set_value();
            }
            unblockFuture.wait();
        });
        ok &= Expect(adapter.Start(error), "adapter Start succeeds for status queue test");
        ok &= Expect(adapter.InjectStatusForTest(R"({"id":1})"), "first status submits");
        auto callbackEnteredFuture = callbackEntered.get_future();
        ok &= Expect(WaitFuture(callbackEnteredFuture, 1000), "status callback is entered");
        ok &= Expect(adapter.InjectStatusForTest(R"({"id":2})"), "second status fills queue");
        ok &= Expect(!adapter.InjectStatusForTest(R"({"id":3})"),
                     "status queue uses bounded wait and drops instead of hanging");
        ok &= Expect(adapter.GetStatus().statusDropped == 1, "dropped status is counted");
        unblockCallback.set_value();
        adapter.Stop();
    }

    return ok ? 0 : 1;
}

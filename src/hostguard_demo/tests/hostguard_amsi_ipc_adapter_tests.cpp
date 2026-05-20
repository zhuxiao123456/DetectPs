#include "hostguard_amsi_ipc_adapter.h"

#include <atomic>
#include <chrono>
#include <cstdio>
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
        const auto detection = EventPipeClassifier::Classify(R"({"cat":"Detection","sensor":"RaspLog"})");
        ok &= Expect(detection.kind == HostGuardAmsiMessageKind::Detection,
                     "cat Detection wins over sensor fallback");

        const auto drain = EventPipeClassifier::Classify(
            R"({"cat":"drain-ack","sensor":"RaspLog","broadcastId":"b1"})");
        ok &= Expect(drain.kind == HostGuardAmsiMessageKind::DrainAck,
                     "cat drain-ack wins over sensor RaspLog");
        ok &= Expect(drain.broadcastId == "b1", "classifier extracts broadcastId");

        const auto diag = EventPipeClassifier::Classify(R"({"sensor":"RaspLog","pattern":"amsi-log"})");
        ok &= Expect(diag.kind == HostGuardAmsiMessageKind::DiagnosticLog,
                     "sensor RaspLog is diagnostic fallback when cat is absent");
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
        ok &= Expect(adapter.InjectRawEventForTest(R"({"cat":"diag","sensor":"RaspLog"})"), "diag submits");
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

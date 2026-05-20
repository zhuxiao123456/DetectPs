#include "hostguard_amsi_ipc_adapter.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

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

std::wstring TestPipeName(const wchar_t* suffix)
{
    return std::wstring(LR"(\\.\pipe\hostguard_amsi_adapter_phase2_)") +
           std::to_wstring(GetCurrentProcessId()) +
           L"_" +
           suffix;
}

void ConfigureRealIpcTestPipes(hostguard_demo::HostGuardAmsiIpcConfig& config, const wchar_t* prefix)
{
    const std::wstring base(prefix);
    config.rulesPipeName = TestPipeName((base + L"_rules").c_str());
    config.eventsPipeName = TestPipeName((base + L"_events").c_str());
    config.controlStatusPipeName = TestPipeName((base + L"_status").c_str());
    config.configPipeName = TestPipeName((base + L"_config").c_str());
}

std::string ExchangeRulesPipePayload(const std::wstring& pipeName, const std::string& payload)
{
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (WaitNamedPipeW(pipeName.c_str(), 100)) {
            break;
        }
        Sleep(20);
    }

    HANDLE pipe = CreateFileW(pipeName.c_str(),
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return "__connect_rules_failed__";
    }

    DWORD written = 0;
    if (!WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) ||
        written != payload.size()) {
        CloseHandle(pipe);
        return "__write_rules_failed__";
    }

    char response[4096] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, response, static_cast<DWORD>(sizeof(response) - 1), &bytesRead, nullptr)) {
        CloseHandle(pipe);
        return "__read_rules_failed__";
    }

    CloseHandle(pipe);
    return std::string(response, bytesRead);
}

bool WritePipePayload(const std::wstring& pipeName, const std::string& payload)
{
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (WaitNamedPipeW(pipeName.c_str(), 100)) {
            break;
        }
        Sleep(20);
    }

    HANDLE pipe = CreateFileW(pipeName.c_str(),
                              GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return false;
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(pipe,
                              payload.data(),
                              static_cast<DWORD>(payload.size()),
                              &written,
                              nullptr);
    CloseHandle(pipe);
    return ok && written == payload.size();
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
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        config.enableRealIpc = true;
        ConfigureRealIpcTestPipes(config, L"rule_ready");
        std::string error;

        ok &= Expect(adapter.Init(config, error), "real IPC adapter Init succeeds");
        ok &= Expect(adapter.UpdateRules(R"({"rules":[{"id":"all"}]})",
                                         R"([{"id":"amsi"}])",
                                         "v1",
                                         "h1",
                                         error),
                     "real IPC adapter rules update succeeds");
        ok &= Expect(adapter.Start(error), "real IPC adapter Start succeeds");
        ok &= Expect(!adapter.GetRecentAdapterDiag().empty(),
                     "real IPC startup records control pipe security validation diag");

        const std::string amsiResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_RULES\n");
        const std::string allResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_ALL_RULES\n");
        const auto status = adapter.GetStatus();
        adapter.Stop();

        ok &= Expect(amsiResponse == R"([{"id":"amsi"}])" "\n",
                     "real rule pipe GET_RULES returns amsi snapshot");
        ok &= Expect(allResponse == R"({"rules":[{"id":"all"}]})" "\n",
                     "real rule pipe GET_ALL_RULES returns all snapshot");
        ok &= Expect(status.ruleRequests == 2, "real rule pipe increments ruleRequests");
        ok &= Expect(status.ruleRequestUnsupported == 0, "supported real rule commands do not increment unsupported count");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        config.enableRealIpc = true;
        ConfigureRealIpcTestPipes(config, L"rule_errors");
        std::string error;

        ok &= Expect(adapter.Init(config, error), "real IPC adapter Init succeeds for error test");
        ok &= Expect(adapter.Start(error), "real IPC adapter Start succeeds without rules");

        const std::string notReadyResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_RULES\n");
        ok &= Expect(adapter.UpdateRules(R"({"rules":[]})", R"([])", "v1", "h1", error),
                     "rules update succeeds after RULES_NOT_READY");
        const std::string unsupportedResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_UNKNOWN\n");
        const auto status = adapter.GetStatus();
        adapter.Stop();

        ok &= Expect(notReadyResponse == "__read_rules_failed__",
                     "RULES_NOT_READY produces no rule pipe response");
        ok &= Expect(unsupportedResponse == "__read_rules_failed__",
                     "UNSUPPORTED_COMMAND produces no rule pipe response");
        ok &= Expect(status.ruleRequests == 2, "error rule requests are counted");
        ok &= Expect(status.ruleRequestUnsupported == 1, "unsupported rule command is counted");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        config.enableRealIpc = true;
        ConfigureRealIpcTestPipes(config, L"event_pipe");
        std::string error;
        std::atomic<int> detections{0};
        std::atomic<int> logs{0};

        ok &= Expect(adapter.Init(config, error), "real event IPC adapter Init succeeds");
        adapter.SetDetectionEventCallback([&](const HostGuardAmsiEventEnvelope& event) {
            if (event.cat == "Detection") {
                ++detections;
            }
        });
        adapter.SetDllDiagnosticLogCallback([&](const HostGuardAmsiEventEnvelope& log) {
            if (log.kind == HostGuardAmsiMessageKind::DiagnosticLog) {
                ++logs;
            }
        });
        ok &= Expect(adapter.Start(error), "real event IPC adapter Start succeeds");

        ok &= Expect(WritePipePayload(config.eventsPipeName, R"({"cat":"Detection","id":"d1"})"),
                     "real event pipe detection write succeeds");
        ok &= Expect(WritePipePayload(config.eventsPipeName, R"({"cat":"diag","sensor":"RaspLog"})"),
                     "real event pipe diag write succeeds");
        ok &= Expect(WritePipePayload(config.eventsPipeName, R"({"cat":"drain-ack","sensor":"RaspLog","broadcastId":"b1"})"),
                     "real event pipe drain ack write succeeds");
        ok &= Expect(WritePipePayload(config.eventsPipeName, R"({"cat":"unexpected"})"),
                     "real event pipe unknown write succeeds");

        ok &= Expect(WaitUntil([&]() { return detections.load() == 1 && logs.load() == 1; }, 1000),
                     "real event pipe delivers detection and diagnostic log callbacks");
        ok &= Expect(WaitUntil([&]() {
                         const auto status = adapter.GetStatus();
                         return status.drainAckReceived == 1 &&
                                status.drainAckCorrelated == 1 &&
                                status.unknownEventReceived == 1;
                     }, 1000),
                     "real event pipe classifies drain ack and unknown payload");
        ok &= Expect(!adapter.GetRecentAdapterDiag().empty(),
                     "unknown real event payload writes adapter diag");
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        config.enableRealIpc = true;
        ConfigureRealIpcTestPipes(config, L"status_pipe");
        std::string error;
        std::atomic<int> statuses{0};
        std::string lastStatus;

        ok &= Expect(adapter.Init(config, error), "real status IPC adapter Init succeeds");
        adapter.SetStatusCallback([&](const std::string& rawJson) {
            lastStatus = rawJson;
            ++statuses;
        });
        ok &= Expect(adapter.Start(error), "real status IPC adapter Start succeeds");

        const std::string payload = R"({"msgType":"DLL_LOADED","instanceId":"i1"})";
        ok &= Expect(WritePipePayload(config.controlStatusPipeName, payload),
                     "real status pipe write succeeds");
        ok &= Expect(WaitUntil([&]() { return statuses.load() == 1; }, 1000),
                     "real status pipe delivers status callback");
        const auto status = adapter.GetStatus();
        adapter.Stop();

        ok &= Expect(lastStatus == payload, "real status callback receives unchanged payload");
        ok &= Expect(status.statusReceived == 1, "real status pipe increments statusReceived");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        config.enableRealIpc = true;
        ConfigureRealIpcTestPipes(config, L"broadcast");
        std::string error;

        ok &= Expect(adapter.Init(config, error), "real broadcaster adapter Init succeeds");
        ok &= Expect(adapter.Start(error), "real broadcaster adapter Start succeeds");

        HostGuardAmsiBroadcastResult reload;
        HostGuardAmsiBroadcastResult pause;
        HostGuardAmsiBroadcastResult resume;
        HostGuardAmsiBroadcastResult unload;

        ok &= Expect(adapter.Reload(10, reload), "real Reload broadcaster call completes");
        ok &= Expect(adapter.PauseDetection(10, pause), "real PauseDetection broadcaster call completes");
        ok &= Expect(adapter.ResumeDetection(10, resume), "real ResumeDetection broadcaster call completes");
        ok &= Expect(adapter.Unload(10, unload), "real Unload broadcaster call completes");
        adapter.Stop();

        ok &= Expect(!reload.broadcastId.empty() && reload.command == "reload",
                     "Reload result includes broadcastId and command");
        ok &= Expect(!pause.broadcastId.empty() && pause.command == "pause",
                     "Pause result includes broadcastId and command");
        ok &= Expect(!resume.broadcastId.empty() && resume.command == "resume",
                     "Resume result includes broadcastId and command");
        ok &= Expect(!unload.broadcastId.empty() && unload.command == "unload",
                     "Unload result includes broadcastId and command");
        ok &= Expect(reload.delivered == 0 && pause.delivered == 0 &&
                         resume.delivered == 0 && unload.delivered == 0,
                     "broadcast calls report no listeners in isolated test");
        ok &= Expect(reload.acked == 0 && pause.acked == 0 &&
                         resume.acked == 0 && unload.acked == 0,
                     "legacy one-byte broadcaster delivery is not counted as ack");
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

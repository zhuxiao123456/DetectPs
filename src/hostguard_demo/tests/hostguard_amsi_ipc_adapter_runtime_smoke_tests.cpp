#include "hostguard_amsi_ipc_adapter.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <functional>
#include <vector>
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

bool PipeServerExists(const std::wstring& pipeName)
{
    HANDLE pipe = CreateFileW(pipeName.c_str(),
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe);
        return true;
    }

    const DWORD error = GetLastError();
    return error == ERROR_PIPE_BUSY || error == ERROR_PIPE_CONNECTED;
}

std::wstring TestPipeName(const wchar_t* suffix)
{
    return std::wstring(LR"(\\.\pipe\hostguard_amsi_adapter_phase25_)") +
           std::to_wstring(GetCurrentProcessId()) +
           L"_" +
           suffix;
}

void ConfigureRealIpcTestPipes(hostguard_demo::HostGuardAmsiIpcConfig& config, const wchar_t* prefix)
{
    const std::wstring base(prefix);
    config.enableRealIpc = true;
    config.rulesPipeName = TestPipeName((base + L"_rules").c_str());
    config.eventsPipeName = TestPipeName((base + L"_events").c_str());
    config.logsPipeName = TestPipeName((base + L"_logs").c_str());
    config.controlStatusPipeName = TestPipeName((base + L"_status").c_str());
    config.configPipeName = TestPipeName((base + L"_config").c_str());
}

std::string ExchangeRulesPipePayload(const std::wstring& pipeName, const std::string& payload)
{
    HANDLE pipe = INVALID_HANDLE_VALUE;
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (!WaitNamedPipeW(pipeName.c_str(), 100)) {
            Sleep(20);
            continue;
        }

        pipe = CreateFileW(pipeName.c_str(),
                           GENERIC_READ | GENERIC_WRITE,
                           0,
                           nullptr,
                           OPEN_EXISTING,
                           0,
                           nullptr);
        if (pipe != INVALID_HANDLE_VALUE) {
            break;
        }
        Sleep(20);
    }
    if (pipe == INVALID_HANDLE_VALUE) {
        return "__connect_rules_failed__";
    }

    DWORD mode = PIPE_READMODE_MESSAGE;
    SetNamedPipeHandleState(pipe, &mode, nullptr, nullptr);

    DWORD written = 0;
    if (!WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) ||
        written != payload.size()) {
        CloseHandle(pipe);
        return "__write_rules_failed__";
    }

    std::string response;
    char chunk[8192] = {};
    for (;;) {
        DWORD bytesRead = 0;
        if (ReadFile(pipe, chunk, static_cast<DWORD>(sizeof(chunk)), &bytesRead, nullptr)) {
            response.append(chunk, bytesRead);
            break;
        }
        const DWORD err = GetLastError();
        if (err == ERROR_MORE_DATA) {
            response.append(chunk, bytesRead);
            continue;
        }
        CloseHandle(pipe);
        return "__read_rules_failed__";
    }

    CloseHandle(pipe);
    return response;
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

} // namespace

int main()
{
    using namespace hostguard_demo;

    bool ok = true;

    {
        HostGuardAmsiIpcConfig config;
        ok &= Expect(config.rulePipeThreads == 16, "real rule pipe default thread count is 16");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        ConfigureRealIpcTestPipes(config, L"startup_stop");
        std::string error;

        ok &= Expect(adapter.Init(config, error), "real IPC adapter Init succeeds");
        ok &= Expect(adapter.Start(error), "real IPC adapter Start succeeds");
        ok &= Expect(adapter.GetStatus().started, "real IPC adapter reports started");
        ok &= Expect(!adapter.GetRecentAdapterDiag().empty(),
                     "real IPC startup records adapter diagnostic");
        adapter.Stop();
        ok &= Expect(!adapter.GetStatus().started, "real IPC adapter Stop clears started state");
        adapter.Stop();
        ok &= Expect(!adapter.GetStatus().started, "real IPC adapter Stop is idempotent");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        ConfigureRealIpcTestPipes(config, L"rule_ready");
        std::string error;

        ok &= Expect(adapter.Init(config, error), "real rule IPC adapter Init succeeds");
        ok &= Expect(adapter.UpdateRules(R"({"rules":[{"id":"all"}]})",
                                         R"([{"id":"amsi"}])",
                                         "v1",
                                         "h1",
                                         error),
                     "real rule IPC adapter rules update succeeds");
        ok &= Expect(adapter.Start(error), "real rule IPC adapter Start succeeds");

        const std::string amsiResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_RULES\n");
        const std::string allResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_ALL_RULES\n");
        const auto status = adapter.GetStatus();
        adapter.Stop();

        ok &= Expect(amsiResponse == R"([{"id":"amsi"}])" "\n",
                     "real rule pipe GET_RULES returns amsi snapshot");
        ok &= Expect(allResponse == R"({"rules":[{"id":"all"}]})" "\n",
                     "real rule pipe GET_ALL_RULES returns all snapshot");
        ok &= Expect(status.ruleRequests == 2, "real rule pipe increments ruleRequests");
        ok &= Expect(status.ruleRequestUnsupported == 0,
                     "supported real rule commands do not increment unsupported count");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        ConfigureRealIpcTestPipes(config, L"rule_large_parallel");
        std::string error;
        const std::string padding(100 * 1024, 'x');
        const std::string allRules = std::string(R"({"rules":[{"id":"large","padding":")") +
                                     padding +
                                     R"("}]})";

        ok &= Expect(adapter.Init(config, error), "large parallel rule IPC adapter Init succeeds");
        ok &= Expect(adapter.UpdateRules(allRules, R"([{"id":"amsi"}])", "v-large", "h-large", error),
                     "large parallel rules update succeeds");
        ok &= Expect(adapter.Start(error), "large parallel rule IPC adapter Start succeeds");

        std::atomic<int> successCount{0};
        std::atomic<int> connectFailures{0};
        std::atomic<int> readFailures{0};
        std::atomic<int> shortResponses{0};
        std::atomic<int> maxResponseSize{0};
        std::vector<std::thread> clients;
        clients.reserve(16);
        for (int i = 0; i < 16; ++i) {
            clients.emplace_back([&]() {
                const std::string response = ExchangeRulesPipePayload(config.rulesPipeName, "GET_ALL_RULES\n");
                if (response == "__connect_rules_failed__") {
                    ++connectFailures;
                    return;
                }
                if (response == "__read_rules_failed__") {
                    ++readFailures;
                    return;
                }
                int observedSize = static_cast<int>(response.size());
                int currentMax = maxResponseSize.load();
                while (observedSize > currentMax &&
                       !maxResponseSize.compare_exchange_weak(currentMax, observedSize)) {
                }
                if (response.find(R"("id":"large")") != std::string::npos &&
                    response.find(padding) != std::string::npos) {
                    ++successCount;
                } else {
                    ++shortResponses;
                }
            });
        }
        for (auto& client : clients) {
            client.join();
        }
        const auto status = adapter.GetStatus();
        adapter.Stop();

        if (successCount.load() != 16) {
            std::fprintf(stderr,
                         "large parallel detail: success=%d connectFailures=%d readFailures=%d shortResponses=%d maxResponseSize=%d\n",
                         successCount.load(),
                         connectFailures.load(),
                         readFailures.load(),
                         shortResponses.load(),
                         maxResponseSize.load());
        }
        ok &= Expect(successCount.load() == 16, "16 concurrent GET_ALL_RULES clients receive 100KB payload");
        ok &= Expect(status.ruleRequests == 16, "large parallel rule requests are counted");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
        ConfigureRealIpcTestPipes(config, L"rule_errors");
        std::string error;

        ok &= Expect(adapter.Init(config, error), "real rule error IPC adapter Init succeeds");
        ok &= Expect(adapter.Start(error), "real rule error IPC adapter Start succeeds without rules");

        const std::string notReadyResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_RULES\n");
        ok &= Expect(adapter.UpdateRules(R"({"rules":[]})", R"([])", "v1", "h1", error),
                     "rules update succeeds after RULES_NOT_READY");
        const std::string unsupportedResponse = ExchangeRulesPipePayload(config.rulesPipeName, "GET_UNKNOWN\n");
        const auto status = adapter.GetStatus();
        adapter.Stop();

        ok &= Expect(notReadyResponse == "__read_rules_failed__",
                     "RULES_NOT_READY closes rule pipe without success response");
        ok &= Expect(unsupportedResponse == "__read_rules_failed__",
                     "UNSUPPORTED_COMMAND closes rule pipe without success response");
        ok &= Expect(status.ruleRequests == 2, "error rule requests are counted");
        ok &= Expect(status.ruleRequestUnsupported == 1, "unsupported rule command is counted");
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
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
        ok &= Expect(WritePipePayload(config.logsPipeName, R"({"cat":"diag","sensor":"RaspLog"})"),
                     "real log pipe diagnostic log write succeeds");
        ok &= Expect(WritePipePayload(config.eventsPipeName, R"({"cat":"diag","sensor":"RaspLog"})"),
                     "real event pipe diagnostic payload is accepted but not treated as log");
        ok &= Expect(WritePipePayload(config.eventsPipeName,
                                      R"({"cat":"drain-ack","sensor":"RaspLog","broadcastId":"b1"})"),
                     "real event pipe drain ack write succeeds");
        ok &= Expect(WritePipePayload(config.eventsPipeName, R"({"cat":"unexpected"})"),
                     "real event pipe unknown write succeeds");

        ok &= Expect(WaitUntil([&]() { return detections.load() == 1 && logs.load() == 1; }, 1000),
                     "real event pipe delivers detection and diagnostic log callbacks");
        ok &= Expect(WaitUntil([&]() {
                         const auto status = adapter.GetStatus();
                         return status.drainAckReceived == 1 &&
                                status.drainAckCorrelated == 1 &&
                                status.unknownEventReceived == 2;
                     }, 1000),
                     "real event pipe classifies drain ack and non-event payloads");
        ok &= Expect(!adapter.GetRecentAdapterDiag().empty(),
                     "unknown real event payload writes adapter diag");
        adapter.Stop();
    }

    {
        HostGuardAmsiIpcAdapter adapter;
        HostGuardAmsiIpcConfig config;
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
        ConfigureRealIpcTestPipes(config, L"broadcast");
        std::string error;

        ok &= Expect(adapter.Init(config, error), "real broadcaster adapter Init succeeds");
        ok &= Expect(adapter.Start(error), "real broadcaster adapter Start succeeds");
        ok &= Expect(!PipeServerExists(config.configPipeName),
                     "HostGuard real IPC adapter does not serve legacy config pipe");
        ok &= Expect(WritePipePayload(config.logsPipeName, R"({"cat":"diag","probe":"log-pipe"})"),
                     "HostGuard real IPC adapter serves diagnostic log pipe");

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
                     "broadcast calls report no listeners in isolated smoke test");
        ok &= Expect(reload.acked == 0 && pause.acked == 0 &&
                         resume.acked == 0 && unload.acked == 0,
                     "legacy one-byte broadcaster delivery is not counted as ack");
    }

    return ok ? 0 : 1;
}

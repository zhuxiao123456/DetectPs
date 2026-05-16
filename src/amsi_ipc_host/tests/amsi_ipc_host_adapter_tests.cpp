#include "amsi_ipc_host.h"

#include "amsi_control_status_sink.h"
#include "amsi_event_sink.h"
#include "amsi_pipe_names.h"
#include "amsi_rule_provider.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>

namespace {

struct FakeEventSink final : amsi_ipc::IAmsiEventSink {
    void OnEventLine(const amsi_ipc::AmsiEventLine& event) override
    {
        lastPayload = event.payload;
        calls.fetch_add(1);
    }

    std::atomic<int> calls{0};
    std::string lastPayload;
};

struct FakeControlStatusSink final : amsi_ipc::IAmsiControlStatusSink {
    void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status) override
    {
        lastPayload = status.payload;
        calls.fetch_add(1);
    }

    std::atomic<int> calls{0};
    std::string lastPayload;
};

struct FakeRuleProvider final : amsi_ipc::IAmsiRuleProvider {
    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override
    {
        lastCommand = command;
        ++buildCalls;
        if (command == "GET_RULES") {
            out.json = R"([{"id":"injected-rule","sensor":"AmsiProvider"}])";
            return true;
        }
        if (command == "GET_ALL_RULES") {
            out.json = R"({"rules":[{"id":"injected-all","sensor":"AmsiProvider"}]})";
            return true;
        }
        error = "unknown command: " + command;
        return false;
    }

    void InvalidateRuleCache() override
    {
        ++invalidateCalls;
    }

    int buildCalls = 0;
    int invalidateCalls = 0;
    std::string lastCommand;
};

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return false;
    }
    return true;
}

bool AdapterConstructorAcceptsExternalSinks()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "rasp_rules.json";
    config.stagingDir = ".";

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;

    AmsiIpcHost host(config, adapters);
    return Expect(eventSink.calls.load() == 0, "constructor must not call event sink") &&
           Expect(statusSink.calls.load() == 0, "constructor must not call control status sink");
}

bool WritePipePayload(const wchar_t* pipeName, const std::string& payload)
{
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (WaitNamedPipeW(pipeName, 100)) {
            break;
        }
        Sleep(20);
    }

    HANDLE pipe = CreateFileW(pipeName,
                              GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "CreateFileW failed for pipe (GLE=%lu)\n", GetLastError());
        return false;
    }

    DWORD written = 0;
    const BOOL ok = WriteFile(pipe,
                              payload.data(),
                              static_cast<DWORD>(payload.size()),
                              &written,
                              nullptr);
    const DWORD error = ok ? ERROR_SUCCESS : GetLastError();
    CloseHandle(pipe);

    if (!ok || written != payload.size()) {
        std::fprintf(stderr,
                     "WriteFile failed for pipe (GLE=%lu written=%lu expected=%zu)\n",
                     error,
                     written,
                     payload.size());
        return false;
    }
    return true;
}

std::string ExchangeRulesPipePayload(const std::string& payload)
{
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (WaitNamedPipeW(amsi_ipc::kRulesPipeName, 100)) {
            break;
        }
        Sleep(20);
    }

    HANDLE pipe = CreateFileW(amsi_ipc::kRulesPipeName,
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        std::fprintf(stderr, "CreateFileW failed for rules pipe (GLE=%lu)\n", GetLastError());
        return "__connect_rules_failed__";
    }

    DWORD written = 0;
    if (!WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) ||
        written != payload.size()) {
        std::fprintf(stderr, "WriteFile failed for rules pipe (GLE=%lu)\n", GetLastError());
        CloseHandle(pipe);
        return "__write_rules_failed__";
    }

    char response[4096] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, response, static_cast<DWORD>(sizeof(response) - 1), &bytesRead, nullptr)) {
        std::fprintf(stderr, "ReadFile failed for rules pipe (GLE=%lu)\n", GetLastError());
        CloseHandle(pipe);
        return "__read_rules_failed__";
    }

    CloseHandle(pipe);
    return std::string(response, bytesRead);
}

bool WaitForCallCount(const std::atomic<int>& calls, int expected)
{
    for (int i = 0; i < 50; ++i) {
        if (calls.load() >= expected) {
            return true;
        }
        Sleep(20);
    }
    return calls.load() >= expected;
}

bool InjectedEventSinkReceivesPipePayload()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "rasp_rules.json";
    config.stagingDir = ".";

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;

    AmsiIpcHost host(config, adapters);
    if (!Expect(host.Start(), "host starts with injected event sink")) {
        return false;
    }

    const std::string payload = "{\"cat\":\"Detection\",\"rule\":\"adapter-event\"}";
    const bool wrote = WritePipePayload(amsi_ipc::kEventsPipeName, payload);
    const bool delivered = WaitForCallCount(eventSink.calls, 1);
    host.Stop();

    return Expect(wrote, "event payload write succeeds") &&
           Expect(delivered, "event sink receives pipe payload") &&
           Expect(eventSink.lastPayload == payload, "event sink receives unchanged payload");
}

bool InjectedControlStatusSinkReceivesPipePayload()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "rasp_rules.json";
    config.stagingDir = ".";

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;

    AmsiIpcHost host(config, adapters);
    if (!Expect(host.Start(), "host starts with injected control status sink")) {
        return false;
    }

    const std::string payload = "{\"msgType\":\"RULE_LOAD_RESULT\",\"success\":true}";
    const bool wrote = WritePipePayload(amsi_ipc::kControlStatusPipeName, payload);
    const bool delivered = WaitForCallCount(statusSink.calls, 1);
    host.Stop();

    return Expect(wrote, "control status payload write succeeds") &&
           Expect(delivered, "control status sink receives pipe payload") &&
           Expect(statusSink.lastPayload == payload, "control status sink receives unchanged payload");
}

bool InjectedRuleProviderServesRulesPipe()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;
    FakeRuleProvider ruleProvider;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "rasp_rules.json";
    config.stagingDir = ".";

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;
    adapters.ruleProvider = &ruleProvider;

    AmsiIpcHost host(config, adapters);
    if (!Expect(host.Start(), "host starts with injected rule provider")) {
        return false;
    }

    const std::string response = ExchangeRulesPipePayload("GET_RULES\n");
    host.Stop();

    return Expect(response == R"([{"id":"injected-rule","sensor":"AmsiProvider"}])" "\n",
                  "rules pipe returns injected provider response") &&
           Expect(ruleProvider.buildCalls == 1, "injected provider was called once") &&
           Expect(ruleProvider.lastCommand == "GET_RULES", "injected provider sees trimmed GET_RULES command");
}

bool InvalidateRulesUsesInjectedProvider()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;
    FakeRuleProvider ruleProvider;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "rasp_rules.json";
    config.stagingDir = ".";

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;
    adapters.ruleProvider = &ruleProvider;

    AmsiIpcHost host(config, adapters);
    host.InvalidateRules();

    return Expect(ruleProvider.invalidateCalls == 1,
                  "InvalidateRules calls injected provider");
}

bool BroadcastReloadAndUnloadReturnResultsWithoutListeners()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;
    FakeRuleProvider ruleProvider;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "rasp_rules.json";
    config.stagingDir = ".";

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;
    adapters.ruleProvider = &ruleProvider;

    AmsiIpcHost host(config, adapters);
    const auto reload = host.BroadcastReload(1, 10);
    const auto unload = host.BroadcastUnload(1, 10);

    return Expect(reload.reached == 0, "BroadcastReload reports no listeners") &&
           Expect(unload.reached == 0, "BroadcastUnload reports no listeners");
}

bool HostStartsWithDemoWatchersDisabled()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;
    FakeRuleProvider ruleProvider;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "";
    config.stagingDir = "";
    config.enableDemoConfigWatcher = false;
    config.enableDemoStagingWatcher = false;

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;
    adapters.ruleProvider = &ruleProvider;

    AmsiIpcHost host(config, adapters);
    if (!Expect(host.Start(), "host starts with demo watchers disabled")) {
        return false;
    }

    const std::string rulesResponse = ExchangeRulesPipePayload("GET_RULES\n");
    const std::string eventPayload = "{\"cat\":\"Detection\",\"rule\":\"watchers-disabled\"}";
    const std::string statusPayload = "{\"msgType\":\"RULE_LOAD_RESULT\",\"success\":true}";
    const bool eventWrote = WritePipePayload(amsi_ipc::kEventsPipeName, eventPayload);
    const bool statusWrote = WritePipePayload(amsi_ipc::kControlStatusPipeName, statusPayload);
    const bool eventDelivered = WaitForCallCount(eventSink.calls, 1);
    const bool statusDelivered = WaitForCallCount(statusSink.calls, 1);
    host.Stop();

    return Expect(rulesResponse == R"([{"id":"injected-rule","sensor":"AmsiProvider"}])" "\n",
                  "rules pipe works with demo watchers disabled") &&
           Expect(eventWrote && eventDelivered && eventSink.lastPayload == eventPayload,
                  "event pipe works with demo watchers disabled") &&
           Expect(statusWrote && statusDelivered && statusSink.lastPayload == statusPayload,
                  "control status pipe works with demo watchers disabled");
}

bool InvalidateAndBroadcastWorkWithDemoWatchersDisabled()
{
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;
    FakeRuleProvider ruleProvider;

    AmsiIpcHostConfig config;
    config.logDir = ".";
    config.rulesPath = "";
    config.stagingDir = "";
    config.enableDemoConfigWatcher = false;
    config.enableDemoStagingWatcher = false;

    AmsiIpcHostAdapters adapters;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;
    adapters.ruleProvider = &ruleProvider;

    AmsiIpcHost host(config, adapters);
    if (!Expect(host.Start(), "host starts before facade calls with demo watchers disabled")) {
        return false;
    }

    host.InvalidateRules();
    const auto reload = host.BroadcastReload(1, 10);
    host.Stop();

    return Expect(ruleProvider.invalidateCalls == 1,
                  "InvalidateRules works with demo watchers disabled") &&
           Expect(reload.reached == 0,
                  "BroadcastReload works with demo watchers disabled and no listeners");
}

} // namespace

int main()
{
    if (!AdapterConstructorAcceptsExternalSinks()) {
        return 1;
    }
    if (!InjectedEventSinkReceivesPipePayload()) {
        return 1;
    }
    if (!InjectedControlStatusSinkReceivesPipePayload()) {
        return 1;
    }
    if (!InjectedRuleProviderServesRulesPipe()) {
        return 1;
    }
    if (!InvalidateRulesUsesInjectedProvider()) {
        return 1;
    }
    if (!BroadcastReloadAndUnloadReturnResultsWithoutListeners()) {
        return 1;
    }
    if (!HostStartsWithDemoWatchersDisabled()) {
        return 1;
    }
    if (!InvalidateAndBroadcastWorkWithDemoWatchersDisabled()) {
        return 1;
    }
    return 0;
}

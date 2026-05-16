#include "amsi_ipc_host.h"

#include "amsi_control_status_sink.h"
#include "amsi_event_sink.h"
#include "amsi_rule_provider.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <atomic>
#include <cstdio>
#include <string>

namespace {

std::wstring TestPipeName(const wchar_t* suffix)
{
    return std::wstring(LR"(\\.\pipe\amsi_detect_hostguard_test_)") +
           std::to_wstring(GetCurrentProcessId()) +
           L"_" +
           suffix;
}

class FakeRuleProvider final : public amsi_ipc::IAmsiRuleProvider {
public:
    bool BuildRulesResponse(const std::string& command,
                            amsi_ipc::AmsiRuleResponse& out,
                            std::string& error) override
    {
        lastCommand = command;
        ++buildCalls;
        if (command == "GET_RULES") {
            out.json = R"([{"id":"hostguard-amsi","sensor":"AmsiProvider"}])";
            return true;
        }
        if (command == "GET_ALL_RULES") {
            out.json = R"({"rules":[{"id":"hostguard-all","sensor":"AmsiProvider"}]})";
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

class FakeEventSink final : public amsi_ipc::IAmsiEventSink {
public:
    void OnEventLine(const amsi_ipc::AmsiEventLine& event) override
    {
        lastPayload = event.payload;
        calls.fetch_add(1);
    }

    std::atomic<int> calls{0};
    std::string lastPayload;
};

class FakeControlStatusSink final : public amsi_ipc::IAmsiControlStatusSink {
public:
    void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status) override
    {
        lastPayload = status.payload;
        calls.fetch_add(1);
    }

    std::atomic<int> calls{0};
    std::string lastPayload;
};

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return false;
    }
    return true;
}

bool WaitForPipe(const std::wstring& pipeName)
{
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (WaitNamedPipeW(pipeName.c_str(), 100)) {
            return true;
        }
        Sleep(20);
    }
    return false;
}

std::string ExchangePipe(const std::wstring& pipeName, const std::string& payload)
{
    if (!WaitForPipe(pipeName)) {
        return "__wait_pipe_failed__";
    }

    HANDLE pipe = CreateFileW(pipeName.c_str(),
                              GENERIC_READ | GENERIC_WRITE,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        return "__connect_failed__";
    }

    DWORD written = 0;
    if (!WriteFile(pipe, payload.data(), static_cast<DWORD>(payload.size()), &written, nullptr) ||
        written != payload.size()) {
        CloseHandle(pipe);
        return "__write_failed__";
    }

    char response[4096] = {};
    DWORD bytesRead = 0;
    if (!ReadFile(pipe, response, static_cast<DWORD>(sizeof(response) - 1), &bytesRead, nullptr)) {
        CloseHandle(pipe);
        return "__read_failed__";
    }

    CloseHandle(pipe);
    return std::string(response, bytesRead);
}

bool WriteOnlyPipe(const std::wstring& pipeName, const std::string& payload)
{
    if (!WaitForPipe(pipeName)) {
        return false;
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

bool WaitForCallCount(const std::atomic<int>& calls, int expected)
{
    for (int attempt = 0; attempt < 50; ++attempt) {
        if (calls.load() >= expected) {
            return true;
        }
        Sleep(20);
    }
    return calls.load() >= expected;
}

} // namespace

int main()
{
    bool ok = true;

    FakeRuleProvider ruleProvider;
    FakeEventSink eventSink;
    FakeControlStatusSink statusSink;

    const std::wstring rulesPipe = TestPipeName(L"rules");
    const std::wstring eventsPipe = TestPipeName(L"events");
    const std::wstring statusPipe = TestPipeName(L"status");
    const std::wstring configPipe = TestPipeName(L"config");

    AmsiIpcHostConfig config;
    config.enableDemoConfigWatcher = false;
    config.enableDemoStagingWatcher = false;
    config.rulesPipeName = rulesPipe;
    config.eventsPipeName = eventsPipe;
    config.controlStatusPipeName = statusPipe;
    config.configPipeName = configPipe;

    AmsiIpcHostAdapters adapters;
    adapters.ruleProvider = &ruleProvider;
    adapters.eventSink = &eventSink;
    adapters.controlStatusSink = &statusSink;

    AmsiIpcHost host(config, adapters);
    ok &= Expect(host.Start(), "HostGuard-style host starts with injected adapters and test pipe names");

    ok &= Expect(ExchangePipe(rulesPipe, "GET_RULES\n") ==
                     R"([{"id":"hostguard-amsi","sensor":"AmsiProvider"}])" "\n",
                 "GET_RULES uses injected provider");
    ok &= Expect(ruleProvider.lastCommand == "GET_RULES",
                 "GET_RULES command is trimmed before provider call");

    ok &= Expect(ExchangePipe(rulesPipe, "GET_ALL_RULES\n") ==
                     R"({"rules":[{"id":"hostguard-all","sensor":"AmsiProvider"}]})" "\n",
                 "GET_ALL_RULES uses injected provider");
    ok &= Expect(ruleProvider.lastCommand == "GET_ALL_RULES",
                 "GET_ALL_RULES command is trimmed before provider call");

    const std::string eventPayload = u8"{\"cat\":\"Detection\",\"msg\":\"中文-🙂\"}";
    ok &= Expect(WriteOnlyPipe(eventsPipe, eventPayload), "event payload write succeeds");
    ok &= Expect(WaitForCallCount(eventSink.calls, 1), "event sink receives payload");
    ok &= Expect(eventSink.lastPayload == eventPayload,
                 "event payload is forwarded unchanged");
    ok &= Expect(!eventSink.lastPayload.empty() && eventSink.lastPayload.back() != '\n',
                 "event payload does not get an appended newline");

    const std::string statusPayload = u8"{\"msgType\":\"RULE_LOAD_RESULT\",\"detail\":\"状态-🙂\"}";
    ok &= Expect(WriteOnlyPipe(statusPipe, statusPayload), "control status payload write succeeds");
    ok &= Expect(WaitForCallCount(statusSink.calls, 1), "control status sink receives payload");
    ok &= Expect(statusSink.lastPayload == statusPayload,
                 "control status payload is forwarded unchanged");
    ok &= Expect(!statusSink.lastPayload.empty() && statusSink.lastPayload.back() != '\n',
                 "control status payload does not get an appended newline");

    host.InvalidateRules();
    ok &= Expect(ruleProvider.invalidateCalls == 1, "InvalidateRules reaches injected provider");

    const auto reload = host.BroadcastReload(1, 10);
    const auto unload = host.BroadcastUnload(1, 10);
    ok &= Expect(reload.reached == 0, "test config pipe has no reload listener");
    ok &= Expect(unload.reached == 0, "test config pipe has no unload listener");

    host.Stop();

    return ok ? 0 : 1;
}

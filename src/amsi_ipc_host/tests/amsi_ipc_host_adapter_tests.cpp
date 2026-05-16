#include "amsi_ipc_host.h"

#include "amsi_control_status_sink.h"
#include "amsi_event_sink.h"
#include "amsi_pipe_names.h"

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
    return 0;
}

#include "hostguard_demo_app.h"
#include "hostguard_file_rule_provider.h"
#include "hostguard_jsonl_control_status_sink.h"
#include "hostguard_jsonl_event_sink.h"
#include "hostguard_paths.h"

#include "amsi_rule_provider.h"
#include "sentry_log.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <fstream>
#include <string>

namespace {

bool Expect(bool condition, const char* message)
{
    if (!condition) {
        std::fprintf(stderr, "FAIL: %s\n", message);
        return false;
    }
    return true;
}

std::string TempRoot()
{
    char buffer[MAX_PATH] = {};
    GetTempPathA(static_cast<DWORD>(sizeof(buffer)), buffer);
    std::string root = std::string(buffer) + "hostguard_demo_tests_" + std::to_string(GetCurrentProcessId());
    CreateDirectoryA(root.c_str(), nullptr);
    return root;
}

std::wstring TestPipeName(const wchar_t* suffix)
{
    return std::wstring(LR"(\\.\pipe\hostguard_demo_test_)") +
           std::to_wstring(GetCurrentProcessId()) +
           L"_" +
           suffix;
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

std::string ReadFileText(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

} // namespace

int main()
{
    const std::string root = TempRoot();
    const std::string logDir = root + "\\logs";
    CreateDirectoryA(logDir.c_str(), nullptr);
    SentryLog_Initialize(logDir.c_str());

    bool ok = true;

    const std::string rulesPath = root + "\\rasp_rules.json";
    {
        std::ofstream rules(rulesPath, std::ios::binary);
        rules << R"({"rules":[{"id":"amsi-1","sensor":"AmsiProvider"},{"id":"other-1","sensor":"OtherSensor"}]})";
    }

    HostGuardFileRuleProvider provider(rulesPath);
    amsi_ipc::AmsiRuleResponse response;
    std::string error;
    ok &= Expect(provider.BuildRulesResponse("GET_RULES", response, error), "GET_RULES succeeds");
    ok &= Expect(response.json.find("amsi-1") != std::string::npos, "GET_RULES includes AMSI rule");
    ok &= Expect(response.json.find("other-1") == std::string::npos, "GET_RULES filters non-AMSI rule");

    ok &= Expect(provider.BuildRulesResponse("GET_ALL_RULES", response, error), "GET_ALL_RULES succeeds");
    ok &= Expect(response.json.find("other-1") != std::string::npos, "GET_ALL_RULES includes full rule set");

    {
        std::ofstream rules(rulesPath, std::ios::binary);
        rules << R"({"rules":[{"id":"amsi-2","sensor":"AmsiProvider"}]})";
    }
    provider.InvalidateRuleCache();
    ok &= Expect(provider.BuildRulesResponse("GET_RULES", response, error), "GET_RULES succeeds after invalidation");
    ok &= Expect(response.json.find("amsi-2") != std::string::npos, "InvalidateRuleCache refreshes rules");

    HostGuardJsonlEventSink eventSink(logDir);
    eventSink.OnEventLine(amsi_ipc::AmsiEventLine{R"({"event":1})"});
    ok &= Expect(ReadFileText(hostguard_demo::DailyJsonlPath(logDir, "rasp-events")).find(R"({"event":1})") != std::string::npos,
                 "event sink writes JSONL payload");

    HostGuardJsonlControlStatusSink statusSink(logDir);
    statusSink.OnControlStatusLine(amsi_ipc::AmsiControlStatusLine{R"({"status":1})"});
    ok &= Expect(ReadFileText(hostguard_demo::DailyJsonlPath(logDir, "rasp-control-status")).find(R"({"status":1})") != std::string::npos,
                 "control status sink writes JSONL payload");

    HostGuardDemoOptions options;
    options.rulesPath = rulesPath;
    options.logDir = logDir;
    options.rulesPipeName = TestPipeName(L"rules");
    options.eventsPipeName = TestPipeName(L"events");
    options.controlStatusPipeName = TestPipeName(L"status");
    options.configPipeName = TestPipeName(L"config");

    HostGuardDemoApp app(options);
    ok &= Expect(app.Start(), "HostGuardDemoApp starts");
    ok &= Expect(app.started(), "HostGuardDemoApp reports started");
    const std::string appRulesResponse = ExchangePipe(options.rulesPipeName, "GET_RULES\n");
    if (appRulesResponse.find("amsi-2") == std::string::npos) {
        std::fprintf(stderr, "rules response: %s\n", appRulesResponse.c_str());
    }
    ok &= Expect(appRulesResponse.find("amsi-2") != std::string::npos,
                 "app rules pipe serves provider content");
    const bool wroteEvent = WriteOnlyPipe(options.eventsPipeName, R"({"pipeEvent":1})");
    if (!wroteEvent) {
        std::fprintf(stderr, "event pipe write failed, lastError=%lu\n", GetLastError());
    }
    ok &= Expect(wroteEvent, "app event pipe accepts payload");
    Sleep(100);
    ok &= Expect(ReadFileText(hostguard_demo::DailyJsonlPath(logDir, "rasp-events")).find(R"({"pipeEvent":1})") != std::string::npos,
                 "app event pipe reaches JSONL sink");
    const bool wroteStatus = WriteOnlyPipe(options.controlStatusPipeName, R"({"pipeStatus":1})");
    if (!wroteStatus) {
        std::fprintf(stderr, "status pipe write failed, lastError=%lu\n", GetLastError());
    }
    ok &= Expect(wroteStatus, "app control status pipe accepts payload");
    Sleep(100);
    ok &= Expect(ReadFileText(hostguard_demo::DailyJsonlPath(logDir, "rasp-control-status")).find(R"({"pipeStatus":1})") != std::string::npos,
                 "app control status pipe reaches JSONL sink");
    ok &= Expect(app.Reload(), "reload command completes");
    ok &= Expect(app.Unload(), "unload command completes");
    app.Stop();
    ok &= Expect(!app.started(), "HostGuardDemoApp reports stopped");

    return ok ? 0 : 1;
}

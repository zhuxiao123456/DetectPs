#include "control_status_collector.h"

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

std::string ReadFileText(const std::string& path)
{
    std::ifstream input(path, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(input)),
                       std::istreambuf_iterator<char>());
}

std::string TempTestDir()
{
    char tempPath[MAX_PATH] = {};
    GetTempPathA(MAX_PATH, tempPath);
    char path[MAX_PATH] = {};
    _snprintf_s(path, sizeof(path), _TRUNCATE,
                "%srasp_sentry_control_status_collector_%lu_%lu",
                tempPath,
                static_cast<unsigned long>(GetCurrentProcessId()),
                static_cast<unsigned long>(GetTickCount()));
    CreateDirectoryA(path, nullptr);
    return std::string(path);
}

std::string ControlStatusPath(const std::string& logDir)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char dateBuf[16];
    _snprintf_s(dateBuf, sizeof(dateBuf), _TRUNCATE,
                "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    return logDir + "\\rasp-control-status-" + dateBuf + ".jsonl";
}

} // namespace

int main()
{
    bool ok = true;
    const std::string logDir = TempTestDir();

    {
        ControlStatusCollector collector(logDir);
        collector.OnControlStatusLine({
            R"({"msgType":"DLL_LOADED","instanceId":"amsi_detect_4321_20260518T100000000Z_1111111111111111","pid":4321,"processStartTime":"2026-05-18T10:00:00.000Z","processPath":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","parentPid":1000,"parentProcessPath":"C:\\Windows\\System32\\cmd.exe"})"
        });

        std::string snapshot = ReadFileText(logDir + "\\rasp-dll-instances.json");
        ok &= Expect(snapshot.find("\"onlineDllCount\": 1") != std::string::npos,
                     "DLL_LOADED snapshot has onlineDllCount=1");
        ok &= Expect(snapshot.find("\"historicalLoadedDllCount\": 1") != std::string::npos,
                     "DLL_LOADED snapshot has one historical instance");
        ok &= Expect(snapshot.find("\"ruleLoadSeen\":false") != std::string::npos,
                     "DLL_LOADED snapshot starts without ruleLoadSeen");

        collector.OnControlStatusLine({
            R"({"msgType":"RULE_LOAD_RESULT","dllInstanceId":"amsi_detect_4321_20260518T100000000Z_1111111111111111","pid":4321,"activeVersion":"v42","success":true})"
        });

        snapshot = ReadFileText(logDir + "\\rasp-dll-instances.json");
        ok &= Expect(snapshot.find("\"onlineDllCount\": 1") != std::string::npos,
                     "RULE_LOAD_RESULT keeps one online instance");
        ok &= Expect(snapshot.find("\"historicalLoadedDllCount\": 1") != std::string::npos,
                     "RULE_LOAD_RESULT does not create a duplicate instance");
        ok &= Expect(snapshot.find("\"instancesWithRuleLoadResult\": 1") != std::string::npos,
                     "RULE_LOAD_RESULT increments rule load coverage");
        ok &= Expect(snapshot.find("\"ruleLoadSeen\":true") != std::string::npos,
                     "RULE_LOAD_RESULT marks the existing instance ruleLoadSeen");
        ok &= Expect(snapshot.find("\"lastRuleVersion\":\"v42\"") != std::string::npos,
                     "RULE_LOAD_RESULT stores active version");

        const std::string raw = ReadFileText(ControlStatusPath(logDir));
        ok &= Expect(raw.find("\"msgType\":\"DLL_LOADED\"") != std::string::npos,
                     "collector preserves raw DLL_LOADED JSONL");
        ok &= Expect(raw.find("\"msgType\":\"RULE_LOAD_RESULT\"") != std::string::npos,
                     "collector preserves raw RULE_LOAD_RESULT JSONL");
    }

    DeleteFileA((logDir + "\\rasp-dll-instances.json").c_str());
    DeleteFileA(ControlStatusPath(logDir).c_str());
    RemoveDirectoryA(logDir.c_str());
    return ok ? 0 : 1;
}

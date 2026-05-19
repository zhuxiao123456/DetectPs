#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdio>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

#include "amsi_ipc_host.h"
#include "sentry_log.h"

static HANDLE g_stopEvent = nullptr;

static BOOL WINAPI CtrlHandler(DWORD type)
{
    if (type == CTRL_C_EVENT ||
        type == CTRL_BREAK_EVENT ||
        type == CTRL_CLOSE_EVENT ||
        type == CTRL_SHUTDOWN_EVENT)
    {
        if (g_stopEvent)
            SetEvent(g_stopEvent);
        return TRUE;
    }
    return FALSE;
}

static std::string WideToUtf8(const wchar_t* ws)
{
    if (!ws || !ws[0])
        return {};
    int len = WideCharToMultiByte(CP_UTF8, 0, ws, -1, nullptr, 0, nullptr, nullptr);
    std::string out(len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, ws, -1, &out[0], len, nullptr, nullptr);
    if (!out.empty() && out.back() == '\0')
        out.pop_back();
    return out;
}

static std::string NormalizeCommand(std::string command)
{
    command.erase(std::remove_if(command.begin(),
                                 command.end(),
                                 [](unsigned char ch) { return ch == '\r' || ch == '\n'; }),
                  command.end());
    std::transform(command.begin(),
                   command.end(),
                   command.begin(),
                   [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
    return command;
}

static void PrintBroadcastResult(const char* action,
                                 const amsi_ipc::AmsiBroadcastResult& result)
{
    std::printf("%s: reached=%d lastError=%lu\n",
                action,
                result.reached,
                static_cast<unsigned long>(result.lastError));
}

static void RunCommandLoop(std::shared_ptr<AmsiIpcHost> host,
                           std::atomic<bool>& lastRequestedPolicyPaused,
                           std::atomic<bool>& keepRunning)
{
    std::string command;
    while (keepRunning.load(std::memory_order_relaxed) &&
           std::cout << "rasp_sentry> " &&
           std::getline(std::cin, command))
    {
        command = NormalizeCommand(command);
        if (command.empty()) {
            continue;
        }
        if (command == "quit" || command == "exit") {
            if (g_stopEvent) {
                SetEvent(g_stopEvent);
            }
            break;
        }
        if (command == "status") {
            std::printf("lastRequestedPolicyPaused: %s\n",
                        lastRequestedPolicyPaused.load(std::memory_order_relaxed) ? "yes" : "no");
            std::printf("note: host-side command record only; not per-DLL actual state\n");
            continue;
        }
        if (command == "reload") {
            host->InvalidateRules();
            const auto result = host->BroadcastReload();
            PrintBroadcastResult("reload", result);
            continue;
        }
        if (command == "unload") {
            const auto result = host->BroadcastUnload();
            PrintBroadcastResult("unload", result);
            continue;
        }
        if (command == "pause" || command == "policy-off" || command == "disable-detection") {
            const auto result = host->BroadcastPauseDetection();
            lastRequestedPolicyPaused.store(true, std::memory_order_relaxed);
            PrintBroadcastResult("policy-off", result);
            SentryLog_Info("Program", "policy-off broadcast reached=%d lastError=%lu",
                           result.reached, static_cast<unsigned long>(result.lastError));
            continue;
        }
        if (command == "resume" || command == "policy-on" || command == "enable-detection") {
            const auto result = host->BroadcastResumeDetection();
            lastRequestedPolicyPaused.store(false, std::memory_order_relaxed);
            PrintBroadcastResult("policy-on", result);
            SentryLog_Info("Program", "policy-on broadcast reached=%d lastError=%lu",
                           result.reached, static_cast<unsigned long>(result.lastError));
            continue;
        }
        std::printf("unknown command: %s\n", command.c_str());
    }
}

int wmain(int argc, wchar_t** argv)
{
    std::string logDir = "C:\\RaspSentry\\rasp_logs";
    std::string rulesPath = "C:\\RaspSentry\\rasp_rules.json";
    std::string stagingDir = "C:\\RaspSentry\\staging";

    for (int i = 1; i + 1 < argc; i++)
    {
        if (wcscmp(argv[i], L"--log") == 0)
            logDir = WideToUtf8(argv[i + 1]);
        else if (wcscmp(argv[i], L"--rules") == 0)
            rulesPath = WideToUtf8(argv[i + 1]);
        else if (wcscmp(argv[i], L"--staging") == 0)
            stagingDir = WideToUtf8(argv[i + 1]);
    }

    if (!CreateDirectoryA(logDir.c_str(), nullptr) &&
        GetLastError() != ERROR_ALREADY_EXISTS)
    {
        fprintf(stderr, "rasp_sentry: cannot create log directory '%s' (GLE=%lu)\n",
                logDir.c_str(), GetLastError());
        return 1;
    }

    SentryLog_Initialize(logDir.c_str());
    SentryLog_Info("Program", "rasp_sentry_native starting");
    SentryLog_Info("Program", "  logDir     = %s", logDir.c_str());
    SentryLog_Info("Program", "  rulesPath  = %s", rulesPath.c_str());
    SentryLog_Info("Program", "  stagingDir = %s", stagingDir.c_str());

    g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    if (!g_stopEvent) {
        SentryLog_Error("Program", "CreateEvent failed (GLE=%lu)", GetLastError());
        return 1;
    }
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    auto host = std::make_shared<AmsiIpcHost>(AmsiIpcHostConfig{logDir, rulesPath, stagingDir});
    if (!host->Start()) {
        SentryLog_Error("Program", "failed to start AMSI IPC host");
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 1;
    }

    std::atomic<bool> lastRequestedPolicyPaused{false};
    std::atomic<bool> keepCommandLoopRunning{true};
    std::thread commandThread(RunCommandLoop,
                              host,
                              std::ref(lastRequestedPolicyPaused),
                              std::ref(keepCommandLoopRunning));

    SentryLog_Info("Program", "rasp_sentry_native running. Press Ctrl+C to stop.");
    std::printf("rasp_sentry_native running. Commands: status, reload, unload, policy-off, policy-on, quit\n");
    WaitForSingleObject(g_stopEvent, INFINITE);

    keepCommandLoopRunning.store(false, std::memory_order_relaxed);
    if (commandThread.joinable()) {
        if (GetFileType(GetStdHandle(STD_INPUT_HANDLE)) == FILE_TYPE_CHAR) {
            commandThread.detach();
        } else {
            commandThread.join();
        }
    }

    SentryLog_Info("Program", "rasp_sentry_native stopping...");
    host->Stop();

    SentryLog_Info("Program", "rasp_sentry_native stopped.");
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    return 0;
}

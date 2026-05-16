#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <cstdio>
#include <string>

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

    AmsiIpcHost host(AmsiIpcHostConfig{logDir, rulesPath, stagingDir});
    if (!host.Start()) {
        SentryLog_Error("Program", "failed to start AMSI IPC host");
        CloseHandle(g_stopEvent);
        g_stopEvent = nullptr;
        return 1;
    }

    SentryLog_Info("Program", "rasp_sentry_native running. Press Ctrl+C to stop.");
    WaitForSingleObject(g_stopEvent, INFINITE);

    SentryLog_Info("Program", "rasp_sentry_native stopping...");
    host.Stop();

    SentryLog_Info("Program", "rasp_sentry_native stopped.");
    CloseHandle(g_stopEvent);
    g_stopEvent = nullptr;
    return 0;
}

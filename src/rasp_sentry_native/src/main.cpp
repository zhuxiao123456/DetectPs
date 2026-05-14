#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <string>
#include <cstdio>

#include "sentry_log.h"
#include "event_collector.h"
#include "control_status_collector.h"
#include "rule_server.h"
#include "config_watcher.h"
#include "amsi_staging_watcher.h"

// ── Shutdown synchronisation ──────────────────────────────────────────────────

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

// ── String helpers ────────────────────────────────────────────────────────────

static std::string WideToUtf8(const wchar_t *ws)
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

// ── Entry point ───────────────────────────────────────────────────────────────

int wmain(int argc, wchar_t **argv)
{
    // ── Defaults — mirror C# ConfigurationManager.AppSettings defaults ────────
    std::string logDir = "C:\\RaspSentry\\rasp_logs";
    std::string rulesPath = "C:\\RaspSentry\\rasp_rules.json";
    std::string stagingDir = "C:\\RaspSentry\\staging";

    // ── CLI argument parsing: --log <dir>  --rules <path>  --staging <dir> ────
    for (int i = 1; i + 1 < argc; i++)
    {
        if (wcscmp(argv[i], L"--log") == 0)
            logDir = WideToUtf8(argv[i + 1]);
        else if (wcscmp(argv[i], L"--rules") == 0)
            rulesPath = WideToUtf8(argv[i + 1]);
        else if (wcscmp(argv[i], L"--staging") == 0)
            stagingDir = WideToUtf8(argv[i + 1]);
    }

    // ── Create log directory ──────────────────────────────────────────────────
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

    // ── Stop event + Ctrl+C handler ───────────────────────────────────────────
    g_stopEvent = CreateEvent(nullptr, TRUE, FALSE, nullptr);
    SetConsoleCtrlHandler(CtrlHandler, TRUE);

    // ── Instantiate services ──────────────────────────────────────────────────
    EventCollector collector(logDir);
    ControlStatusCollector controlStatusCollector(logDir);
    RuleServer ruleServer(rulesPath);
    ConfigWatcher watcher(rulesPath, &ruleServer);
    AmsiStagingWatcher stagingWatcher(stagingDir, collector.GetDrainQueue());

    // ── Start in dependency order (mirrors Program.cs) ────────────────────────
    collector.Start();
    SentryLog_Info("Program", "EventCollector started - %d threads on amsi_detect_events",
                   EventCollector::kThreadCount);

    controlStatusCollector.Start();
    SentryLog_Info("Program", "ControlStatusCollector started - %d threads on amsi_detect_control_status",
                   ControlStatusCollector::kThreadCount);

    ruleServer.Start();
    SentryLog_Info("Program", "RuleServer started - %d threads on amsi_detect_rules",
                   RuleServer::kThreadCount);

    watcher.Start();
    SentryLog_Info("Program", "ConfigWatcher started — watching %s", rulesPath.c_str());

    stagingWatcher.Start();
    SentryLog_Info("Program", "AmsiStagingWatcher started — staging: %s", stagingDir.c_str());

    SentryLog_Info("Program", "rasp_sentry_native running. Press Ctrl+C to stop.");

    // ── Block until Ctrl+C / service stop ─────────────────────────────────────
    WaitForSingleObject(g_stopEvent, INFINITE);

    SentryLog_Info("Program", "rasp_sentry_native stopping...");

    // ── Stop in reverse order ─────────────────────────────────────────────────
    stagingWatcher.Stop();
    watcher.Stop();
    ruleServer.Stop();
    controlStatusCollector.Stop();
    collector.Stop();

    SentryLog_Info("Program", "rasp_sentry_native stopped.");
    CloseHandle(g_stopEvent);
    return 0;
}

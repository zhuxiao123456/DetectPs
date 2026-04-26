#include "sentry_log.h"
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>

// ── Module-global state ───────────────────────────────────────────────────────

static char            g_logDir[MAX_PATH] = {};
static CRITICAL_SECTION g_cs;
static bool            g_csReady = false;

// ── Internal helpers ──────────────────────────────────────────────────────────

static std::string BuildLogPath()
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char dateBuf[16];
    _snprintf_s(dateBuf, sizeof(dateBuf), _TRUNCATE,
                "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);
    std::string path = std::string(g_logDir) +
                       "\\rasp-sentry-diag-" + dateBuf + ".log";
    return path;
}

static void Write(const char* level, const char* component, const char* message)
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    char header[64];
    _snprintf_s(header, sizeof(header), _TRUNCATE,
                "[%04d-%02d-%02d %02d:%02d:%02d.%03d UTC] %s [%s] ",
                st.wYear, st.wMonth, st.wDay,
                st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                level, component);

    if (!g_csReady) return;
    EnterCriticalSection(&g_cs);

    // Console
    fputs(header,  stdout);
    fputs(message, stdout);
    fputc('\n',    stdout);

    // Daily log file — open-append-close per write (matches C# File.AppendAllText)
    std::string path = BuildLogPath();
    HANDLE hFile = CreateFileA(path.c_str(),
                               FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        std::string line = std::string(header) + message + "\n";
        DWORD written = 0;
        WriteFile(hFile, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
        CloseHandle(hFile);
    }

    LeaveCriticalSection(&g_cs);
}

// ── Public API ────────────────────────────────────────────────────────────────

void SentryLog_Initialize(const char* logDir)
{
    strncpy_s(g_logDir, sizeof(g_logDir), logDir ? logDir : "", _TRUNCATE);
    InitializeCriticalSection(&g_cs);
    g_csReady = true;
}

static void Logv(const char* level, const char* component, const char* fmt, va_list ap)
{
    char buf[2048];
    _vsnprintf_s(buf, sizeof(buf), _TRUNCATE, fmt, ap);
    Write(level, component, buf);
}

void SentryLog_Info(const char* component, const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt); Logv("INFO ", component, fmt, ap); va_end(ap);
}

void SentryLog_Warn(const char* component, const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt); Logv("WARN ", component, fmt, ap); va_end(ap);
}

void SentryLog_Error(const char* component, const char* fmt, ...)
{
    va_list ap; va_start(ap, fmt); Logv("ERROR", component, fmt, ap); va_end(ap);
}

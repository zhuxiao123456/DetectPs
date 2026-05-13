#include "control_status_collector.h"
#include "pipe_security.h"
#include "sentry_log.h"

#include <cstdio>
#include <string>
#include <utility>

ControlStatusCollector::ControlStatusCollector(std::string logDir)
    : m_logDir(std::move(logDir))
{
    for (auto& h : m_threads)
        h = INVALID_HANDLE_VALUE;
}

ControlStatusCollector::~ControlStatusCollector()
{
    if (m_running.load())
        Stop();
}

void ControlStatusCollector::Start()
{
    InitializeCriticalSection(&m_fileLock);
    m_running.store(true);
    for (int i = 0; i < kThreadCount; ++i)
    {
        DWORD tid = 0;
        m_threads[i] = CreateThread(nullptr, 0, ThreadProc, this, 0, &tid);
        if (m_threads[i] == nullptr || m_threads[i] == INVALID_HANDLE_VALUE)
            SentryLog_Error("ControlStatusCollector", "Failed to create thread %d (GLE=%lu)", i, GetLastError());
    }
}

void ControlStatusCollector::Stop()
{
    m_running.store(false);

    for (int i = 0; i < kThreadCount; ++i)
    {
        HANDLE h = CreateFileW(L"\\\\.\\pipe\\amsi_detect_control_status",
                               GENERIC_WRITE, 0, nullptr,
                               OPEN_EXISTING, 0, nullptr);
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
    }

    HANDLE valid[kThreadCount];
    int count = 0;
    for (auto& h : m_threads)
        if (h != INVALID_HANDLE_VALUE)
            valid[count++] = h;
    if (count > 0)
        WaitForMultipleObjects(count, valid, TRUE, 3000);

    for (auto& h : m_threads)
    {
        if (h != INVALID_HANDLE_VALUE)
            CloseHandle(h);
        h = INVALID_HANDLE_VALUE;
    }

    DeleteCriticalSection(&m_fileLock);
}

DWORD WINAPI ControlStatusCollector::ThreadProc(LPVOID param)
{
    static_cast<ControlStatusCollector*>(param)->ServerLoop();
    return 0;
}

void ControlStatusCollector::ServerLoop()
{
    SECURITY_ATTRIBUTES sa = {};
    PACL acl = nullptr;
    bool haveSa = MakeAuthenticatedUsersSecurity(&sa, &acl);

    while (m_running.load())
    {
        HANDLE hPipe = CreateNamedPipeW(
            L"\\\\.\\pipe\\amsi_detect_control_status",
            PIPE_ACCESS_INBOUND,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            kThreadCount,
            0,
            65536,
            0,
            haveSa ? &sa : nullptr);

        if (hPipe == INVALID_HANDLE_VALUE)
        {
            SentryLog_Error("ControlStatusCollector", "CreateNamedPipeW failed (GLE=%lu)", GetLastError());
            Sleep(100);
            continue;
        }

        BOOL connected = ConnectNamedPipe(hPipe, nullptr);
        if (!m_running.load())
        {
            DisconnectNamedPipe(hPipe);
            CloseHandle(hPipe);
            break;
        }
        if (!connected && GetLastError() != ERROR_PIPE_CONNECTED)
        {
            CloseHandle(hPipe);
            continue;
        }

        char buf[65536];
        DWORD bytesRead = 0;
        BOOL ok = ReadFile(hPipe, buf, static_cast<DWORD>(sizeof(buf) - 1), &bytesRead, nullptr);

        DisconnectNamedPipe(hPipe);
        CloseHandle(hPipe);

        if (!ok || bytesRead == 0)
            continue;
        buf[bytesRead] = '\0';

        std::string line(buf, bytesRead);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
            line.pop_back();
        if (!line.empty())
            AppendLine(line);
    }

    if (haveSa)
        FreePipeSecurity(&sa, acl);
}

void ControlStatusCollector::AppendLine(const std::string& jsonLine)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char dateBuf[16];
    _snprintf_s(dateBuf, sizeof(dateBuf), _TRUNCATE,
                "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);

    std::string path = m_logDir + "\\rasp-control-status-" + dateBuf + ".jsonl";

    EnterCriticalSection(&m_fileLock);
    HANDLE hFile = CreateFileA(path.c_str(),
                               FILE_APPEND_DATA,
                               FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_ALWAYS,
                               FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        std::string line = jsonLine + "\n";
        DWORD written = 0;
        WriteFile(hFile, line.c_str(), static_cast<DWORD>(line.size()), &written, nullptr);
        CloseHandle(hFile);
    }
    LeaveCriticalSection(&m_fileLock);

    SentryLog_Info("ControlStatusCollector", "Appended control status to %s", path.c_str());
}

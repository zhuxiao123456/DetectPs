#include "control_status_collector.h"
#include "sentry_log.h"

#include <cstdio>
#include <string>
#include <utility>

ControlStatusCollector::ControlStatusCollector(std::string logDir)
    : m_logDir(std::move(logDir)),
      m_statusChannel(*this),
      m_statusPipePool(amsi_ipc::kControlStatusPipeName,
                       kThreadCount,
                       m_statusChannel,
                       0,
                       65536,
                       PIPE_ACCESS_INBOUND,
                       GENERIC_WRITE)
{
}

ControlStatusCollector::~ControlStatusCollector()
{
    Stop();
}

void ControlStatusCollector::Start()
{
    if (m_started) {
        return;
    }
    InitializeCriticalSection(&m_fileLock);
    m_started = true;
    if (!m_statusPipePool.Start()) {
        SentryLog_Error("ControlStatusCollector", "Failed to start one or more control status pipe worker thread(s)");
    }
}

void ControlStatusCollector::Stop()
{
    if (!m_started) {
        return;
    }

    m_statusPipePool.Stop();
    DeleteCriticalSection(&m_fileLock);
    m_started = false;
}

void ControlStatusCollector::OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status)
{
    std::string line = status.payload;
    // Preserve legacy ControlStatusCollector behavior exactly: trim only
    // trailing LF, CR, and space before appending non-empty payloads.
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    if (!line.empty())
        AppendLine(line);
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

#include "event_collector.h"
#include "sentry_log.h"
#include <cstdio>
#include <string>

// ── DrainAckQueue ─────────────────────────────────────────────────────────────

EventCollector::DrainAckQueue::DrainAckQueue()
{
    InitializeCriticalSection(&m_cs);
}

EventCollector::DrainAckQueue::~DrainAckQueue()
{
    DeleteCriticalSection(&m_cs);
}

void EventCollector::DrainAckQueue::Enqueue(const std::string& line)
{
    EnterCriticalSection(&m_cs);
    m_items.push_back(line);
    LeaveCriticalSection(&m_cs);
}

bool EventCollector::DrainAckQueue::TryDequeue(std::string& out)
{
    EnterCriticalSection(&m_cs);
    if (m_items.empty()) { LeaveCriticalSection(&m_cs); return false; }
    out = std::move(m_items.front());
    m_items.pop_front();
    LeaveCriticalSection(&m_cs);
    return true;
}

// ── EventCollector ────────────────────────────────────────────────────────────

EventCollector::EventCollector(std::string logDir)
    : m_logDir(std::move(logDir)),
      m_eventChannel(*this),
      m_eventPipePool(amsi_ipc::kEventsPipeName,
                      kThreadCount,
                      m_eventChannel,
                      0,
                      65536,
                      PIPE_ACCESS_INBOUND,
                      GENERIC_WRITE)
{
}

EventCollector::~EventCollector()
{
    Stop();
}

void EventCollector::Start()
{
    if (m_started) {
        return;
    }
    InitializeCriticalSection(&m_fileLock);
    m_started = true;
    if (!m_eventPipePool.Start()) {
        SentryLog_Error("EventCollector", "Failed to start one or more event pipe worker thread(s)");
    }
}

void EventCollector::Stop()
{
    if (!m_started) {
        return;
    }
    m_eventPipePool.Stop();
    DeleteCriticalSection(&m_fileLock);
    m_started = false;
}

void EventCollector::OnEventLine(const amsi_ipc::AmsiEventLine& event)
{
    std::string line = event.payload;
    // Preserve legacy EventCollector behavior: trim only trailing whitespace
    // after the pipe payload has been received, then append non-empty events.
    while (!line.empty() && (line.back() == '\n' || line.back() == '\r' || line.back() == ' '))
        line.pop_back();
    if (!line.empty())
        AppendLine(line);
}

void EventCollector::AppendLine(const std::string& jsonLine)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char dateBuf[16];
    _snprintf_s(dateBuf, sizeof(dateBuf), _TRUNCATE,
                "%04d-%02d-%02d", st.wYear, st.wMonth, st.wDay);

    std::string path = m_logDir + "\\rasp-events-" + dateBuf + ".jsonl";

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

    SentryLog_Info("EventCollector", "Appended event to %s", path.c_str());

    // Forward drain-ack events to AmsiStagingWatcher
    if (jsonLine.find("\"cat\":\"drain-ack\"") != std::string::npos)
        m_drainQueue.Enqueue(jsonLine);
}

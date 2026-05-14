#pragma once
// event_collector.h - 16-thread named pipe server on \\.\pipe\amsi_detect_events.
// Receives JSONL lines from all RASP modules and appends them to daily log files.
// Also detects "drain-ack" events and enqueues them for AmsiStagingWatcher.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <atomic>
#include <deque>
#include <string>

class EventCollector
{
public:
    static constexpr const wchar_t* kPipeName   = L"amsi_detect_events";
    static constexpr int            kThreadCount = 16;

    // Thread-safe MPSC queue shared with AmsiStagingWatcher.
    struct DrainAckQueue
    {
        DrainAckQueue();
        ~DrainAckQueue();
        void        Enqueue(const std::string& line);
        bool        TryDequeue(std::string& out);   // returns false when empty
    private:
        CRITICAL_SECTION     m_cs;
        std::deque<std::string> m_items;
    };

    explicit EventCollector(std::string logDir);
    ~EventCollector();

    void Start();
    void Stop();

    DrainAckQueue* GetDrainQueue() { return &m_drainQueue; }

private:
    std::string       m_logDir;
    std::atomic<bool> m_running{false};
    HANDLE            m_threads[kThreadCount];
    CRITICAL_SECTION  m_fileLock;
    DrainAckQueue     m_drainQueue;

    static DWORD WINAPI ThreadProc(LPVOID param);
    void  ServerLoop();
    void  AppendLine(const std::string& jsonLine);
};

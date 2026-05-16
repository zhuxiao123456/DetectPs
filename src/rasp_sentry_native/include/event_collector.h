#pragma once
// event_collector.h - 16-thread named pipe server on \\.\pipe\amsi_detect_events.
// Receives JSONL lines from all RASP modules and appends them to daily log files.
// Also detects "drain-ack" events and enqueues them for AmsiStagingWatcher.

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <deque>
#include <string>

#include "amsi_event_channel.h"
#include "amsi_event_sink.h"
#include "amsi_pipe_names.h"
#include "named_pipe_server_pool.h"

class EventCollector : public amsi_ipc::IAmsiEventSink
{
public:
    static constexpr const wchar_t* kPipeName   = amsi_ipc::kEventsPipeName;
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
    void OnEventLine(const amsi_ipc::AmsiEventLine& event) override;

    DrainAckQueue* GetDrainQueue() { return &m_drainQueue; }

private:
    std::string       m_logDir;
    bool              m_started = false;
    CRITICAL_SECTION  m_fileLock;
    DrainAckQueue     m_drainQueue;
    amsi_ipc::AmsiEventChannel m_eventChannel;
    amsi_ipc::NamedPipeServerPool m_eventPipePool;

    void  AppendLine(const std::string& jsonLine);
};

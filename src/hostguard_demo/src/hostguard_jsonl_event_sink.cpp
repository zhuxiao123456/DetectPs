#include "hostguard_jsonl_event_sink.h"

#include "hostguard_paths.h"

#include <fstream>

HostGuardJsonlEventSink::HostGuardJsonlEventSink(std::string logDir)
    : logDir_(std::move(logDir))
{
    hostguard_demo::EnsureDirectory(logDir_);
}

void HostGuardJsonlEventSink::OnEventLine(const amsi_ipc::AmsiEventLine& event)
{
    std::lock_guard<std::mutex> guard(lock_);
    std::ofstream output(hostguard_demo::DailyJsonlPath(logDir_, "rasp-events"),
                         std::ios::binary | std::ios::app);
    output << event.payload << '\n';
}

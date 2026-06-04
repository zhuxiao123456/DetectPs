#include "hostguard_jsonl_event_sink.h"

#include "hostguard_paths.h"

#include <fstream>
#include <utility>

HostGuardJsonlEventSink::HostGuardJsonlEventSink(std::string logDir)
    : HostGuardJsonlEventSink(std::move(logDir), "rasp-events")
{
}

HostGuardJsonlEventSink::HostGuardJsonlEventSink(std::string logDir, std::string filePrefix)
    : logDir_(std::move(logDir)),
      filePrefix_(std::move(filePrefix))
{
    hostguard_demo::EnsureDirectory(logDir_);
}

void HostGuardJsonlEventSink::OnEventLine(const amsi_ipc::AmsiEventLine& event)
{
    std::lock_guard<std::mutex> guard(lock_);
    std::ofstream output(hostguard_demo::DailyJsonlPath(logDir_, filePrefix_),
                         std::ios::binary | std::ios::app);
    output << event.payload << '\n';
}

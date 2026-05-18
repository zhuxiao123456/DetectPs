#include "hostguard_jsonl_control_status_sink.h"

#include "hostguard_paths.h"

#include <fstream>

HostGuardJsonlControlStatusSink::HostGuardJsonlControlStatusSink(std::string logDir)
    : logDir_(std::move(logDir))
{
    hostguard_demo::EnsureDirectory(logDir_);
}

void HostGuardJsonlControlStatusSink::OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status)
{
    std::lock_guard<std::mutex> guard(lock_);
    std::ofstream output(hostguard_demo::DailyJsonlPath(logDir_, "rasp-control-status"),
                         std::ios::binary | std::ios::app);
    output << status.payload << '\n';
}

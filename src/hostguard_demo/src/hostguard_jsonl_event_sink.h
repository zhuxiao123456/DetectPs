#pragma once

#include "amsi_event_sink.h"

#include <mutex>
#include <string>

class HostGuardJsonlEventSink final : public amsi_ipc::IAmsiEventSink {
public:
    explicit HostGuardJsonlEventSink(std::string logDir);
    HostGuardJsonlEventSink(std::string logDir, std::string filePrefix);

    void OnEventLine(const amsi_ipc::AmsiEventLine& event) override;

private:
    std::string logDir_;
    std::string filePrefix_;
    std::mutex lock_;
};

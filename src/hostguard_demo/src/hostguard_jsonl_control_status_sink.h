#pragma once

#include "amsi_control_status_sink.h"

#include <mutex>
#include <string>

class HostGuardJsonlControlStatusSink final : public amsi_ipc::IAmsiControlStatusSink {
public:
    explicit HostGuardJsonlControlStatusSink(std::string logDir);

    void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status) override;

private:
    std::string logDir_;
    std::mutex lock_;
};

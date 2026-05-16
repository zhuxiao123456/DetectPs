#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <string>

#include "amsi_control_status_channel.h"
#include "amsi_control_status_sink.h"
#include "amsi_pipe_names.h"
#include "named_pipe_server_pool.h"

class ControlStatusCollector : public amsi_ipc::IAmsiControlStatusSink
{
public:
    static constexpr const wchar_t* kPipeName = amsi_ipc::kControlStatusPipeName;
    static constexpr int kThreadCount = 2;

    explicit ControlStatusCollector(std::string logDir);
    ~ControlStatusCollector();

    void Start();
    void Stop();
    void OnControlStatusLine(const amsi_ipc::AmsiControlStatusLine& status) override;

private:
    std::string m_logDir;
    bool m_started = false;
    CRITICAL_SECTION m_fileLock;
    amsi_ipc::AmsiControlStatusChannel m_statusChannel;
    amsi_ipc::NamedPipeServerPool m_statusPipePool;

    void AppendLine(const std::string& jsonLine);
};

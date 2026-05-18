#pragma once

#include "hostguard_demo_app.h"

#include <string>

enum class HostGuardPipeClientChannel {
    Rules,
    Event,
    ControlStatus,
};

struct HostGuardPipeClientOptions {
    HostGuardPipeMode pipeMode = HostGuardPipeMode::Demo;
    HostGuardPipeClientChannel channel = HostGuardPipeClientChannel::Rules;
    std::wstring pipeName;
    std::string payload;
    bool expectsResponse = false;
};

bool ParseHostGuardPipeClientOptions(int argc,
                                     const char* const* argv,
                                     HostGuardPipeClientOptions& options,
                                     std::string& error);

bool RunHostGuardPipeClient(const HostGuardPipeClientOptions& options,
                            std::string& response,
                            std::string& error);

std::string HostGuardPipeClientUsage();

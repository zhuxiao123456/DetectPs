#include "hostguard_pipe_client.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace {

bool ParseMode(const std::string& value, HostGuardPipeMode& mode)
{
    if (value == "--demo-pipes") {
        mode = HostGuardPipeMode::Demo;
        return true;
    }
    if (value == "--production-pipes") {
        mode = HostGuardPipeMode::Production;
        return true;
    }
    return false;
}

std::wstring PipeNameFor(HostGuardPipeMode mode, HostGuardPipeClientChannel channel)
{
    const bool production = mode == HostGuardPipeMode::Production;
    switch (channel) {
    case HostGuardPipeClientChannel::Rules:
        return production ? LR"(\\.\pipe\amsi_detect_rules)" :
                            LR"(\\.\pipe\amsi_detect_rules_demo)";
    case HostGuardPipeClientChannel::Event:
        return production ? LR"(\\.\pipe\amsi_detect_events)" :
                            LR"(\\.\pipe\amsi_detect_events_demo)";
    case HostGuardPipeClientChannel::ControlStatus:
        return production ? LR"(\\.\pipe\amsi_detect_control_status)" :
                            LR"(\\.\pipe\amsi_detect_control_status_demo)";
    }
    return {};
}

std::string LastErrorText(const char* operation)
{
    return std::string(operation) + " failed, GetLastError=" + std::to_string(GetLastError());
}

} // namespace

bool ParseHostGuardPipeClientOptions(int argc,
                                     const char* const* argv,
                                     HostGuardPipeClientOptions& options,
                                     std::string& error)
{
    if (argc != 4) {
        error = "usage: " + HostGuardPipeClientUsage();
        return false;
    }

    HostGuardPipeMode mode = HostGuardPipeMode::Demo;
    if (!ParseMode(argv[1], mode)) {
        error = "pipe mode must be explicit: --demo-pipes or --production-pipes";
        return false;
    }

    const std::string channel = argv[2];
    const std::string payload = argv[3];
    options.pipeMode = mode;

    if (channel == "rules") {
        if (payload != "GET_RULES" && payload != "GET_ALL_RULES") {
            error = "rules command must be GET_RULES or GET_ALL_RULES";
            return false;
        }
        options.channel = HostGuardPipeClientChannel::Rules;
        options.payload = payload + "\n";
        options.expectsResponse = true;
    } else if (channel == "event") {
        options.channel = HostGuardPipeClientChannel::Event;
        options.payload = payload;
        options.expectsResponse = false;
    } else if (channel == "status") {
        options.channel = HostGuardPipeClientChannel::ControlStatus;
        options.payload = payload;
        options.expectsResponse = false;
    } else {
        error = "channel must be rules, event, or status";
        return false;
    }

    options.pipeName = PipeNameFor(options.pipeMode, options.channel);
    return true;
}

bool RunHostGuardPipeClient(const HostGuardPipeClientOptions& options,
                            std::string& response,
                            std::string& error)
{
    if (!WaitNamedPipeW(options.pipeName.c_str(), 2000)) {
        error = LastErrorText("WaitNamedPipeW");
        return false;
    }

    const DWORD access = options.expectsResponse ? (GENERIC_READ | GENERIC_WRITE) : GENERIC_WRITE;
    HANDLE pipe = CreateFileW(options.pipeName.c_str(),
                              access,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe == INVALID_HANDLE_VALUE) {
        error = LastErrorText("CreateFileW");
        return false;
    }

    DWORD written = 0;
    if (!WriteFile(pipe,
                   options.payload.data(),
                   static_cast<DWORD>(options.payload.size()),
                   &written,
                   nullptr) ||
        written != options.payload.size()) {
        error = LastErrorText("WriteFile");
        CloseHandle(pipe);
        return false;
    }

    if (options.expectsResponse) {
        char buffer[65536] = {};
        DWORD bytesRead = 0;
        if (!ReadFile(pipe, buffer, static_cast<DWORD>(sizeof(buffer) - 1), &bytesRead, nullptr)) {
            error = LastErrorText("ReadFile");
            CloseHandle(pipe);
            return false;
        }
        response.assign(buffer, bytesRead);
    }

    CloseHandle(pipe);
    return true;
}

std::string HostGuardPipeClientUsage()
{
    return "hostguard_demo_pipe_client.exe (--demo-pipes|--production-pipes) "
           "(rules GET_RULES|rules GET_ALL_RULES|event <json>|status <json>)";
}

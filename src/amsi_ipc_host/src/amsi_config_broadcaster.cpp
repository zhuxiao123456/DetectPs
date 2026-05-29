#include "amsi_config_broadcaster.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <algorithm>
#include <utility>

namespace amsi_ipc {

AmsiConfigBroadcaster::AmsiConfigBroadcaster(std::wstring configPipeName)
    : configPipeName_(std::move(configPipeName))
{
}

AmsiConfigBroadcaster::~AmsiConfigBroadcaster()
{
    Stop();
}

bool AmsiConfigBroadcaster::Start()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (running_) {
        return true;
    }

    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    HANDLE probePipe = CreateNamedPipeW(configPipeName_.c_str(),
                                        PIPE_ACCESS_OUTBOUND,
                                        PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                        PIPE_UNLIMITED_INSTANCES,
                                        1,
                                        0,
                                        0,
                                        &sa);
    if (probePipe == INVALID_HANDLE_VALUE) {
        return false;
    }
    CloseHandle(probePipe);

    stopEvent_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    if (!stopEvent_) {
        return false;
    }

    running_ = true;
    acceptThread_ = CreateThread(nullptr, 0, AcceptThreadProc, this, 0, nullptr);
    if (!acceptThread_) {
        running_ = false;
        CloseHandle(static_cast<HANDLE>(stopEvent_));
        stopEvent_ = nullptr;
        return false;
    }
    return true;
}

void AmsiConfigBroadcaster::Stop()
{
    HANDLE thread = nullptr;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_ && !acceptThread_ && !stopEvent_) {
            return;
        }
        running_ = false;
        if (stopEvent_) {
            SetEvent(static_cast<HANDLE>(stopEvent_));
        }
        thread = static_cast<HANDLE>(acceptThread_);
        CloseClientsLocked();
    }

    WakeAcceptThread();

    if (thread) {
        WaitForSingleObject(thread, 3000);
        CloseHandle(thread);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    acceptThread_ = nullptr;
    if (stopEvent_) {
        CloseHandle(static_cast<HANDLE>(stopEvent_));
        stopEvent_ = nullptr;
    }
}

AmsiBroadcastResult AmsiConfigBroadcaster::Broadcast(AmsiControlSignal signal,
                                                     int maxListeners,
                                                     std::uint32_t timeoutMs) const
{
    AmsiBroadcastResult result{};
    if (maxListeners <= 0) {
        result.lastError = ERROR_INVALID_PARAMETER;
        return result;
    }

    const auto rawSignal = static_cast<std::uint8_t>(signal);

    const DWORD deadline = GetTickCount() + timeoutMs;
    while (result.reached < maxListeners) {
        HANDLE pipe = INVALID_HANDLE_VALUE;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!clients_.empty()) {
                pipe = static_cast<HANDLE>(clients_.back());
                clients_.pop_back();
            }
        }

        if (pipe == INVALID_HANDLE_VALUE) {
            const DWORD now = GetTickCount();
            if (timeoutMs == 0 || now >= deadline) {
                result.lastError = result.reached > 0 ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
                break;
            }
            Sleep(std::min<DWORD>(25, deadline - now));
            continue;
        }

        DWORD written = 0;
        const BOOL ok = WriteFile(pipe, &rawSignal, 1, &written, nullptr);
        const DWORD writeError = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(pipe);

        if (!ok || written != 1) {
            result.lastError = ok ? ERROR_WRITE_FAULT : writeError;
            break;
        }

        ++result.reached;
        result.lastError = ERROR_SUCCESS;
    }

    return result;
}

unsigned long __stdcall AmsiConfigBroadcaster::AcceptThreadProc(void* param)
{
    static_cast<AmsiConfigBroadcaster*>(param)->AcceptLoop();
    return 0;
}

void AmsiConfigBroadcaster::AcceptLoop()
{
    SECURITY_DESCRIPTOR sd = {};
    InitializeSecurityDescriptor(&sd, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorDacl(&sd, TRUE, nullptr, FALSE);

    SECURITY_ATTRIBUTES sa = {};
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = &sd;
    sa.bInheritHandle = FALSE;

    for (;;) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                break;
            }
        }

        HANDLE pipe = CreateNamedPipeW(configPipeName_.c_str(),
                                       PIPE_ACCESS_OUTBOUND,
                                       PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                                       PIPE_UNLIMITED_INSTANCES,
                                       1,
                                       0,
                                       0,
                                       &sa);
        if (pipe == INVALID_HANDLE_VALUE) {
            Sleep(100);
            continue;
        }

        const BOOL connected = ConnectNamedPipe(pipe, nullptr);
        const DWORD connectError = connected ? ERROR_SUCCESS : GetLastError();

        std::lock_guard<std::mutex> lock(mutex_);
        if (!running_) {
            DisconnectNamedPipe(pipe);
            CloseHandle(pipe);
            break;
        }
        if (!connected && connectError != ERROR_PIPE_CONNECTED) {
            CloseHandle(pipe);
            continue;
        }
        clients_.push_back(pipe);
    }
}

void AmsiConfigBroadcaster::CloseClientsLocked()
{
    for (void* client : clients_) {
        CloseHandle(static_cast<HANDLE>(client));
    }
    clients_.clear();
}

void AmsiConfigBroadcaster::WakeAcceptThread() const
{
    HANDLE pipe = CreateFileW(configPipeName_.c_str(),
                              GENERIC_READ,
                              0,
                              nullptr,
                              OPEN_EXISTING,
                              0,
                              nullptr);
    if (pipe != INVALID_HANDLE_VALUE) {
        CloseHandle(pipe);
    }
}

} // namespace amsi_ipc

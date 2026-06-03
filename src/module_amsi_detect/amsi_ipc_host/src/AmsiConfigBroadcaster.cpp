/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "../amsi_ipc_host/include/AmsiConfigBroadcaster.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>

#include <algorithm>
#include <utility>

namespace amsi_ipc {
    namespace {
        std::uint32_t ClampAcceptThreadCount(std::uint32_t count) {
            if (count < 1) {
                return 1;
            }
            if (count > 32) {
                return 32;
            }
            return count;
        }
    }

    AmsiConfigBroadcaster::AmsiConfigBroadcaster(std::wstring configPipeName)
            : AmsiConfigBroadcaster(std::move(configPipeName), 1) {
    }

    AmsiConfigBroadcaster::AmsiConfigBroadcaster(std::wstring configPipeName, std::uint32_t acceptThreadCount)
            : configPipeName_(std::move(configPipeName)),
              acceptThreadCount_(ClampAcceptThreadCount(acceptThreadCount)) {
    }

    AmsiConfigBroadcaster::~AmsiConfigBroadcaster() {
        Stop();
    }

    bool AmsiConfigBroadcaster::Start() {
        std::unique_lock<std::mutex> lock(mutex_);
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
        acceptThreads_.clear();
        for (std::uint32_t i = 0; i < acceptThreadCount_; ++i) {
            HANDLE thread = CreateThread(nullptr, 0, AcceptThreadProc, this, 0, nullptr);
            if (!thread) {
                running_ = false;
                SetEvent(stopEvent_);
                CloseClientsLocked();
                std::vector<HANDLE> startedThreads;
                startedThreads.swap(acceptThreads_);
                const std::uint32_t wakeCount = static_cast<std::uint32_t>(startedThreads.size());
                lock.unlock();
                WakeAcceptThreads(wakeCount);
                JoinAcceptThreads(startedThreads, wakeCount);
                lock.lock();
                CloseHandle(stopEvent_);
                stopEvent_ = nullptr;
                return false;
            }
            acceptThreads_.push_back(thread);
        }
        return true;
    }

    void AmsiConfigBroadcaster::Stop() {
        std::vector<HANDLE> threads;
        std::uint32_t wakeCount = 0;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_ && acceptThreads_.empty() && !stopEvent_) {
                return;
            }
            running_ = false;
            if (stopEvent_) {
                SetEvent(stopEvent_);
            }
            threads.swap(acceptThreads_);
            wakeCount = static_cast<std::uint32_t>(threads.size());
            CloseClientsLocked();
        }

        WakeAcceptThreads(wakeCount);

        JoinAcceptThreads(threads, wakeCount);

        std::lock_guard<std::mutex> lock(mutex_);
        if (stopEvent_) {
            CloseHandle(stopEvent_);
            stopEvent_ = nullptr;
        }
    }

    AmsiBroadcastResult AmsiConfigBroadcaster::Broadcast(AmsiControlSignal signal,
                                                         int maxListeners,
                                                         std::uint32_t timeoutMs) const {
        AmsiBroadcastResult result{};
        if (maxListeners <= 0) {
            result.lastError = ERROR_INVALID_PARAMETER;
            return result;
        }

        const auto rawSignal = static_cast<std::uint8_t>(signal);
        const ULONGLONG startTick = GetTickCount64();

        while (result.reached < maxListeners) {
            HANDLE pipe = INVALID_HANDLE_VALUE;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (!clients_.empty()) {
                    pipe = clients_.back();
                    clients_.pop_back();
                }
            }

            if (pipe == INVALID_HANDLE_VALUE) {
                const ULONGLONG elapsed = GetTickCount64() - startTick;
                if (timeoutMs == 0 || elapsed >= timeoutMs) {
                    result.lastError = result.reached > 0 ? ERROR_SUCCESS : ERROR_FILE_NOT_FOUND;
                    break;
                }
                const DWORD remaining = static_cast<DWORD>(timeoutMs - elapsed);
                Sleep(std::min<DWORD>(25, remaining));
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

    unsigned long __stdcall AmsiConfigBroadcaster::AcceptThreadProc(void *param) {
        static_cast<AmsiConfigBroadcaster *>(param)->AcceptLoop();
        return 0;
    }

    void AmsiConfigBroadcaster::AcceptLoop() {
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

            if (IsStopRequested()) {
                CloseHandle(pipe);
                break;
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

    void AmsiConfigBroadcaster::CloseClientsLocked() {
        for (HANDLE client: clients_) {
            CloseHandle(client);
        }
        clients_.clear();
    }

    void AmsiConfigBroadcaster::JoinAcceptThreads(std::vector<HANDLE> &threads,
                                                  std::uint32_t wakeCount) const {
        const std::uint32_t boundedWakeCount = static_cast<std::uint32_t>(
                std::min<std::size_t>(threads.size(), wakeCount));
        bool wakeRetried = false;
        for (HANDLE thread: threads) {
            DWORD wait = WaitForSingleObject(thread, 3000);
            if (wait == WAIT_TIMEOUT && !wakeRetried) {
                WakeAcceptThreads(boundedWakeCount);
                wakeRetried = true;
                wait = WaitForSingleObject(thread, 1000);
            }
            CloseHandle(thread);
        }
        threads.clear();
    }

    bool AmsiConfigBroadcaster::IsStopRequested() const {
        HANDLE stopEvent = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!running_) {
                return true;
            }
            stopEvent = stopEvent_;
        }

        return stopEvent && WaitForSingleObject(stopEvent, 0) == WAIT_OBJECT_0;
    }

    void AmsiConfigBroadcaster::WakeAcceptThreads(std::uint32_t wakeCount) const {
        for (std::uint32_t i = 0; i < wakeCount; ++i) {
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
    }

} // namespace amsi_ipc

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * Defines AMSI config control signal broadcaster.
 */

#ifndef AMSI_CONFIG_BROADCASTER_H
#define AMSI_CONFIG_BROADCASTER_H

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

namespace amsi_ipc {
    enum class AmsiControlSignal : std::uint8_t {
        Reload = 0x01,
        Unload = 0x02,
        PauseDetection = 0x03,
        ResumeDetection = 0x04,
    };

    struct AmsiBroadcastResult {
        int reached = 0;
        std::uint32_t lastError = 0;
    };

    class AmsiConfigBroadcaster {
    public:
        explicit AmsiConfigBroadcaster(std::wstring configPipeName);

        AmsiConfigBroadcaster(std::wstring configPipeName, std::uint32_t acceptThreadCount);

        ~AmsiConfigBroadcaster();

        AmsiConfigBroadcaster(const AmsiConfigBroadcaster &) = delete;

        AmsiConfigBroadcaster &operator=(const AmsiConfigBroadcaster &) = delete;

        bool Start();

        void Stop();

        AmsiBroadcastResult Broadcast(AmsiControlSignal signal,
                                      int maxListeners,
                                      std::uint32_t timeoutMs) const;

    private:
        static unsigned long __stdcall AcceptThreadProc(void *param);

        void AcceptLoop();

        void CloseClientsLocked();

        void JoinAcceptThreads(std::vector<HANDLE> &threads, std::uint32_t wakeCount) const;

        bool IsStopRequested() const;

        void WakeAcceptThreads(std::uint32_t wakeCount) const;

        std::wstring configPipeName_;
        std::uint32_t acceptThreadCount_ = 1;
        std::vector<HANDLE> acceptThreads_;
        HANDLE stopEvent_ = nullptr;
        mutable std::mutex mutex_;
        mutable std::vector<HANDLE> clients_;
        bool running_ = false;
    };
} // namespace amsi_ipc

#endif

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 定义 AMSI config 控制信号广播结构。
 */

#ifndef AMSI_CONFIG_BROADCASTER_H
#define AMSI_CONFIG_BROADCASTER_H

#pragma once

#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace amsi_ipc {
    // 定义广播通信的控制指令, 强制底层类型为单字节 std::uint8_t, 降低通信开销和复杂度
    enum class AmsiControlSignal : std::uint8_t {
        Reload = 0x01,
        Unload = 0x02,
        PauseDetection = 0x03,
        ResumeDetection = 0x04,
    };
    // 封装广播操作的执行结果
    struct AmsiBroadcastResult {
        int reached = 0;  // 收到指定的探针数量
        std::uint32_t lastError = 0;  // 过程中发生的最后一个 Windows 系统错误码 (GetLastError())，方便上层诊断
    };

    // 执行广播动作的核心类
    class AmsiConfigBroadcaster {
    public:
        explicit AmsiConfigBroadcaster(std::wstring configPipeName);

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

        void WakeAcceptThread() const;

        std::wstring configPipeName_;
        void *acceptThread_ = nullptr;
        void *stopEvent_ = nullptr;
        mutable std::mutex mutex_;
        mutable std::vector<void *> clients_;
        bool running_ = false;
    };

} // namespace amsi_ipc

#endif

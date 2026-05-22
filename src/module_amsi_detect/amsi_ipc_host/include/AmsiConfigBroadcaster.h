/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 定义了广播通信的“协议”和数据结构
 */

#ifndef AMSI_CONFIG_BROADCASTER_H
#define AMSI_CONFIG_BROADCASTER_H

#pragma once

#include <cstdint>
#include <string>

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

        AmsiBroadcastResult Broadcast(AmsiControlSignal signal,
                                      int maxListeners,
                                      std::uint32_t timeoutMs) const;

    private:
        std::wstring configPipeName_;
    };

} // namespace amsi_ipc

#endif

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "../amsi_ipc_host/include/AmsiConfigBroadcaster.h"

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

#include <utility>

namespace amsi_ipc {

AmsiConfigBroadcaster::AmsiConfigBroadcaster(std::wstring configPipeName)
    : configPipeName_(std::move(configPipeName))
{
}

/*
 * 功能: 广播
 * AmsiControlSignal signal：要发送的指令�?x01 �?0x02）�?
 * int maxListeners：最大监听者数量。系统里可能注入了成百上千个进程，这个参数作为熔断机制，防止广播循环永远无法退出�?
 * std::uint32_t timeoutMs：连接超时时间（毫秒）。防止某个进程的管道卡死导致主服务被挂起
 * 输出: 成功触达的数量和错误�?
 */
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

    for (int i = 0; i < maxListeners; ++i) {
        // 在指定的 timeoutMs 时间内，等待命名管道的任意一个实例变为可用状态。如果超时或找不到，立刻跳出循环
        if (!WaitNamedPipeW(configPipeName_.c_str(), timeoutMs)) {
            result.lastError = GetLastError();
            break;
        }
        // �?GENERIC_WRITE (只写) 权限打开这个管道实例。如果由于权限或并发导致打开失败，记录错误并跳出
        HANDLE pipe = CreateFileW(configPipeName_.c_str(),
                                  GENERIC_WRITE,
                                  0,
                                  nullptr,
                                  OPEN_EXISTING,
                                  0,
                                  nullptr);
        if (pipe == INVALID_HANDLE_VALUE) {
            result.lastError = GetLastError();
            break;
        }
        // 发送指�?(WriteFile)：将 signal 转换�?1 个字�?(&rawSignal)，写入管�?
        DWORD written = 0;
        const BOOL ok = WriteFile(pipe, &rawSignal, 1, &written, nullptr);
        const DWORD writeError = ok ? ERROR_SUCCESS : GetLastError();
        CloseHandle(pipe);
        // 清理并计数：关闭句柄 CloseHandle(pipe)，将 result.reached 累加 1
        if (!ok || written != 1) {
            result.lastError = ok ? ERROR_WRITE_FAULT : writeError;
            break;
        }

        ++result.reached;
        result.lastError = ERROR_SUCCESS;
    }

    return result;
}

} // namespace amsi_ipc

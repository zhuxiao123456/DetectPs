/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */

#include "../include/AmsiControlStatusChannel.h"

#include <string>

namespace amsi_ipc {
// 将外部传入的 sink 绑定到类的内部成员上
AmsiControlStatusChannel::AmsiControlStatusChannel(IAmsiControlStatusSink& sink)
    : sink_(sink)
{
}

void AmsiControlStatusChannel::HandleClient(HANDLE pipe)
{
    char buffer[65536] = {};
    DWORD bytesRead = 0;
    // 调用 Windows API 同步读取管道数据
    const BOOL ok = ReadFile(pipe,
                             buffer,
                             static_cast<DWORD>(sizeof(buffer) - 1),
                             &bytesRead,
                             nullptr);
    if (!ok || bytesRead == 0) {
        return;  // 读取失败、直接丢弃
    }
    // 读取到的缓冲区和实际读取长度 bytesRead 构造一个 std::string。
    // 然后将其包装进 AmsiControlStatusLine 结构体，调用 sink_ 接口将数据推送到 hostguard 分析后端
    sink_.OnControlStatusLine(AmsiControlStatusLine{std::string(buffer, bytesRead)});
}

} // namespace amsi_ipc

/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 处理客户端（AMSI 探针）状态上报的管道数据接收处理器
 */
#ifndef AMSI_CONTROL_STATUS_CHANNEL_H
#define AMSI_CONTROL_STATUS_CHANNEL_H

#pragma once

#include "AmsiControlStatusSink.h"
#include "NamedPipeServerPool.h"

namespace amsi_ipc {

/*
 * 继承了 INamedPipeClientHandler 接口。
 * 这是一个典型的策略模式 (Strategy Pattern) 或 回调接口设计。
 * 底层的 NamedPipeServerPool 不关心业务逻辑，它只负责维护多线程和网络 I/O，一旦有客户端连接，它就调用这个接口的 HandleClient 方法
 */
class AmsiControlStatusChannel : public INamedPipeClientHandler {
public:
    explicit AmsiControlStatusChannel(IAmsiControlStatusSink& sink);

    void HandleClient(HANDLE pipe) override;

private:
    // 依赖注入 (Dependency Injection)。Channel 类本身只负责“从管道里把字节流读出来”
    // 读出数据后，它会把数据丢给 sink_, 这个 sink_ 就是 hostguard 主程序提供的分析引擎接口
    IAmsiControlStatusSink& sink_;
};

} // namespace amsi_ipc

#endif

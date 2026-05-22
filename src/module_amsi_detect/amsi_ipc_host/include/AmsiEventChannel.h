/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 负责处理命名管道客户端连接的具体工作类
 */
#ifndef AMSI_EVENT_CHANNEL_H
#define AMSI_EVENT_CHANNEL_H

#pragma once

#include "AmsiEventSink.h"
#include "NamedPipeServerPool.h"

namespace amsi_ipc {
// 继承自管道处理器接口，这意味着它的实例会被塞进 NamedPipeServerPool（管道线程池）中。当有 AMSI 探针连上管道时，线程池就会回调它的函数
class AmsiEventChannel : public INamedPipeClientHandler {
public:
    explicit AmsiEventChannel(IAmsiEventSink& sink);

    void HandleClient(HANDLE pipe) override;

private:
    IAmsiEventSink& sink_;
};

} // namespace amsi_ipc

#endif

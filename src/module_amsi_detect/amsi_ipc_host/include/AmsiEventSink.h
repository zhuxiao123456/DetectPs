/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 * 定义了数据流出的标准“协议”接口
 */
#ifndef AMSI_EVENT_SINK_H
#define AMSI_EVENT_SINK_H

#pragma once

#include <string>

namespace amsi_ipc {

struct AmsiEventLine {
    std::string payload;  // 从管道中读取到的单次事件的原始数据
};

class IAmsiEventSink {
public:
    virtual ~IAmsiEventSink() = default;
    // 事件回调分发函数,当底层通道从管道读出数据后，就会调用这个函数,hostguard继承该接口并在函数内部实现 JSON 解析、告警落盘、阻断策略等
    virtual void OnEventLine(const AmsiEventLine& event) = 0;
};

} // namespace amsi_ipc

#endif

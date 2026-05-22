/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#ifndef AMSI_CONTROL_STATUS_SINK_H
#define AMSI_CONTROL_STATUS_SINK_H

#pragma once

#include <string>

namespace amsi_ipc {

struct AmsiControlStatusLine {
    std::string payload;
};

class IAmsiControlStatusSink {
public:
    virtual ~IAmsiControlStatusSink() = default;
    virtual void OnControlStatusLine(const AmsiControlStatusLine& status) = 0;
};

} // namespace amsi_ipc

#endif

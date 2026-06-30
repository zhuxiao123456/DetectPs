/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2026-2026. All rights reserved.
 */
#ifndef AMSI_RULE_CHANNEL_H
#define AMSI_RULE_CHANNEL_H

#pragma once

#include "AmsiRuleProvider.h"
#include "NamedPipeServerPool.h"

namespace amsi_ipc {

using AmsiRuleChannelLogCallback = void (*)(const char* message, void* context);

class AmsiRuleChannel : public INamedPipeClientHandler {
public:
    explicit AmsiRuleChannel(IAmsiRuleProvider& provider);

    void SetLogCallback(AmsiRuleChannelLogCallback callback, void* context);
    void HandleClient(HANDLE pipe) override;

private:
    void EmitLog(const char* message) const;

    IAmsiRuleProvider& provider_;
    AmsiRuleChannelLogCallback logCallback_ = nullptr;
    void* logContext_ = nullptr;
};

} // namespace amsi_ipc

#endif
